/* Inlude elements related to ISO7816 and the board */
#include "smartcard_token.h"
#include "api/syscall.h"
#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

#include "api/print.h"

typedef struct {
    uint8_t channel_initialized;
    SC_ATR atr; /* The ATR needed for the low level operations */
    uint8_t T_protocol; /* The ISO7816-3 protocol (T=0 or T=1) */
    uint8_t secure_channel; /* Boolean telling if the channel is secure or not yet */
    uint8_t IV[16]; /* Initialization Vector. We use this as an anti-replay mechanism. */
    uint8_t first_IV[16]; /* First Initialization Vector value. We use this as a random seed for some key derivations. */
    /* Symmetric session key for confidentiality 128-bit AES key. */
    uint8_t AES_key[16];
    /* HMAC SHA-256 secret key */
    uint8_t HMAC_key[32];
} token_channel;

token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 } };

/* Include libecc headers for the crypto part
 * (asymmetric ECC and hash functions).
 */
#include "libsig.h"

/* Include the HMAC header */
#include "hmac.h"

/* Include the AES header */
#include "aes.h"

/* Include our ECDSA private key */
#include "platform_private_key.h"

/* Include the token ECDSA public key */
#include "token_public_key.h"

#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

/******* Crypto helpers ****************/

static void inc_iv(uint8_t IV[16]){
    int i;
    for(i = 16; i > 0; i--){
        if(++IV[i-1]){
            break;
        }
    }

    return;
}

static void add_iv(uint8_t IV[16], unsigned int inc){
    unsigned int i;

    for(i = 0; i < inc; i++){
        inc_iv(IV);
    }

    return;
}


/****** Token operations **************/
/* [RB] FIXME: the layer handling the encryption and the integrity should
 * be abstracted and not dependent with the physical layer. For now these
 * layers are mixed because of the way ISO7816-3 mixes layers, but there should
 * be a clean way to split this and keep all the crypto code and the secure channel
 * code independent of the transport layer (so that the exact same code handles
 * tokens on ISO7816, I2C, SPI and so on).
 */

/* Our token instructions */
enum token_instructions {
    TOKEN_INS_SELECT_APPLET = 0xA4,
    TOKEN_INS_SECURE_CHANNEL_INIT = 0xD5,
    TOKEN_INS_SECURE_CHANNEL_ECHO = 0xD6,
    TOKEN_INS_UNLOCK = 0xD7,
    TOKEN_INS_SET_PIN = 0xD8,
    TOKEN_INS_LOCK = 0xD9,
    TOKEN_INS_GET_KEY = 0xDA,
};

enum token_responses {
    TOKEN_RESP_OK = 0x9000,
};

/* We describe hereafter the 'physical' layer to
 * communicate with our token. the rationale is to
 * distinguish between a 'clear text' channel before the
 * ECDH, and a secure channel protected in confidentiality
 * with AES-CTR and in integrity with a HMAC SHA256.
 * We are deemed to use AES with 128-bit keys because of
 * the lack of support for AES-192 and AES-256 in the current
 * mainstream Javacard cards.
 */

/* Self-synchronization anti-replay window of 10 attempts */
#define ANTI_REPLAY_SELF_SYNC_WINDOW    10



/* Secure channel negotiation:
 * We use an ECDH with mutual authentication in order to derive our session key and IV.
 */
int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp);
int token_negotiate_secure_channel(token_channel *channel){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;
    /* Our ECDSA key pair */
    ec_key_pair our_key_pair;
    /* The token ECDSA public key */
    ec_pub_key token_pub_key;
        /* The projective point we will use */
        prj_pt Q;
        /* The equivalent affine point */
        aff_pt Q_aff;
        nn d;
    uint8_t siglen;
        struct ec_sign_context sig_ctx;
        struct ec_verify_context verif_ctx;
        /* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
    /* SHA256 context used to derive our secrets */
    sha256_context sha256_ctx;
    /* Shared secret buffer */
    uint8_t shared_secret[NN_MAX_BIT_LEN / 8];
    uint8_t digest[SHA256_DIGEST_SIZE];

    /******* Reader answer ***********************************/
        /* Importing specific curve parameters from the constant static
         * buffers describing it:
         * It is possible to import a curve set of parameters by its name.
         */
        the_curve_const_parameters =
                ec_get_curve_params_by_name((const unsigned char *)"FRP256V1",
                                            (u8)local_strnlen((const char *)
                                                              "FRP256V1",
                                                              MAX_CURVE_NAME_LEN)
                                            + 1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
                goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);

    if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
        goto err;
    }

    /* If there is not enough room in the short APDU for Q and the signature, get out */
    if(((3 * BYTECEIL(curve_params.ec_fp.p_bitlen)) + siglen) > SHORT_APDU_LC_MAX){
        goto err;
    }

    /* Import our ECDSA key pair */
    if(ec_structured_key_pair_import_from_priv_key_buf(&our_key_pair, &curve_params, (const unsigned char*)FRP256V1_ECDSA_private_key, sizeof(FRP256V1_ECDSA_private_key), ECDSA)){
        goto err;
    }

        /* Initialize our projective point with the curve parameters */
        prj_pt_init(&Q, &(curve_params.ec_curve));

        /* Generate our ECDH parameters: a private scalar d and a public value Q = dG where G is the
         * curve generator.
         * d = random mod (q) where q is the order of the generator G.
     * Note: we have chosen to do this the 'explicit way', but we could have used the ECDSA key pair generation
     * primitive to handle the random private scalar d and its public counter part dG.
         */
        nn_init(&d, 0);
        if (nn_get_random_mod(&d, &(curve_params.ec_gen_order))) {
                goto err;
        }
        /* Q = dG */
        prj_pt_mul_monty(&Q, &d, &(curve_params.ec_gen));
    /* Normalize Q to have the unique representation (by moving to affine representation and back to projective) */
    prj_pt_to_aff(&Q_aff, &Q);
    ec_shortw_aff_to_prj(&Q, &Q_aff);

        /* Export Q to serialize it in the APDU.
         * Our export size is exactly 3 coordinates in Fp, so this should be 3 times the size
         * of an element in Fp.
         */
        if(prj_pt_export_to_buf(&Q, apdu.data,
                             3 * BYTECEIL(curve_params.ec_fp.p_bitlen))){
        goto err;
    }
    apdu.lc = 3 * BYTECEIL(curve_params.ec_fp.p_bitlen);

    /* Now compute the ECDSA signature of Q */
        if(ec_sign_init(&sig_ctx, &our_key_pair, ECDSA, SHA256)){
        goto err;
    }
    if(ec_sign_update(&sig_ctx, (const uint8_t*)apdu.data, apdu.lc)){
        goto err;
    }
    /* Append the signature in the APDU */
    if(ec_sign_finalize(&sig_ctx, &(apdu.data[apdu.lc]), siglen)){
        goto err;
    }
    apdu.lc += siglen;

    /* The instruction to perform an ECDH is D5: the reader sends its random scalar
     * and receives the card random scalar.
     */
    apdu.cla = 0x00; apdu.ins = TOKEN_INS_SECURE_CHANNEL_INIT; apdu.p1 = 0x00; apdu.p2 = 0x00;
    apdu.le = apdu.lc; apdu.send_le = 1;
    if(token_send_receive(channel, &apdu, &resp)){
        goto err;
    }

    /******* Smartcard response ***********************************/
    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        /* The smartcard responded an error */
        goto err;
    }
    if(resp.le != ((3 * BYTECEIL(curve_params.ec_fp.p_bitlen)) + (uint32_t)siglen)){
        /* This is not the size we are waiting for ... */
        goto err;
    }
    /* Import the token public key */
    if(ec_structured_pub_key_import_from_buf(&token_pub_key, &curve_params, (const unsigned char*)FRP256V1_ECDSA_public_key, sizeof(FRP256V1_ECDSA_public_key), ECDSA)){
        goto err;
    }

    /* Verify the signature */
    if(ec_verify_init(&verif_ctx, &token_pub_key, &(resp.data[resp.le-siglen]), siglen, ECDSA, SHA256)){
        goto err;
    }
    if(ec_verify_update(&verif_ctx, resp.data, resp.le-siglen)){
        goto err;
    }
    if(ec_verify_finalize(&verif_ctx)){
        goto err;
    }

    /* Signature is OK, now extract the point from the APDU */
    if(prj_pt_import_from_buf(&Q, resp.data, 3 * BYTECEIL(curve_params.ec_fp.p_bitlen), &(curve_params.ec_curve))){
        goto err;
    }

    /* Now compute dQ where d is our secret */
        prj_pt_mul_monty(&Q, &d, &Q);
    /* Move to affine representation to get the unique representation of the point
     * (the other party should send us a normalized point, but nevermind do it anyways).
     */
        prj_pt_to_aff(&Q_aff, &Q);
    /* The shared secret is Q_aff.x, which is 32 bytes:
     * we derive our AES 256-bit secret key, our 256-bit HMAC key as well as our initial IV from this value.
     */
    fp_export_to_buf(shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen), &(Q_aff.x));

    /* AES Key = SHA-256("AES_SESSION_KEY" | shared_secret) (first 128 bits) */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (uint8_t*)"AES_SESSION_KEY", sizeof("AES_SESSION_KEY")-1);
    sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
    sha256_final(&sha256_ctx, digest);
    memcpy(channel->AES_key, digest, 16);
    /* HMAC Key = SHA-256("HMAC_SESSION_KEY" | shared_secret) (256 bits) */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (uint8_t*)"HMAC_SESSION_KEY", sizeof("HMAC_SESSION_KEY")-1);
    sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
    sha256_final(&sha256_ctx, channel->HMAC_key);
    /* IV = SHA-256("SESSION_IV" | shared_secret) (first 128 bits) */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (uint8_t*)"SESSION_IV", sizeof("SESSION_IV")-1);
    sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
    sha256_final(&sha256_ctx, digest);
    memcpy(channel->IV, digest, 16);
    memcpy(channel->first_IV, channel->IV, 16);

    /* Our secure channel is initialized */
    channel->secure_channel = 1;

        /* Uninit local variables */
        prj_pt_uninit(&Q);
        aff_pt_uninit(&Q_aff);
        nn_uninit(&d);

    return 0;
err:
    SC_smartcard_lost();
    return -1;
}

/* APDU encryption and integrity */
int token_apdu_cmd_encrypt(token_channel *channel, SC_APDU_cmd *apdu){
    hmac_context hmac_ctx;
    uint8_t hmac[SHA256_DIGEST_SIZE];
    uint8_t tmp;
    uint32_t hmac_len = sizeof(hmac);

    /* Sanity checks */
    if(!channel->secure_channel){
        /* Why encrypt since we do not have a secure channel yet? */
        goto err;
    }
    if((apdu->le > SHORT_APDU_LE_MAX) || (apdu->lc > SHORT_APDU_LC_MAX)){
        /* Sanity check: we only deal with short APDUs */
        goto err;
    }
    if(apdu->lc > (SHORT_APDU_LC_MAX - sizeof(hmac))){
        /* Not enough room for our HMAC */
        goto err;
    }

    /* Compute the integrity on the full encrypted data + CLA/INS/P1/P2, lc and le on 1 byte since we deal only with short APDUs */
    if(hmac_init(&hmac_ctx, channel->HMAC_key, sizeof(channel->HMAC_key), SHA256)){
        goto err;
    }
    /* Pre-append the IV for anti-replay on the integrity with empty data */
    hmac_update(&hmac_ctx, channel->IV, sizeof(channel->IV));
    hmac_update(&hmac_ctx, &(apdu->cla), 1);
    hmac_update(&hmac_ctx, &(apdu->ins), 1);
    hmac_update(&hmac_ctx, &(apdu->p1),  1);
    hmac_update(&hmac_ctx, &(apdu->p2),  1);
    if(apdu->lc != 0){
        /* Encryption */
        aes_context aes_context;
        /* Encrypt the APDU data with AES-CTR */
        /* [RB] NOTE/FIXME: for now, we always use the software AES because of the
         * peculiarities of how the CTR mode is implemented in hardwre in the STM32 CRYP block.
         * Since we need the IV incrementations to be on par with what happens on the token size,
         * we are not necessarily aligned with the AES block (which is OK since it is a stream mode),
         * but the hardware needs this. TODO: implement a wrapper around the existing CRYP glue to handle
         * this.
         */
#if defined(__arm__)
//#if (PROD_CRYPTO_HARD == 1)
//        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, AES_HARD_NODMA, NULL, NULL, -1, -1)){
//#else
        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, AES_SOFT_ANSSI_MASKED, NULL, NULL, -1, -1)){
//#endif
#else
        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
            goto err;
        }
        if(aes(&aes_context, apdu->data, apdu->data, apdu->lc, -1, -1)){
            goto err;
        }
        /* Update the HMAC */
        tmp = (uint8_t)apdu->lc & 0xff;
        hmac_update(&hmac_ctx, &tmp, 1);
        hmac_update(&hmac_ctx, apdu->data, apdu->lc);
    }
    else{
        /* Increment our anti-replay counter manually since we don't have data */
        inc_iv(channel->IV);
    }
    /* When encrypting an APDU, we always expect a response with at least 32 bytes of HMAC.
     * In order to avoid any issue, we ask of a Le = 0 meaning that we expect a maximum amount of
     * 256 bytes.
     */
    apdu->send_le = 1;
    apdu->le = 0;
    tmp = (uint8_t)apdu->le & 0xff;
    hmac_update(&hmac_ctx, &tmp, 1);

    /* Add the integrity HMAC tag to the APDU data and increment the Lc
     * size accordingly.
     */
    if(hmac_finalize(&hmac_ctx, hmac, &hmac_len)){
        goto err;
    }
    if(hmac_len != sizeof(hmac)){
        goto err;
    }
    memcpy(&(apdu->data[apdu->lc]), hmac, sizeof(hmac));
    apdu->lc += sizeof(hmac);

    return 0;
err:
    SC_smartcard_lost();
    return -1;
}

int token_apdu_resp_decrypt(token_channel *channel, SC_APDU_resp *resp){
    hmac_context hmac_ctx;
    uint8_t hmac[SHA256_DIGEST_SIZE];
    uint8_t hmac_recv[SHA256_DIGEST_SIZE];
    uint8_t tmp;
    int self_sync_attempts = ANTI_REPLAY_SELF_SYNC_WINDOW;
    uint32_t hmac_len = sizeof(hmac);

    /* Sanity check */
    if(!channel->secure_channel){
        goto err;
    }
    /* Response data contains at least a HMAC */
    if(resp->le < sizeof(hmac_recv)){
        goto err;
    }
    /* If we have not received a short APDU, this is an error */
    if(resp->le > SHORT_APDU_LE_MAX){
        goto err;
    }
    /* Copy the received HMAC */
    memcpy(hmac_recv, &(resp->data[resp->le - sizeof(hmac_recv)]), sizeof(hmac_recv));
    resp->le -= sizeof(hmac_recv);
CHECK_INTEGRITY_AGAIN:
    /* Check the integrity */
    if(hmac_init(&hmac_ctx, channel->HMAC_key, sizeof(channel->HMAC_key), SHA256)){
        goto err;
    }
    /* Pre-append the IV for anti-replay on the integrity with empty data */
    hmac_update(&hmac_ctx, channel->IV, sizeof(channel->IV));
    /* Update the HMAC with SW1 and SW2 */
    hmac_update(&hmac_ctx, &(resp->sw1), 1);
    hmac_update(&hmac_ctx, &(resp->sw2), 1);
    /* If we have data, update the HMAC  */
    if(resp->le > 0){
        tmp = (uint8_t)resp->le & 0xff;
        hmac_update(&hmac_ctx, &tmp, 1);
        hmac_update(&hmac_ctx, resp->data, resp->le);
    }
    /* Finalize the HMAC */
    if(hmac_finalize(&hmac_ctx, hmac, &hmac_len)){
        goto err;
    }
    if(hmac_len != sizeof(hmac)){
        goto err;
    }

    /* Compare the computed HMAC and the received HMAC */
    if(!are_equal(hmac, hmac_recv, sizeof(hmac)) != 0){
        /* Integrity is not OK, try to self-synchronize a bit ... */
        if(self_sync_attempts == 0){
            /* We have exhausted our self-sync attempts: return an error */
            goto err;
        }
        self_sync_attempts--;
        inc_iv(channel->IV);
        goto CHECK_INTEGRITY_AGAIN;
    }

    /* Decrypt our data in place if there are some */
    if(resp->le != 0){
        aes_context aes_context;
        /* Decrypt the APDU response data with AES-CTR */
        /* [RB] NOTE/FIXME: for now, we always use the software AES because of the
         * peculiarities of how the CTR mode is implemented in hardwre in the STM32 CRYP block.
         * Since we need the IV incrementations to be on par with what happens on the token size,
         * we are not necessarily aligned with the AES block (which is OK since it is a stream mode),
         * but the hardware needs this. TODO: implement a wrapper around the existing CRYP glue to handle
         * this.
         */
#if defined(__arm__)
//#if (PROD_CRYPTO_HARD == 1)
//        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, AES_HARD_NODMA, NULL, NULL, -1, -1)){
//#else
        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, AES_SOFT_ANSSI_MASKED, NULL, NULL, -1, -1)){
//#endif
#else
        if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
            goto err;
        }
        if(aes(&aes_context, resp->data, resp->data, resp->le, -1, -1)){
            goto err;
        }
    }

    if(resp->le == 0){
        /* Increment the anti-replay for the next exchange */
        inc_iv(channel->IV);
    }

    return 0;
err:
    SC_smartcard_lost();
    return -1;
}


/* The token 'send'/'receive' primitive. Depending on the secure channel state, we
 * send raw or encrypted APDU data.
 * Because we want our secure channel to be compatible in T=0 and T=1, and since T=0
 * mixes the ISO layers and needs CLA/INS/P1/P2/P3, we do not encrypt these. They
 * are however part of the integrity tag computation in order to avoid integrity issues.
 *
 */
int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp){
#ifdef SMARTCARD_DEBUG
    SC_print_APDU(apdu);

#endif
#ifdef MEASURE_TOKEN_PERF
    uint64_t start, end;

    sys_get_systick(&start, PREC_MICRO);
#endif

    /* Channel is not initialized */
    if(!channel->channel_initialized){
        goto err;
    }

    /* Channel is initialized: are we in secure channel mode? */
    if(channel->secure_channel){
        /* In secure channel mode, we encrypt everything and send it.
         * Encrypt the APDU "in place" in order to avoid memory loss */
        /* If we have not space in the APDU, get out ... */
        if(apdu->lc > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
            /* We must have some place for the integrity tag */
            goto err;
        }
        /* Encrypt the APDU and append the integrity tag */
        if(token_apdu_cmd_encrypt(channel, apdu)){
            goto err;
        }
        /* Send the encrypted APDU and receive the encrypted response */
        if(SC_send_APDU(apdu, resp, &(channel->atr), channel->T_protocol)){
            goto err;
        }
        /* Decrypt the response in place and check its integrity */
        if(token_apdu_resp_decrypt(channel, resp)){
            goto err;
        }
    }
    else{
        /* In non secure channel mode, we do not encrypt: send the raw
         * APDU and receive the raw response.
         */
        if(SC_send_APDU(apdu, resp, &(channel->atr), channel->T_protocol)){
            goto err;
        }
    }

#ifdef MEASURE_TOKEN_PERF
    sys_get_systick(&end, PREC_MICRO);
#endif
#ifdef SMARTCARD_DEBUG
    SC_print_RESP(resp);
#endif
#ifdef MEASURE_TOKEN_PERF
    printf("[Token] [++++++++++++++] APDU send/receive took %d milliseconds [++++++++++++++]\n", ((end - start) / 1000));
#endif

    return 0;

err:
#ifdef SMARTCARD_DEBUG
    printf("APDU send/receive error (secure channel or lower layers errors)\n");
    SC_smartcard_lost();
#endif

    return -1;
}


/* Update AES and HMAC session keys given an input string */
void token_channel_session_keys_update(token_channel *channel, const char *in, unsigned int in_len, unsigned char use_iv){
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_context sha256_ctx;
    unsigned int i;

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (unsigned char*)in, in_len);
    if(use_iv == 1){
        sha256_update(&sha256_ctx, channel->IV, sizeof(channel->IV));
    }
    sha256_final(&sha256_ctx, digest);
    for(i = 0; i < sizeof(channel->AES_key); i++){
        channel->AES_key[i] ^= digest[i];
    }
    for(i = 0; i < sizeof(channel->HMAC_key); i++){
        channel->HMAC_key[i] ^= digest[i];
    }

    return;
}

/****** Smartcard low level APDUs ****/
const unsigned char applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x70 };
//const unsigned char applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x37 };
const unsigned char applet_echo_AID[] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x57, 0x6F, 0x72, 0x6C, 0x64 };

/* Select an applet */
int token_select_applet(token_channel *channel, const unsigned char *aid, unsigned int aid_len){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;

    apdu.cla = 0x00; apdu.ins = TOKEN_INS_SELECT_APPLET; apdu.p1 = 0x04; apdu.p2 = 0x00; apdu.lc = aid_len;
    apdu.le = 0x00; apdu.send_le = 1;
    memcpy(apdu.data, aid, aid_len);

    if(token_send_receive(channel, &apdu, &resp)){
        goto err;
    }

    return 0;

err:
    return -1;
}


/* Send a user pin */
int token_send_user_pin(const char *pin, unsigned int pin_len, unsigned char *pin_ok, unsigned int *remaining_tries){
    unsigned int i;
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;
    char padded_pin[16];

    *remaining_tries = 0;
    if (!pin_ok) {
        goto err;
    }

    /* Some sanity checks here */
    if(pin_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
        goto err;
    }
    if(pin_len > 15){
        goto err;
    }

    for(i = 0; i < pin_len; i++){
        padded_pin[i] = pin[i];
    }
    for(i= pin_len; i < (sizeof(padded_pin)-1); i++){
        padded_pin[i] = 0;
    }
    padded_pin[15] = pin_len;

    for(i = 0; i < sizeof(padded_pin); i++){
        apdu.data[i] = padded_pin[i];
    }
    apdu.cla = 0x00; apdu.ins = TOKEN_INS_UNLOCK; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 16; apdu.le = 0x00; apdu.send_le = 1;
    if(token_send_receive(&curr_token_channel, &apdu, &resp)){
        goto err;
    }

    /* Check the response */
    if(resp.le != 1){
        goto err;
    }
    /* Get the remaining tries */
    *remaining_tries = resp.data[0];

    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        /* The smartcard responded an error */
        *pin_ok = 0;
    }
    else{
        /* The pin is OK */
        *pin_ok = 1;
        /* Update our AES and HMAC sessions keys with information derived from the
         * PIN: a SHA-256 hash of the PIN concatenated with the IV.
         */
        token_channel_session_keys_update(&curr_token_channel, padded_pin, sizeof(padded_pin), 1);
    }

    return 0;
err:
    return -1;
}

/* Change PIN */
int token_change_user_pin(const char *pin, unsigned int pin_len){
    unsigned int i;
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;
    char padded_pin[16];

    /* Some sanity checks here */
    if(pin_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
        goto err;
    }
    if(pin_len > 15){
        goto err;
    }

    for(i = 0; i < pin_len; i++){
        padded_pin[i] = pin[i];
    }
    for(i= pin_len; i < (sizeof(padded_pin)-1); i++){
        padded_pin[i] = 0;
    }
    padded_pin[15] = pin_len;

    for(i = 0; i < sizeof(padded_pin); i++){
        apdu.data[i] = padded_pin[i];
    }
    apdu.cla = 0x00; apdu.ins = TOKEN_INS_SET_PIN; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 16; apdu.le = 0x00; apdu.send_le = 0;
    if(token_send_receive(&curr_token_channel, &apdu, &resp)){
        goto err;
    }

    /* Check the response */
    if(resp.le != 1){
        goto err;
    }

    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        /* The smartcard responded an error */
        goto err;
    }

    return 0;
err:
    return -1;
}

/* Lock the token (close the PIN authenticated session) */
int token_lock(void){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;

    apdu.cla = 0x00; apdu.ins = TOKEN_INS_LOCK; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 0;
    if(token_send_receive(&curr_token_channel, &apdu, &resp)){
        goto err;
    }

    /* Check the response */
    if(resp.le != 1){
        goto err;
    }

    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        /* The smartcard responded an error */
        goto err;
    }

    return 0;
err:
    return -1;
}

/* Get key and its derivative */
int token_get_key(const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len, unsigned char *h_key, unsigned int h_key_len){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;
    /* SHA256 context used to derive our secrets */
    sha256_context sha256_ctx;
    /* Digest buffer */
    uint8_t digest[SHA256_DIGEST_SIZE];
    /* AES context to decrypt the response */
    aes_context aes_context;

    /* Sanity check */
    if((pin == NULL) || (key == NULL) || (h_key == NULL)){
        goto err;
    }

    /* Sanity checks on the key length and its derivative
     * The Key is an AES-256 key, size is 32 bytes.
     * The Key derivative is a SHA-256 of the key, i.e. 32 bytes.
     */
    if((key_len != 32) || (h_key_len != 32)){
        goto err;
    }

    memset(key, 0, key_len);
    memset(h_key, 0, h_key_len);

    apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 64; apdu.send_le = 1;
    if(token_send_receive(&curr_token_channel, &apdu, &resp)){
        goto err;
    }

    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        /* The smartcard responded an error */
        goto err;
    }

    /* This is not the length we expect! */
    if(resp.le != 64){
        goto err;
    }

    /* In order to avoid fault attacks on the token logics without providing a PIN, sensitive
     * secrets are encrypted using a key derived from it.
     * The KEY used here is a 128-bit AES key as the first half of SHA-256(first_IV || SHA-256(PIN)).
     */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (uint8_t*)pin, pin_len);
    sha256_final(&sha256_ctx, digest);

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, curr_token_channel.first_IV, sizeof(curr_token_channel.first_IV));
    sha256_update(&sha256_ctx, digest, sizeof(digest));
    sha256_final(&sha256_ctx, digest);

    /* Decrypt our response buffer */
    /* [RB] FIXME: this should be a AES_DECRYPT here instread of AES_ENCRYPT, but for now we only have
     * a masked encryption. This MUST migrated as soon as a masked decryption is available.
     */
    #if defined(__arm__)
    /* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
    if(aes_init(&aes_context, digest, AES128, curr_token_channel.IV, CBC, AES_ENCRYPT, AES_SOFT_ANSSI_MASKED, NULL, NULL, -1, -1)){
#else
    /* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
    if(aes_init(&aes_context, digest, AES128, curr_token_channel.IV, CBC, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
        goto err;
    }
    /* Decrypt */
    if(aes(&aes_context, resp.data, resp.data, resp.le, -1, -1)){
        goto err;
    }

    /* Now split the response */
    memcpy(key, resp.data, key_len);
    memcpy(h_key, resp.data + key_len, h_key_len);

    return 0;
err:
    return -1;

}


int token_early_init(void){
    return SC_fsm_early_init();
}


int token_init(void){
    SC_ATR atr;
    uint8_t T_protocol;

    curr_token_channel.channel_initialized = 0;
    curr_token_channel.secure_channel = 0;

    /* Initialize the card communication */
    if(SC_fsm_init(&atr, &T_protocol, 0, 0)){
        SC_print_ATR(&atr);
        goto err;
    }

    curr_token_channel.atr = atr;
    curr_token_channel.T_protocol = T_protocol;
    curr_token_channel.channel_initialized = 1;

    return 0;
err:
    return -1;
}

int token_secure_channel_init(void){
    if(token_select_applet(&curr_token_channel, applet_AID, sizeof(applet_AID))){
        goto err;
    }

    if(token_negotiate_secure_channel(&curr_token_channel)){
        goto err;
    }
    return 0;
err:
    return -1;
}

