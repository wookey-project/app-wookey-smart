/* Inlude elements related to ISO7816 and the board */
#include "smartcard_token.h"
#include "api/syscall.h"
#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

#include "api/print.h"

/****** Token operations **************/
/* [RB] FIXME: the layer handling the encryption and the integrity should
 * be abstracted and not dependent with the physical layer. For now these
 * layers are mixed because of the way ISO7816-3 mixes layers, but there should
 * be a clean way to split this and keep all the crypto code and the secure channel
 * code independent of the transport layer (so that the exact same code handles
 * tokens on ISO7816, I2C, SPI and so on).
 */

/* We describe hereafter the 'physical' layer to
 * communicate with our token. the rationale is to
 * distinguish between a 'clear text' channel before the
 * ECDH, and a secure channel protected in confidentiality
 * with AES-CTR and in integrity with a HMAC SHA256.
 * We are deemed to use AES with 128-bit keys because of
 * the lack of support for AES-192 and AES-256 in the current
 * mainstream Javacard cards.
 */

/* Self-synchronization anti-replay window of 10 attempts of a maximum size of AES blocks in an APDU */
#define ANTI_REPLAY_SELF_SYNC_WINDOW    (10*16)

int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp);

/* [RB] FIXME: this is a hell of number of arguments ... We should clearly find a way to reduce this! */
int decrypt_platform_keys(token_channel *channel, const char *pet_pin, uint32_t pet_pin_len, const databag *keybag, uint32_t keybag_num, databag *decrypted_keybag, uint32_t decrypted_keybag_num, uint32_t pbkdf2_iterations){
        uint8_t pbkdf[SHA512_DIGEST_SIZE];
        uint32_t pbkdf_len;
        hmac_context hmac_ctx;
        uint8_t hmac[SHA256_DIGEST_SIZE];
        uint32_t hmac_len = sizeof(hmac);
        aes_context aes_context;
        uint8_t *platform_salt = NULL;
        uint32_t platform_salt_len = 0;
        uint8_t *platform_iv = NULL;
        uint32_t platform_iv_len = 0;
        uint8_t *platform_hmac_tag = NULL;
        uint32_t platform_hmac_tag_len = 0;
        unsigned int i;
        uint8_t token_key[SHA512_DIGEST_SIZE];
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
    uint8_t error = 1;

	/* Sanity checks */
        if((pet_pin == NULL) || (keybag == NULL) || (decrypted_keybag == NULL)){
            printf("err %d\n", error++);
                goto err;
        }
        /* Sanity checks on lengths 
         * A Keybag contains at least an IV, a salt and a HMAC tag
         */
        if(keybag_num < 3){
            printf("err %d\n", error++);
                goto err;
        }
        if(decrypted_keybag_num != (keybag_num - 3)){
            printf("err %d\n", error++);
                goto err;
        }

        platform_iv = keybag[0].data;
        platform_iv_len = keybag[0].size;
        platform_salt = keybag[1].data;
        platform_salt_len = keybag[1].size;
        platform_hmac_tag = keybag[2].data;
        platform_hmac_tag_len = keybag[2].size;

        /* First of all, we derive our decryption and HMAC keys
         * from the PET PIN using PBKDF2.
         */
        pbkdf_len = sizeof(pbkdf);
        if(hmac_pbkdf2(SHA512, (unsigned char*)pet_pin, pet_pin_len, platform_salt, platform_salt_len, pbkdf2_iterations, SHA512_DIGEST_SIZE, pbkdf, &pbkdf_len)){
            printf("err %d\n", error++);
                goto err;
        }

	/* Once we have derived our PBKDF2 key, we ask the token for the decryption key */
	/* Sanity check: th secure channel must not be already negotiated */
	if((channel == NULL) || (channel->secure_channel == 1)){
            printf("err %d\n", error++);
		goto err;
	}
	apdu.cla = 0x00; apdu.ins = TOKEN_INS_DERIVE_LOCAL_PET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; 
	apdu.lc = SHA512_DIGEST_SIZE; apdu.le = SHA512_DIGEST_SIZE; apdu.send_le = 1;
	memcpy(apdu.data, pbkdf, pbkdf_len);
	if(token_send_receive(channel, &apdu, &resp)){
            printf("err %d\n", error++);
		goto err;
	}
	
	/******* Smartcard response ***********************************/
	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
            printf("err %d\n", error++);
		goto err;
	}
	if(resp.le != SHA512_DIGEST_SIZE){
		/* Bad response lenght */
            printf("err %d\n", error++);
		goto err;
	}
	memcpy(token_key, resp.data, SHA512_DIGEST_SIZE);

        /* First, we check the HMAC value, the HMAC key is the 256 right most bits of
         * the PBKDF2 value.
         */
        if(hmac_init(&hmac_ctx, token_key+32, SHA256_DIGEST_SIZE, SHA256)){
            printf("err %d\n", error++);
                goto err;
        }
        hmac_update(&hmac_ctx, platform_iv, platform_iv_len);
        hmac_update(&hmac_ctx, platform_salt, platform_salt_len);
        for(i = 0; i < (keybag_num - 3); i++){
                hmac_update(&hmac_ctx, keybag[i+3].data, keybag[i+3].size);
        }
        if(hmac_finalize(&hmac_ctx, hmac, &hmac_len)){
            printf("err %d\n", error++);
                goto err;
        }
        /* Check the HMAC tag and return an error if there is an issue */
        if((hmac_len != SHA256_DIGEST_SIZE) || (platform_hmac_tag_len != SHA256_DIGEST_SIZE)){
            printf("err %d\n", error++);
                goto err;
        }
        if(!are_equal(hmac, platform_hmac_tag, hmac_len)){
            printf("err %d\n", error++);
                goto err;
        }
        /* HMAC is OK, we can decrypt our data */
#if defined(__arm__)
        /* Use the protected masked AES ofr the platform keys decryption */
        /* [RB] FIXME: use a 256-bit AES when the masked implementation is ready to handle it */
        if(aes_init(&aes_context, token_key, AES128, platform_iv, CTR, AES_DECRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
        /* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
        if(aes_init(&aes_context, token_key, AES128, platform_iv, CTR, AES_DECRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
            printf("err %d\n", error++);
                goto err;
        }
        /* Decrypt all our data encapsulated in the keybag */
        for(i = 0; i < (keybag_num - 3); i++){
                if(aes(&aes_context, keybag[i+3].data, decrypted_keybag[i].data, decrypted_keybag[i].size, -1, -1)){
            printf("err %d\n", error++);
                        goto err;
                }
        }

        return 0;

err:
        return -1;
}

/* Secure channel negotiation:
 * We use an ECDH with mutual authentication in order to derive our session key and IV.
 */
/* [RB] FIXME: clean the sensitive values when they are no more used ... */
static int token_negotiate_secure_channel(token_channel *channel, const unsigned char *decrypted_platform_priv_key_data, uint32_t decrypted_platform_priv_key_data_len, const unsigned char *decrypted_platform_pub_key_data, uint32_t decrypted_platform_pub_key_data_len, const unsigned char *decrypted_token_pub_key_data, uint32_t decrypted_token_pub_key_data_len, ec_curve_type curve_type){
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
#ifdef USE_SIG_BLINDING
	nn scalar_b;
#endif
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

	/* Sanity checks */
	if((channel == NULL) || (decrypted_platform_priv_key_data == NULL) || (decrypted_platform_pub_key_data == NULL) || (decrypted_token_pub_key_data == NULL)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
	uint64_t start, end;
        sys_get_systick(&start, PREC_MILLI);
#endif

	/******* Reader answer ***********************************/
        /* Importing specific curve parameters from its type.
         */
        the_curve_const_parameters = ec_get_curve_params_by_type(curve_type);

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

	/* Import our platform ECDSA private and public keys */
	if(ec_structured_priv_key_import_from_buf(&(our_key_pair.priv_key),  &curve_params, decrypted_platform_priv_key_data, decrypted_platform_priv_key_data_len, ECDSA)){
		goto err;
	}
	if(ec_structured_pub_key_import_from_buf(&(our_key_pair.pub_key),  &curve_params, decrypted_platform_pub_key_data, decrypted_platform_pub_key_data_len, ECDSA)){
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
#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] BEGIN = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif
        /* Q = dG */
#ifdef USE_SIG_BLINDING
	/* NB: we use a blind scalar multiplication here since we do not want our
	 * private d to leak ...
	 */
	nn_init(&scalar_b, 0);
        if (nn_get_random_mod(&scalar_b, &(curve_params.ec_gen_order))) {
                goto err;
        }
        prj_pt_mul_monty_blind(&Q, &d, &(curve_params.ec_gen), &scalar_b, &(curve_params.ec_gen_order));
	/* Clear blinding scalar */
	nn_uninit(&scalar_b);
#else
        prj_pt_mul_monty(&Q, &d, &(curve_params.ec_gen));	
#endif

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] Q = dG Time taken = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif

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

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] ECDSA SIGN = %lld milliseconds\n", (end - start));
#endif

	/* The instruction to perform an ECDH is TOKEN_INS_SECURE_CHANNEL_INIT: the reader sends its random scalar 
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
	if(ec_structured_pub_key_import_from_buf(&token_pub_key, &curve_params, decrypted_token_pub_key_data, decrypted_token_pub_key_data_len, ECDSA)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start, PREC_MILLI);
#endif

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

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] ECDSA VERIFY = %lld milliseconds\n", (end - start));
#endif
	
	/* Signature is OK, now extract the point from the APDU */
	if(prj_pt_import_from_buf(&Q, resp.data, 3 * BYTECEIL(curve_params.ec_fp.p_bitlen), &(curve_params.ec_curve))){
		/* NB: prj_pt_import_from_buf checks if the point is indeed on the
		 * curve or not, and returns an error if this is not the case ...
		 */
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Now compute dQ where d is our secret */
#ifdef USE_SIG_BLINDING
	/* NB: we use a blind scalar multiplication here since we do not want our
	 * private d to leak ...
	 */
	nn_init(&scalar_b, 0);
        if (nn_get_random_mod(&scalar_b, &(curve_params.ec_gen_order))) {
                goto err;
        }
        prj_pt_mul_monty_blind(&Q, &d, &Q, &scalar_b, &(curve_params.ec_gen_order));
	/* Clear blinding scalar */
	nn_uninit(&scalar_b);
#else
        prj_pt_mul_monty(&Q, &d, &Q);
#endif


#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] dQ = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Clear d */
	nn_uninit(&d);
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

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] Symmetric crypto = %lld milliseconds\n", (end - start));
#endif

	/* Our secure channel is initialized */
	channel->secure_channel = 1;

        /* Uninit local variables */
        prj_pt_uninit(&Q);
        aff_pt_uninit(&Q_aff);

	return 0;
err:
	return -1;
}

/* APDU encryption and integrity */
static int token_apdu_cmd_encrypt(token_channel *channel, SC_APDU_cmd *apdu){
	hmac_context hmac_ctx;
	uint8_t hmac[SHA256_DIGEST_SIZE];
	uint8_t tmp;
	uint32_t hmac_len = sizeof(hmac);

	/* Sanitiy checks */
	if((channel == NULL) || (apdu == NULL)){
		goto err;
	}
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
#if defined(__arm__)
		/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
		/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
			goto err;
		}
		if(aes(&aes_context, apdu->data, apdu->data, apdu->lc, -1, -1)){
			goto err;
		}
		/* Increment the IV by as many blocks as necessary */
                add_iv(channel->IV, apdu->lc / AES_BLOCK_SIZE);

		/* Update the HMAC */
		tmp = (uint8_t)apdu->lc & 0xff;
		hmac_update(&hmac_ctx, &tmp, 1);
		hmac_update(&hmac_ctx, apdu->data, apdu->lc);
	}
	/* Always increment our anti-replay counter manually at least once fot the next data batch to send/receive */
	inc_iv(channel->IV);
	
	/* When encrypting an APDU, we always expect a response with at least 32 bytes of HMAC.
	 * In order to avoid any issue, we ask for a Le = 0 meaning that we expect a maximum amount of
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
	return -1;
}

static int token_apdu_resp_decrypt(token_channel *channel, SC_APDU_resp *resp){
	hmac_context hmac_ctx;
	uint8_t hmac[SHA256_DIGEST_SIZE];
	uint8_t hmac_recv[SHA256_DIGEST_SIZE];
	uint8_t tmp;
	int self_sync_attempts = ANTI_REPLAY_SELF_SYNC_WINDOW;
	uint32_t hmac_len = sizeof(hmac);

	/* Sanity check */
	if((channel == NULL) || (resp == NULL)){
		goto err;
	}
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
	if(!are_equal(hmac, hmac_recv, sizeof(hmac))){
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
#if defined(__arm__)
		/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
		/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
			goto err;
		}
		if(aes(&aes_context, resp->data, resp->data, resp->le, -1, -1)){
			goto err;
		}
		/* Increment the IV by as many blocks as necessary */
                add_iv(channel->IV, resp->le / AES_BLOCK_SIZE);
	}
	/* Always increment our anti-replay counter manually at least once fot the next data batch to send/receive */
	inc_iv(channel->IV);

	return 0;
err:
	return -1;
}

/* 
 * Try to send an APDU on the physical line multiple times
 * in case of possible errors before giving up ...
 */
#define TOKEN_MAX_SEND_APDU_TRIES 20
static int SC_send_APDU_with_errors(SC_APDU_cmd *apdu, SC_APDU_resp *resp, SC_Card *card){
	unsigned int num_tries;
	int ret;
	num_tries = 0;
	while(1){
		ret = SC_send_APDU(apdu, resp, card);
		num_tries++;
		if(!ret){
			return 0;
		}
		if(ret && (num_tries >= TOKEN_MAX_SEND_APDU_TRIES)){
			goto err;
		}
		if(!SC_is_smartcard_inserted(card)){
			/* Smartcard has been lost ... */
			goto err;
		}
		/* Wait the requested timeout with the card to reset the current APDU */
		SC_wait_card_timeout(card);
	}

err:
	return ret;
}

/* The token 'send'/'receive' primitive. Depending on the secure channel state, we
 * send raw or encrypted APDU data.
 * Because we want our secure channel to be compatible in T=0 and T=1, and since T=0
 * mixes the ISO layers and needs CLA/INS/P1/P2/P3, we do not encrypt these. They
 * are however part of the integrity tag computation in order to avoid integrity issues.
 *
 */
int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp){
#ifdef MEASURE_TOKEN_PERF
    uint64_t start, end;
#endif
    /* Sanity check */
    if((channel == NULL) || (apdu == NULL) || (resp == NULL)){
        goto err;
    }

#ifdef SMARTCARD_DEBUG
    SC_print_APDU(apdu);
#endif
#ifdef MEASURE_TOKEN_PERF
    sys_get_systick(&start, PREC_MILLI);
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
        if(SC_send_APDU_with_errors(apdu, resp, &(channel->card))){
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
        if(SC_send_APDU_with_errors(apdu, resp, &(channel->card))){
            goto err;
        }
    }

#ifdef MEASURE_TOKEN_PERF
    sys_get_systick(&end, PREC_MILLI);
#endif
#ifdef SMARTCARD_DEBUG
    SC_print_RESP(resp);
#endif
#ifdef MEASURE_TOKEN_PERF
    printf("[Token] [++++++++++++++] APDU send/receive took %lld milliseconds [++++++++++++++]\n", (end - start));
#endif

    return 0;

err:
#ifdef SMARTCARD_DEBUG
    printf("APDU send/receive error (secure channel or lower layers errors)\n");
#endif
    SC_smartcard_lost(&(channel->card));

    return -1;
}


/* Update AES and HMAC session keys given an input string */
void token_channel_session_keys_update(token_channel *channel, const char *in, unsigned int in_len, unsigned char use_iv){
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_context sha256_ctx;
    unsigned int i;

    /* Sanity check */
    if((channel == NULL) || (in == NULL)){
        return;
    }

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

/* Select an applet */
int token_select_applet(token_channel *channel, const unsigned char *aid, unsigned int aid_len){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;

    if((channel == NULL) || (aid == NULL)){
	goto err;
    }

    apdu.cla = 0x00; apdu.ins = TOKEN_INS_SELECT_APPLET; apdu.p1 = 0x04; apdu.p2 = 0x00; apdu.lc = aid_len;
    apdu.le = 0x00; apdu.send_le = 1;
    memcpy(apdu.data, aid, aid_len);

    if(token_send_receive(channel, &apdu, &resp)){
        goto err;
    }

    /* Check return status */
    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        goto err; 
    }

    return 0;

err:
    return -1;
}


/* Send a pin */
int token_send_pin(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *pin_ok, unsigned int *remaining_tries, token_pin_types pin_type){
	unsigned int i;
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	char padded_pin[16];

	if((pin == NULL) || (pin_ok == NULL) || (remaining_tries == NULL)){
		goto err;
	}

	*remaining_tries = 0;
	*pin_ok = 0;

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
	if(pin_type == TOKEN_PET_PIN){
		apdu.ins = TOKEN_INS_UNLOCK_PET_PIN;
	}
	else if(pin_type == TOKEN_USER_PIN){
		apdu.ins = TOKEN_INS_UNLOCK_USER_PIN;
	}
	else{
		goto err;
	}
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 16; apdu.le = 0x00; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
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
		token_channel_session_keys_update(channel, padded_pin, sizeof(padded_pin), 1);
	}

	return 0;
err:
	return -1;
}

/* Change user and PET PIN */
int token_change_pin(token_channel *channel, const char *pin, unsigned int pin_len, token_pin_types pin_type, const databag *keybag, uint32_t keybag_num, uint32_t pbkdf2_iterations){
	unsigned int i;
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	char padded_pin[16];
        uint8_t *platform_salt = NULL;
        uint32_t platform_salt_len = 0;
        uint8_t pbkdf[SHA512_DIGEST_SIZE];
        uint32_t pbkdf_len;

	if((pin == NULL) || (keybag == NULL)){
		goto err;
	}
	/* Sanity checks on lengths 
         * A Keybag contains at least an IV, a salt and a HMAC tag
         */
        if(keybag_num < 3){
                goto err;
        }
        platform_salt = keybag[1].data;
        platform_salt_len = keybag[1].size;

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
	for(i = pin_len; i < (sizeof(padded_pin)-1); i++){
		padded_pin[i] = 0;
	}
	padded_pin[15] = pin_len;

	for(i = 0; i < sizeof(padded_pin); i++){
		apdu.data[i] = padded_pin[i];
	}
	if(pin_type == TOKEN_PET_PIN){
	        pbkdf_len = sizeof(pbkdf);
        	if(hmac_pbkdf2(SHA512, (unsigned char*)pin, pin_len, platform_salt, platform_salt_len, pbkdf2_iterations, SHA512_DIGEST_SIZE, pbkdf, &pbkdf_len)){
                	goto err;
	        }
		if(pbkdf_len != SHA512_DIGEST_SIZE){
			goto err;
		}
		apdu.ins = TOKEN_INS_SET_PET_PIN;
		apdu.lc = 16 + SHA512_DIGEST_SIZE;
		memcpy(apdu.data+sizeof(padded_pin), pbkdf, SHA512_DIGEST_SIZE);
	}
	else if(pin_type == TOKEN_USER_PIN){
		apdu.ins = TOKEN_INS_SET_USER_PIN;
		apdu.lc = 16;
	}
	else{
		goto err;
	}
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00;
	apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/* Check the response */
	if(resp.le != 0){
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
int token_lock(token_channel *channel){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_LOCK; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
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

/* Get the PET Name */
int token_get_pet_name(token_channel *channel, char *pet_name, unsigned int *pet_name_length){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	if((pet_name == NULL) || (pet_name_length == NULL)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_PET_NAME; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	/* Check the input length */
	if(*pet_name_length < resp.le){
		goto err;
	}

	*pet_name_length  = resp.le;
	memcpy(pet_name, resp.data, resp.le);

	return 0;
err:
	return -1;
}

/* Set the PET Name */
int token_set_pet_name(token_channel *channel, char *pet_name, unsigned int pet_name_length){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	if(pet_name == NULL){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_SET_PET_NAME; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = pet_name_length; apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
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

int token_secure_channel_init(token_channel *channel, const unsigned char *decrypted_platform_priv_key_data, uint32_t decrypted_platform_priv_key_data_len, const unsigned char *decrypted_platform_pub_key_data, uint32_t decrypted_platform_pub_key_data_len, const unsigned char *decrypted_token_pub_key_data, uint32_t decrypted_token_pub_key_data_len, ec_curve_type curve_type){

	if(channel == NULL){
		goto err;
	}
	/* [RB] NOTE: the rest of the sanity checks on the pointers should be performed by the lower
	 * functions.
	 */
	if(token_negotiate_secure_channel(channel, decrypted_platform_priv_key_data, decrypted_platform_priv_key_data_len, decrypted_platform_pub_key_data, decrypted_platform_pub_key_data_len, decrypted_token_pub_key_data, decrypted_token_pub_key_data_len, curve_type)){
		goto err;
	}
	return 0;
err:
	return -1;
}



/**********************************************************************/
int token_early_init(void){
    return SC_fsm_early_init();
}

int token_init(token_channel *channel){
	SC_Card card;

	if(channel == NULL){
		goto err;
	}

	channel->channel_initialized = 0;
	channel->secure_channel = 0;

        /* Initialize the card communication. First, try to negotiate PSS,
         * and do it without negotiation if it fails.
	 * In our use case, we expect the T=1 protocol to be used, so we
	 * force its usage.
         */
        if(SC_fsm_init(&card, 1, 1, 0, 64)){
               if(SC_fsm_init(&card, 0, 0, 0, 0)){
                       goto err;
               }
        }

	channel->card = card;
	channel->channel_initialized = 1;

	return 0;
err:
	return -1;
}
