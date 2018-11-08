#include "smartcard_auth_token.h"
#include "ipc_proto.h"

/* Include our encrypted platform keys  */
#include "AUTH/encrypted_platform_auth_keys.h"

#include "api/syscall.h"
#include "api/print.h"


#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

/* Primitive for debug output */
#ifdef SMARTCARD_DEBUG
#define log_printf(...) printf(__VA_ARGS__)
#else
#define log_printf(...)
#endif

/*FIXME: not clean*/
extern uint8_t id_pin;

static const unsigned char auth_applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x70 };

/* Get key and its derivative */
int auth_token_get_key(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len, unsigned char *h_key, unsigned int h_key_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	/* SHA256 context used to derive our secrets */
	sha256_context sha256_ctx;
	/* Digest buffer */
	uint8_t digest[SHA256_DIGEST_SIZE];
	/* AES context to decrypt the response */
	aes_context aes_context;
        uint8_t enc_IV[AES_BLOCK_SIZE];

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	/* Sanity check */
	if((pin == NULL) || (key == NULL) || (h_key == NULL)){
		goto err;
	}
	/* Sanity checks on the key length and its derivative
	 * The Key is an AES-256 key, size is 32 bytes.
	 * The Key derivative is a SHA-256 of the key, i.e. 32 bytes.
	 */
	if((key_len != 32) || (h_key_len != SHA256_DIGEST_SIZE)){
		goto err;
	}

	memset(key, 0, key_len);
	memset(h_key, 0, h_key_len);

        /* Save the current IV and compute the AES-CBC IV (current IV incremented by 1) */
        memcpy(enc_IV, channel->IV, sizeof(enc_IV));
        add_iv(enc_IV, 1);

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = (key_len + h_key_len); apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
	if(resp.le != (key_len + h_key_len)){
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
	sha256_update(&sha256_ctx, channel->first_IV, sizeof(channel->first_IV)); 
	sha256_update(&sha256_ctx, digest, sizeof(digest));
	sha256_final(&sha256_ctx, digest);

	/* Decrypt our response buffer */
	/* [RB] FIXME: this should be a AES_DECRYPT here instread of AES_ENCRYPT, but for now we only have 
	 * a masked encryption. This MUST migrated as soon as a masked decryption is available.
	 */
#if defined(__arm__)
	/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_ENCRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
	/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
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

/* We provide two callbacks: one to ask for the PET pin, the other to 
 * ask for the user PIN while showing the PET name to get confirmation.
 */
int auth_token_exchanges(token_channel *channel, cb_auth_token_ask_pet_pin_t ask_pet_pin, cb_auth_token_ask_user_pin_t ask_user_pin, unsigned char *AES_CBC_ESSIV_key, unsigned int AES_CBC_ESSIV_key_len, unsigned char *AES_CBC_ESSIV_h_key, unsigned int AES_CBC_ESSIV_h_key_len){
	int ret;
	unsigned int i;

	char pet_pin[16] = { 0 };
	char user_pin[16] = { 0 };
	char pet_name[32] = { 0 };
	unsigned int pet_pin_len, user_pin_len, pet_name_len;

	/* Decrypt the platform keys provided the PET PIN value  */
	unsigned char decrypted_token_pub_key_data_auth[sizeof(token_pub_key_data_auth)];
	unsigned char decrypted_platform_priv_key_data_auth[sizeof(platform_priv_key_data_auth)];
	unsigned char decrypted_platform_pub_key_data_auth[sizeof(platform_pub_key_data_auth)];
	databag decrypted_auth_keybag[] = {
		{ .data = decrypted_token_pub_key_data_auth, .size = sizeof(decrypted_token_pub_key_data_auth) },
		{ .data = decrypted_platform_priv_key_data_auth, .size = sizeof(decrypted_platform_priv_key_data_auth) },
		{ .data = decrypted_platform_pub_key_data_auth, .size = sizeof(decrypted_platform_pub_key_data_auth) },
	};


#ifdef MEASURE_TOKEN_PERF
	uint64_t start, end;
	uint64_t start_secure_channel, end_secure_channel;
	uint64_t start_decrypt_keys, end_decrypt_keys;

        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Sanity check */
	if((channel == NULL) || (ask_pet_pin == NULL) || (ask_user_pin == NULL) || (AES_CBC_ESSIV_key == NULL) || (AES_CBC_ESSIV_h_key == NULL)){
		goto err;
	}
	if((AES_CBC_ESSIV_key_len != 32) || (AES_CBC_ESSIV_h_key_len != 32)){
		goto err;
	}

        /* Zeroize token channel */
        channel->channel_initialized = 0; 
	channel->secure_channel = 0;
	memset(channel->IV, 0, sizeof(channel->IV));
	memset(channel->first_IV, 0, sizeof(channel->first_IV));
	memset(channel->AES_key, 0, sizeof(channel->AES_key));
	memset(channel->HMAC_key, 0, sizeof(channel->HMAC_key));

	/* Initialize the low level layer (ISO7816-3 or ISO14443-4) */
	if(token_init(channel)){
		goto err;
	}

	log_printf("[AUTH Token] Initialization is OK!\n");
        SC_print_Card(&(channel->card));

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start_decrypt_keys, PREC_MILLI);
#endif
        /* Select the AUTH applet on the token */
        if(token_select_applet(channel, auth_applet_AID, sizeof(auth_applet_AID))){
                goto err;
        }

    struct sync_command      ipc_sync_cmd = { 0 };
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    logsize_t size = 0;
    uint8_t id = 0;


	/* Ask the user for the PET PIN */
	pet_pin_len = sizeof(pet_pin);
	if(ask_pet_pin(pet_pin, &pet_pin_len)){
        printf("[Pet Pin] Failed to ask for pet pin!\n");
		goto err;
	}

	/* Decrypt the platform keys */
	if(decrypt_platform_keys(channel, pet_pin, pet_pin_len, keybag_auth, sizeof(keybag_auth)/sizeof(databag), decrypted_auth_keybag, sizeof(decrypted_auth_keybag)/sizeof(databag), PLATFORM_PBKDF2_ITERATIONS)){

        ipc_sync_cmd.magic = MAGIC_CRYPTO_PETPIN_RESP;
        ipc_sync_cmd.state = SYNC_FAILURE;
        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

        printf("[Platform] Failed to decrypt platform keys!\n");
		goto err;
	}

    ipc_sync_cmd.magic = MAGIC_CRYPTO_PETPIN_RESP;
    ipc_sync_cmd.state = SYNC_DONE;
    sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);



#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end_decrypt_keys, PREC_MILLI);
	log_printf("[AUTH Token] Keys decryption is OK! Time taken = %lld milliseconds\n", (end_decrypt_keys - start_decrypt_keys));
#endif

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start_secure_channel, PREC_MILLI);
#endif

	/* Initialize the secure channel with the token */
	if(token_secure_channel_init(channel, decrypted_platform_priv_key_data_auth, sizeof(decrypted_platform_priv_key_data_auth), decrypted_platform_pub_key_data_auth, sizeof(decrypted_platform_pub_key_data_auth), decrypted_token_pub_key_data_auth, sizeof(decrypted_token_pub_key_data_auth), USED_SIGNATURE_CURVE)){
		log_printf("[XX] [AUTH Token] Secure channel negotiation error ...\n");
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end_secure_channel, PREC_MILLI);
	log_printf("[AUTH Token] Secure channel negotiation is OK! Time taken = %lld milliseconds\n", (end_secure_channel - start_secure_channel));
#else
	log_printf("[AUTH Token] Secure channel negotiation is OK!\n");
#endif

	/*************** Send PET PIN */
	unsigned char pin_ok;
	unsigned int remaining_tries;
	if(token_send_pin(channel, pet_pin, pet_pin_len, &pin_ok, &remaining_tries, TOKEN_PET_PIN)){
		goto err;
	}
	if(!pin_ok){
		log_printf("[AUTH Token] PET PIN is NOT OK, remaining tries = %d\n", remaining_tries);
		goto err;
	}

	/*************** Get PET Name */
	pet_name_len = sizeof(pet_name);
	if(token_get_pet_name(channel, pet_name, &pet_name_len)){
		log_printf("[AUTH Token] ERROR when getting the PET NAME\n");
		goto err;
	}
	log_printf("[AUTH Token] PET NAME is '");
	for(i = 0; i < pet_name_len; i++){
		log_printf("%c", pet_name[i]);
	}
	log_printf("'\n");



    /************* Send pet name to pin */

    /* receive pet name requet from pin */
    size = sizeof(struct sync_command);
    id = id_pin;
    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (ipc_sync_cmd.magic == MAGIC_CRYPTO_PETPIN_CMD &&
        ipc_sync_cmd.state == SYNC_ASK_FOR_DATA) {

        ipc_sync_cmd_data.magic = MAGIC_CRYPTO_PETPIN_RESP;
        ipc_sync_cmd_data.state = SYNC_DONE;
        ipc_sync_cmd_data.data_size = pet_name_len;
        memset(&ipc_sync_cmd_data.data.u8, 0x0, 32);
        memcpy(&ipc_sync_cmd_data.data.u8, pet_name, pet_name_len);

        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

        /* now we wait for PIN to inform us if the pet name is okay for the user */

        id = id_pin;
        size = sizeof(struct sync_command);
        sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        if (ipc_sync_cmd.magic != MAGIC_CRYPTO_PETPIN_RESP ||
            ipc_sync_cmd.state != SYNC_ACKNOWLEDGE) {
            printf("Pin hasn't acknowledge the Pet name !\n");
            goto err;
        }
    }

    log_printf("[AUTH Token] Pen name acknowledge by the user\n");
    /*************** Get User PIN */


	/* Ask for the USER pin while provdiding him the PET name */
	user_pin_len = sizeof(user_pin);
	if(ask_user_pin(pet_name, pet_name_len, user_pin, &user_pin_len)){
		goto err;
	}

	if(token_send_pin(channel, user_pin, user_pin_len, &pin_ok, &remaining_tries, TOKEN_USER_PIN)){
		goto err;
	}
	if(!pin_ok){
		log_printf("[AUTH Token] USER PIN is NOT OK, remaining tries = %d\n", remaining_tries);

        ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
        ipc_sync_cmd.state = SYNC_FAILURE;
        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

		goto err;
	}
    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    ipc_sync_cmd.state = SYNC_DONE;
    sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

	
	/*************** Get the CBC-ESSIV key and its hash */
	if(auth_token_get_key(channel, user_pin, user_pin_len, AES_CBC_ESSIV_key, AES_CBC_ESSIV_key_len, AES_CBC_ESSIV_h_key, AES_CBC_ESSIV_h_key_len)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	log_printf("[AUTH Token] [++++++++++++++] Total time for token communication %lld milliseconds [++++++++++++++]\n", (end - start));
#endif

	return 0;

err:
	ret = -1;

	return ret;
}
