#include "smartcard_dfu_token.h"
#include "api/syscall.h"
#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

#include "api/print.h"

/* Include our encrypted platform keys  */
#include "DFU/encrypted_platform_dfu_keys.h"

#define SMARTCARD_DEBUG

/* Primitive for debug output */
#ifdef SMARTCARD_DEBUG
#define log_printf(...) printf(__VA_ARGS__)
#else
#define log_printf(...)
#endif


static const unsigned char dfu_applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x71 };

/* Ask the DFU token to begin a decrypt session by sending the initial IV and its HMAC */
int dfu_token_begin_decrypt_session(token_channel *channel, const unsigned char *iv, uint32_t iv_len, const unsigned char *iv_hmac, uint32_t iv_hmac_len){
        SC_APDU_cmd apdu;
        SC_APDU_resp resp;

	/* Sanity checks */
	if((channel == NULL) || (iv == NULL) || (iv_hmac == NULL)){
		goto err;
	}
	/* Sanity checks on the sizes */
	if((iv_len != AES_BLOCK_SIZE) || (iv_hmac_len != SHA256_DIGEST_SIZE)){
		goto err;
	}

        apdu.cla = 0x00; apdu.ins = TOKEN_INS_BEGIN_DECRYPT_SESSION; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = AES_BLOCK_SIZE+SHA256_DIGEST_SIZE; apdu.le = 0; apdu.send_le = 1;
	memcpy(apdu.data, iv, iv_len);
	memcpy(apdu.data+iv_len, iv_hmac, iv_hmac_len);
        if(token_send_receive(channel, &apdu, &resp)){
                goto err;
        }

        /******* Token response ***********************************/
        if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                /* The smartcard responded an error */
                goto err;
        }
	
        return 0;
err:
        return -1;
}

/* Ask the DFU token to derive a session key for a firmware chunk */
int dfu_token_derive_key(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len){
        SC_APDU_cmd apdu;
        SC_APDU_resp resp;

        /* Sanity checks */
        if((channel == NULL) || (derived_key == NULL)){
                goto err;
        }
	if(derived_key_len < AES_BLOCK_SIZE){
		goto err;
	}
	
        apdu.cla = 0x00; apdu.ins = TOKEN_INS_DERIVE_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = AES_BLOCK_SIZE; apdu.send_le = 1;
        if(token_send_receive(channel, &apdu, &resp)){
                goto err;
        }

        /******* Token response ***********************************/
        if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                /* The smartcard responded an error */
                goto err;
        }
	/* Check the response */
	if(resp.le != AES_BLOCK_SIZE){
		goto err;
	}
	memcpy(derived_key, resp.data, AES_BLOCK_SIZE);
	
        return 0;
err:
        return -1;
}

int dfu_token_exchanges(token_channel *channel, cb_dfu_token_ask_pet_pin_t ask_pet_pin, cb_dfu_token_ask_user_pin_t ask_user_pin){
	int ret;
	unsigned int i;

        char pet_pin[16] = { 0 };
        char user_pin[16] = { 0 };
        char pet_name[32] = { 0 };
        unsigned int pet_pin_len, user_pin_len, pet_name_len;
	/* Decrypt the platform keys provided the PET PIN value  */
	unsigned char decrypted_token_pub_key_data_dfu[sizeof(token_pub_key_data_dfu)];
	unsigned char decrypted_platform_priv_key_data_dfu[sizeof(platform_priv_key_data_dfu)];
	unsigned char decrypted_platform_pub_key_data_dfu[sizeof(platform_pub_key_data_dfu)];
	unsigned char decrypted_firmware_sig_pub_key_data_dfu[sizeof(firmware_sig_pub_key_data_dfu)];
	databag decrypted_dfu_keybag[] = {
        	{ .data = decrypted_token_pub_key_data_dfu, .size = sizeof(decrypted_token_pub_key_data_dfu) },
	        { .data = decrypted_platform_priv_key_data_dfu, .size = sizeof(decrypted_platform_priv_key_data_dfu) },
        	{ .data = decrypted_platform_pub_key_data_dfu, .size = sizeof(decrypted_platform_pub_key_data_dfu) },
	        { .data = decrypted_firmware_sig_pub_key_data_dfu, .size = sizeof(firmware_sig_pub_key_data_dfu) },
	};

#ifdef MEASURE_TOKEN_PERF
	uint64_t start, end;
	uint64_t start_secure_channel, end_secure_channel;
	uint64_t start_decrypt_keys, end_decrypt_keys;

        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Sanity check */
	if((channel == NULL) || (ask_pet_pin == NULL) || (ask_user_pin == NULL)){
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

	log_printf("[DFU Token] Initialization is OK!\n");
        SC_print_Card(&(channel->card));

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start_decrypt_keys, PREC_MILLI);
#endif

	/* Select the DFU applet on the token */
        if(token_select_applet(channel, dfu_applet_AID, sizeof(dfu_applet_AID))){
                goto err;
        }

        /* Ask the user for the PET PIN */
        pet_pin_len = sizeof(pet_pin);
        if(ask_pet_pin(pet_pin, &pet_pin_len)){
                goto err;
        }

	/* Decrypt the platform keys */
	if(decrypt_platform_keys(channel, pet_pin, pet_pin_len, keybag_dfu, sizeof(keybag_dfu)/sizeof(databag), decrypted_dfu_keybag, sizeof(decrypted_dfu_keybag)/sizeof(databag), PLATFORM_PBKDF2_ITERATIONS)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end_decrypt_keys, PREC_MILLI);
	log_printf("[DFU Token] Keys decryption is OK! Time taken = %lld milliseconds\n", (end_decrypt_keys - start_decrypt_keys));
#endif

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start_secure_channel, PREC_MILLI);
#endif

	/* Initialize the secure channel with the token */
	if(token_secure_channel_init(channel, decrypted_platform_priv_key_data_dfu, sizeof(decrypted_platform_priv_key_data_dfu), decrypted_platform_pub_key_data_dfu, sizeof(decrypted_platform_pub_key_data_dfu), decrypted_token_pub_key_data_dfu, sizeof(decrypted_token_pub_key_data_dfu), USED_SIGNATURE_CURVE)){
		log_printf("[XX] [DFU Token] Secure channel negotiation error ...\n");
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end_secure_channel, PREC_MILLI);
	log_printf("[DFU Token] Secure channel negotiation is OK! Time taken = %lld milliseconds\n", (end_secure_channel - start_secure_channel));
#else
	log_printf("[DFU Token] Secure channel negotiation is OK!\n");
#endif

	unsigned char pin_ok;
	unsigned int remaining_tries;
        if(token_send_pin(channel, pet_pin, pet_pin_len, &pin_ok, &remaining_tries, TOKEN_PET_PIN)){
		goto err;
	}
	if(!pin_ok){
		log_printf("[DFU Token] PET PIN is NOT OK, remaining tries = %d\n", remaining_tries);
		goto err;
	}

        pet_name_len = sizeof(pet_name);
        if(token_get_pet_name(channel, pet_name, &pet_name_len)){
		log_printf("[DFU Token] ERROR when getting the PET NAME\n");
		goto err;
	}
	log_printf("[DFU Token] PET NAME is '");
	for(i = 0; i < pet_name_len; i++){
		log_printf("%c", pet_name[i]);
	}
	log_printf("'\n");

        /* Ask for the USER pin while provdiding him the PET name */
        user_pin_len = sizeof(user_pin);
        if(ask_user_pin(pet_name, pet_name_len, user_pin, &user_pin_len)){
                goto err;
        }

        if(token_send_pin(channel, user_pin, user_pin_len, &pin_ok, &remaining_tries, TOKEN_USER_PIN)){
		goto err;
	}
	if(!pin_ok){
		log_printf("[DFU Token] USER PIN is NOT OK, remaining tries = %d\n", remaining_tries);
		goto err;
	}

	unsigned char iv[] = "\xb9\xec\x9d\xce\x21\xf9\x3a\x68\xc5\x47\x0e\x2a\x52\xc8\x9b\x9e";
	unsigned char iv_hmac[] = "\xbb\x31\x52\x34\xdb\x3f\x87\x82\x9c\x93\xc6\x56\x79\x71\x4d\x2c\xe1\x52\xd1\xa6\x71\xc4\x50\x98\x43\x7f\x7c\xba\x67\xeb\xe5\x3f";
	dfu_token_begin_decrypt_session(channel, iv, 16, iv_hmac, 32);

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	log_printf("[DFU Token] [++++++++++++++] Total time for token communication %lld milliseconds [++++++++++++++]\n", (end - start));
#endif

	return 0;

err:
	ret = -1;

	return ret;
}
