#ifndef __SMARTCARD_DFU_TOKEN_H__
#define __SMARTCARD_DFU_TOKEN_H__

#include "smartcard_token.h"

/****** Token operations **************/
/* Our dfuentication token specific instructions */
enum dfu_token_instructions {
        /* This handles firmware encryption key derivation in DFU mode */
        TOKEN_INS_BEGIN_DECRYPT_SESSION = 0x20,
        TOKEN_INS_DERIVE_KEY = 0x21,
};

/* High level functions to communicate with the token */
int dfu_token_begin_decrypt_session(token_channel *channel, const unsigned char *iv, uint32_t iv_len, const unsigned char *iv_hmac, uint32_t iv_hmac_len);
int dfu_token_derive_key(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len);

/* Callbacks */
typedef int (*cb_dfu_token_ask_pet_pin_t)(char *pet_pin, unsigned int *pet_pin_len);
typedef int (*cb_dfu_token_ask_user_pin_t)(char *pet_name, unsigned int pet_name_len, char *user_pin, unsigned int *use_pin_len);
int dfu_token_exchanges(token_channel *channel, cb_dfu_token_ask_pet_pin_t ask_pet_pin, cb_dfu_token_ask_user_pin_t ask_user_pin);

#endif /* __SMARTCARD_DFU_TOKEN_H__ */
