#ifndef __SMARTCARD_TOKEN_H__
#define __SMARTCARD_TOKEN_H__

#include "libsmartcard.h"

int token_early_init(void);
/* High level functions to communicate with the token */
int token_init(void);

int token_secure_channel_init(void);

int     token_send_user_pin(const char *pin,
                            unsigned int pin_len,
                            unsigned char *pin_ok,
                            unsigned int *remaining_tries);

int     token_change_pin(char *pin,
                         uint8_t pin_len);

int token_lock(void);

int token_get_key(const char *pin,
                  unsigned int pin_len,
                  unsigned char *key,
                  unsigned int key_len,
                  unsigned char *h_key,
                  unsigned int h_key_len);

#endif /* __SMARTCARD_TOKEN_H__ */
