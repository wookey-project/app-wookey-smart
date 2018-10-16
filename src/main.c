/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */

#include "api/syscall.h"
#include "api/print.h"
#include "libcryp.h"
#include "librng.h"
#include "smartcard_token.h"
#include "aes.h"
#include "ipc_proto.h"

#define SMART_DEBUG 0

/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
int _main(uint32_t task_id)
{
    /* FIXME: try to make key global, __GLOBAL_OFFSET_TAB error */
    char *wellcome_msg = "hello, I'm smart";
//    char buffer_out[2] = "@@";
    uint8_t id = 0;
    uint8_t id_crypto = 0;
    uint8_t id_pin = 0;
    e_syscall_ret ret = 0;
    logsize_t size = 32;
    int     dma_in_desc, dma_out_desc;

   struct sync_command ipc_sync_cmd;

    // smartcard vars
    // FIXME
    unsigned char pin_ok = 0;
    unsigned int remaining_tries = 0;
    int tokenret = 0;


    //

    printf("%s, my id is %x\n", wellcome_msg, task_id);

    ret = sys_init(INIT_GETTASKID, "crypto", &id_crypto);
    printf("crypto is task %x !\n", id_crypto);

    ret = sys_init(INIT_GETTASKID, "pin", &id_pin);
    printf("pin is task %x !\n", id_pin);


    cryp_early_init(false, CRYP_CFG, CRYP_PRODMODE, &dma_in_desc, &dma_out_desc);
    rng_early_init(RNG_THROUGH_CRYP);

    // FIXME
    tokenret = token_early_init();
    switch (tokenret) {
        case 1:
            printf("error while declaring GPIOs\n");
            break;
        case 2:
            printf("error while declaring USART\n");
            break;
        case 3:
            printf("error while init smartcard\n");
            break;
        default:
            printf("Smartcard early init done\n");
    }

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

    /*********************************************
     * Secure channel negocation
     *********************************************/

    /* Initialize the ISO7816-3 layer */
	if(!tokenret && token_init()){
		goto err;
	}

	if(!tokenret && token_secure_channel_init()){
		printf("[XX] [Token] Secure channel negotiation error ...\n");
		goto err;
	}
    /*******************************************
     * let's syncrhonize with other tasks
     *******************************************/
    size = 2;

    /* First, wait for pin to finish its init phase */
    id = id_pin;
    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("pin has finished its init phase, acknowledge...\n");
    }

    ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

    do {
      size = 2;
      ret = sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Then Syncrhonize with crypto */
    size = 2;

    printf("sending end_of_init syncrhonization to crypto\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from Crypto */
    id = id_crypto;

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP
        && ipc_sync_cmd.state == SYNC_ACKNOWLEDGE) {
        printf("crypto has acknowledge end_of_init, continuing\n");
    }


    /*********************************************
     * Wait for crypto to ask for key injection
     *********************************************/

    /* First, wait for pin to finish its init phase */
    id = id_crypto;
    size = 2;
    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd.magic == MAGIC_CRYPTO_INJECT_CMD
        && ipc_sync_cmd.state == SYNC_READY) {
        printf("crypto is requesting key injection...\n");
    }



    /*********************************************
     * Request PIN to pin task
     *********************************************/
    char pin[32] = {0};
    uint8_t pin_len = 0;

    printf("sending end_of_init syncrhonization to crypto\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_CMD;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_pin, 2, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from Crypto */
    id = id_pin;
    size = 35; /* max pin size: 32 */

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd.magic == MAGIC_CRYPTO_PIN_RESP
        && ipc_sync_cmd.state == SYNC_DONE) {
        printf("received pin from PIN\n");
        memcpy(pin, (void*)&(ipc_sync_cmd.data), ipc_sync_cmd.data_size);
        pin_len = ipc_sync_cmd.data_size;
        hexdump((uint8_t*)pin, pin_len);
    } else {
        goto err;
    }

    /*********************************************
     * Send PIN to token
     *********************************************/

#if 1
    // pin management should be separated in another function
    // token_pin_init(&pin, &len); // waiting for user PIN entry from pin app
    if (token_send_user_pin(pin, pin_len, &pin_ok, &remaining_tries)) {
		printf("[XX] [Token] Unable to send pin to token ...\n");
        // Error while mounting T=1 secure channel, sending NACK to pin
        //
        ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
        ipc_sync_cmd.state = SYNC_FAILURE;
        ipc_sync_cmd.data_size = 0;
        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
        goto err;
    }
#endif
    /*********************************************
     * Key injection in CRYP device
     *********************************************/
    /* Get key from token */
    unsigned char AES_CBC_ESSIV_key[32] = { 0 }; //"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
	unsigned char AES_CBC_ESSIV_h_key[32] = { 0 };

#if 1
	if (token_get_key(pin, pin_len, AES_CBC_ESSIV_key, sizeof(AES_CBC_ESSIV_key), AES_CBC_ESSIV_h_key, sizeof(AES_CBC_ESSIV_h_key))){
        ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
        ipc_sync_cmd.state = SYNC_FAILURE;
        ipc_sync_cmd.data_size = 0;
        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
		goto err;
	}
    // pin received and T=1 channel correctly mounted. sending ACK to pin
    //
    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    ipc_sync_cmd.state = SYNC_DONE;
    ipc_sync_cmd.data_size = 0;
    sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);


#endif
#ifdef SMART_DEBUG
    printf("key received:\n");
    hexdump(AES_CBC_ESSIV_key, 32);
    printf("hash received:\n");
    hexdump(AES_CBC_ESSIV_h_key, 32);
#endif

    /* inject key in CRYP device, iv=0, encrypt by default */
    cryp_init(AES_CBC_ESSIV_key, KEY_256, 0, AES_ECB, ENCRYPT);

    printf("cryptography and smartcard initialization done!\n");

    /***********************************************
     * Acknowledge key injection to Crypto
     * and send key hash
     ***********************************************/
    ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
    ipc_sync_cmd.state = SYNC_DONE;
    ipc_sync_cmd.data_size = (uint8_t)32;
    memcpy(&ipc_sync_cmd.data, AES_CBC_ESSIV_h_key, 32);

    do {
      size = 3 + 32;
      ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    // infinite loop at end of init
    printf("Acknowedge send, going back to sleep up keeping only smartcard watchdog.\n");
    while (1) {
        // detect Smartcard extraction using EXTI IRQ
//        sys_yield();
        id = id_crypto;
        size = sizeof (struct sync_command);

        // is there a smartcard ejection detection ?
        if (!SC_is_smartcard_inserted()) {
          sys_reset();
        }
        // is there a key schedule request ?
        ret = sys_ipc(IPC_RECV_ASYNC, &id, &size, (char*)&ipc_sync_cmd);

        if (ret == SYS_E_DONE) {
            //cryp_init_injector(AES_CBC_ESSIV_key, KEY_256);
            cryp_init(AES_CBC_ESSIV_key, KEY_256, 0, AES_ECB, (enum crypto_dir)ipc_sync_cmd.data[0]);

            ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
            ipc_sync_cmd.state = SYNC_DONE;
            ipc_sync_cmd.data_size = (uint8_t)0;

            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
        }
        // nothing ? just wait for next event
        sys_yield();
    }

err:
    printf("Oops\n");
    while (1) {

        sys_yield();
        // reset at first interrupt
        sys_reset();
    }

    return 0;
}
