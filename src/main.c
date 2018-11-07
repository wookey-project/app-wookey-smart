/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */

#include "api/syscall.h"
#include "api/print.h"
#include "libcryp.h"
#include "smartcard_auth_token.h"
#include "smartcard_dfu_token.h"
#include "aes.h"
#include "ipc_proto.h"
#include "autoconf.h"

#define SMART_DEBUG 1


int auth_token_ask_pet_pin(__attribute__((unused)) char *pet_pin, __attribute__((unused)) unsigned int *pet_pin_len){
	memcpy(pet_pin, "1234", 4);
	*pet_pin_len = 4;
#if 0
    /*********************************************
     * Request PIN to pin task
     *********************************************/
    printf("asking for PET pin to the PIN task\n");
    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_CMD;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    do {
      ret = sys_ipc(IPC_SEND_SYNC, id_pin, 2, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from PIN */
    id = id_pin;
    size = *pet_pin_len+2; /* max pin size: 32 */

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd.magic == MAGIC_CRYPTO_PIN_RESP
        && ipc_sync_cmd.state == SYNC_DONE) {
        printf("received pin from PIN\n");
	if(ipc_sync_cmd.data_size > *pet_pin_len){
            goto err;
        }
        memcpy(pet_pin, (void*)&(ipc_sync_cmd.data), ipc_sync_cmd.data_size);
        (*pet_pint_len) = ipc_sync_cmd.data_size;
        //hexdump((uint8_t*)pin, pin_len);
    } else {
        goto err;
    }

    return 0;
err:
    return -1;
#endif
    return 0;
}

int auth_token_ask_user_pin(__attribute__((unused)) char *pet_name, __attribute__((unused)) unsigned int pet_name_len, __attribute__((unused)) char *user_pin, __attribute__((unused)) unsigned int *user_pin_len){
    memcpy(user_pin, "1234", 4);
    *user_pin_len = 4;
    return 0;
}


/*
 * We use the local -fno-stack-protector flag for main because
 * the stack protection has not been initialized yet.
 *
 * We use _main and not main to permit the usage of exactly *one* arg
 * without compiler complain. argc/argv is not a goot idea in term
 * of size and calculation in a microcontroler
 */
int _main(uint32_t __attribute__((unused)) task_id)
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
    struct sync_command_data ipc_sync_cmd_data;

    // smartcard vars
    int tokenret = 0;

    //

    printf("%s, my id is %x\n", wellcome_msg, task_id);

    ret = sys_init(INIT_GETTASKID, "crypto", &id_crypto);
    printf("crypto is task %x !\n", id_crypto);

    ret = sys_init(INIT_GETTASKID, "pin", &id_pin);
    printf("pin is task %x !\n", id_pin);


    cryp_early_init(false, CRYP_CFG, CRYP_PRODMODE, &dma_in_desc, &dma_out_desc);

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

    /*******************************************
     * let's synchronize with other tasks
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
     * AUTH token communication, to get key from it
     *********************************************/
    unsigned char CBC_ESSIV_key[32] = {0};
    unsigned char CBC_ESSIV_h_key[32] = {0};

    token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 } };
    if(!tokenret && auth_token_exchanges(&curr_token_channel, auth_token_ask_pet_pin, auth_token_ask_user_pin, CBC_ESSIV_key, sizeof(CBC_ESSIV_key), CBC_ESSIV_h_key, sizeof(CBC_ESSIV_h_key)))
    {
        goto err;
    }

#ifdef SMART_DEBUG
    printf("key received:\n");
    hexdump(CBC_ESSIV_key, 32);
    printf("hash received:\n");
    hexdump(CBC_ESSIV_h_key, 32);
#endif

    /* inject key in CRYP device, iv=0, encrypt by default */
#ifdef CONFIG_AES256_CBC_ESSIV
    cryp_init_injector(CBC_ESSIV_key, KEY_256);
#else
#ifdef CONFIG_TDES_CBC_ESSIV 
    cryp_init_injector(CBC_ESSIV_key, KEY_192);
    /* In order to avoid cold boot attacks, we can safely erase the master key! */
    memset(CBC_ESSIV_key, 0, sizeof(CBC_ESSIV_key));
#else
#error "No FDE algorithm has been selected ..."
#endif
#endif

    printf("cryptography and smartcard initialization done!\n");

    /***********************************************
     * Acknowledge key injection to Crypto
     * and send key hash
     ***********************************************/
    ipc_sync_cmd_data.magic = MAGIC_CRYPTO_INJECT_RESP;
    ipc_sync_cmd_data.state = SYNC_DONE;
    ipc_sync_cmd_data.data_size = (uint8_t)32;
    memcpy(&ipc_sync_cmd_data.data.u8, CBC_ESSIV_h_key, 32);

    do {
      size = sizeof(struct sync_command_data);
      ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd_data);
    } while (ret != SYS_E_DONE);

    // infinite loop at end of init
    printf("Acknowedge send, going back to sleep up keeping only smartcard watchdog.\n");
    while (1) {
        // detect Smartcard extraction using EXTI IRQ
//        sys_yield();
        id = id_crypto;
        size = sizeof (struct sync_command_data);

        // is there a smartcard ejection detection ?
        if (!SC_is_smartcard_inserted(&(curr_token_channel.card))) {
	  printf("Card ejection detected! Resetting the board through syscall!\n");
          sys_reset();
        }
#ifdef CONFIG_AES256_CBC_ESSIV
        /* If we use AES-CBC-ESSIV, we might have to reinject the key! */
        // is there a key schedule request ?
        ret = sys_ipc(IPC_RECV_ASYNC, &id, &size, (char*)&ipc_sync_cmd_data);

        if (ret == SYS_E_DONE) {
            cryp_init_injector(CBC_ESSIV_key, KEY_256);

            ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
            ipc_sync_cmd.state = SYNC_DONE;

            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
        }
#endif
        // nothing ? just wait for next event
        sys_yield();
    }

err:
    printf("Oops\n");
    while (1) {
        sys_yield();
        // reset at first interrupt
        //sys_reset();
    }
    return 0;
}
