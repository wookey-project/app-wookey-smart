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

token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };
uint8_t id_pin = 0;

int auth_token_ask_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    struct sync_command      ipc_sync_cmd = { 0 };
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("Request PIN for authentication\n");
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("Request PIN for modification\n");
    }
    else{
        goto err;
    }

    /*********************************************
     * Request PIN to pin task
     *********************************************/
    if(pin_type == TOKEN_PET_PIN){
	printf("Ask pet pin to PIN task\n");
        cmd_magic = MAGIC_CRYPTO_PETPIN_CMD;
        resp_magic = MAGIC_CRYPTO_PETPIN_RESP;
    }
    else if(pin_type == TOKEN_USER_PIN){
	printf("Ask user pin to PIN task\n");
        cmd_magic = MAGIC_CRYPTO_PIN_CMD;
        resp_magic = MAGIC_CRYPTO_PIN_RESP;
    }
    else{
	printf("Error: asking for unknown type pin ...\n");
	goto err;
    }
    ipc_sync_cmd.magic = cmd_magic;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd_data.magic == resp_magic
            && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("received pin from PIN\n");
        if(*pin_len < ipc_sync_cmd_data.data_size){
              goto err;
        }
        memcpy(pin, (void*)&(ipc_sync_cmd_data.data.u8), ipc_sync_cmd_data.data_size);
        *pin_len = ipc_sync_cmd_data.data_size;
        return 0;
    }

err:
    return -1;
}

int auth_token_confirm_pin(uint8_t ok, token_pin_types pin_type, token_pin_actions action){
    struct sync_command      ipc_sync_cmd = { 0 };

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("Request PIN for authentication\n");
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("Request PIN for modification\n");
    }
    else{
        goto err;
    }


    if(pin_type == TOKEN_USER_PIN){
       ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    }
    else if(pin_type == TOKEN_PET_PIN){
       ipc_sync_cmd.magic = MAGIC_CRYPTO_PETPIN_RESP;
    }
    else{
        goto err;
    }
    if(ok){
    	ipc_sync_cmd.state = SYNC_DONE;
    } else{
    	ipc_sync_cmd.state = SYNC_FAILURE;
    }
    sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);

	return 0;
err:
	return -1;
}

int auth_token_ask_pet_name(char *pet_name, unsigned int *pet_name_len)
{
    struct sync_command      ipc_sync_cmd = { 0 };
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    /*********************************************
     * Request PET name to pin task
     *********************************************/
    cmd_magic = MAGIC_CRYPTO_PETNAME_CMD;
    resp_magic = MAGIC_CRYPTO_PETNAME_RESP;

    ipc_sync_cmd.magic = cmd_magic;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    do {
        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    do {
        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
    } while (ret != SYS_E_DONE);
    if (   ipc_sync_cmd_data.magic == resp_magic
            && ipc_sync_cmd_data.state == SYNC_DONE) {
        printf("received pin from PIN\n");
        if(*pet_name_len < ipc_sync_cmd_data.data_size){
              goto err;
        }
        memcpy(pet_name, (void*)&(ipc_sync_cmd_data.data.u8), ipc_sync_cmd_data.data_size);
        *pet_name_len = ipc_sync_cmd_data.data_size;
        return 0;
    }

err:
    return -1;
}



int auth_token_confirm_pet_name(const char *pet_name, unsigned int pet_name_len)
{
    /************* Send pet name to pin */
    struct sync_command      ipc_sync_cmd = { 0 };
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    logsize_t size = 0;
    uint8_t id = 0;

    /* receive pet name requet from pin */
    size = sizeof(struct sync_command);
    id = id_pin;
    sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);

    if (ipc_sync_cmd.magic == MAGIC_CRYPTO_PETNAME_CMD &&
        ipc_sync_cmd.state == SYNC_ASK_FOR_DATA) {

        ipc_sync_cmd_data.magic = MAGIC_CRYPTO_PETNAME_RESP;
        ipc_sync_cmd_data.state = SYNC_DONE;
        ipc_sync_cmd_data.data_size = pet_name_len;
        memset(&ipc_sync_cmd_data.data.u8, 0x0, 32);
        memcpy(&ipc_sync_cmd_data.data.u8, pet_name, pet_name_len);

        sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);

        /* now we wait for PIN to inform us if the pet name is okay for the user */
        id = id_pin;
        size = sizeof(struct sync_command);
        sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
        if (ipc_sync_cmd.magic != MAGIC_CRYPTO_PETNAME_RESP ||
            ipc_sync_cmd.state != SYNC_ACKNOWLEDGE) {
            printf("Pin hasn't acknowledge the Pet name !\n");
            goto err;
        }
    }

    printf("[AUTH Token] Pen name acknowledge by the user\n");


    return 0;
err:
	return -1;
}

void smartcard_removal_action(void){
    /* Check if smartcard has been removed, and reboot if yes */
    if((curr_token_channel.card.type != SMARTCARD_UNKNOWN) && !SC_is_smartcard_inserted(&(curr_token_channel.card))){
        SC_smartcard_lost(&(curr_token_channel.card));
        sys_reset();
    }	
}

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
    e_syscall_ret ret = 0;
    logsize_t size = 32;
    int     dma_in_desc, dma_out_desc;

    struct sync_command      ipc_sync_cmd;
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
    size = sizeof(struct sync_command);

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
      size = sizeof(struct sync_command);
      ret = sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd);
    } while (ret != SYS_E_DONE);

    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to crypto\n");
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
    size = sizeof(struct sync_command);
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

    /* Register smartcard removal handler */
    curr_token_channel.card.type = SMARTCARD_CONTACT;
    SC_register_user_handler_action(&(curr_token_channel.card), smartcard_removal_action);
    curr_token_channel.card.type = SMARTCARD_UNKNOWN;
    
    /* Token callbacks */
    cb_token_callbacks auth_token_callbacks = { .ask_pin = auth_token_ask_pin, .confirm_pin = auth_token_confirm_pin, .ask_pet_name = auth_token_ask_pet_name, .confirm_pet_name = auth_token_confirm_pet_name };
    if(!tokenret && auth_token_exchanges(&curr_token_channel, &auth_token_callbacks, CBC_ESSIV_key, sizeof(CBC_ESSIV_key), CBC_ESSIV_h_key, sizeof(CBC_ESSIV_h_key)))
    {
        goto err;
    }

    /* Now that we have received our assets, we can lock the token.
     * We maintain the secure channel opened for a while, we only lock the
     * user PIN for now.
     */
    if(token_user_pin_lock(&curr_token_channel)){ 
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
    printf("AES256_CBC_ESSIV used!\n");
#else
#ifdef CONFIG_TDES_CBC_ESSIV 
    cryp_init_injector(CBC_ESSIV_key, KEY_192);
    /* In order to avoid cold boot attacks, we can safely erase the master key! */
    memset(CBC_ESSIV_key, 0, sizeof(CBC_ESSIV_key));
    printf("TDES_CBC_ESSIV used!\n");
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


    /*******************************************
     * Smart main event loop
     *******************************************/

    while (1) {
        // detect Smartcard extraction using EXTI IRQ
        id = ANY_APP;
        size = sizeof (struct sync_command_data);

        ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
        if (ret != SYS_E_DONE) {
            continue;
        }
       
	/***************************************************************************/ 
        if (id == id_crypto) {
            /*******************************
             * Managing Crypto task IPC
             ******************************/
            switch (ipc_sync_cmd_data.magic) {

                /********* Key injection request *************/
#ifdef CONFIG_AES256_CBC_ESSIV
                case MAGIC_CRYPTO_INJECT_CMD:
                    {
                        /* If we use AES-CBC-ESSIV, we might have to reinject the key! */
                        // is there a key schedule request ?

                        if (ret == SYS_E_DONE) {
                            cryp_init_injector(CBC_ESSIV_key, KEY_256);

                            ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
                            ipc_sync_cmd.state = SYNC_DONE;

                            sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
                        }
                        break;
                    }
#endif

                    /********* defaulting to none    *************/
                default:
                    {
                        break;
                    }
            }
        }

	/***************************************************************************/ 
        if (id == id_pin) {
            /*******************************
             * Managing Pin task IPC
             ******************************/
            switch (ipc_sync_cmd_data.magic) {
                /********* full authentication request *******/
                case MAGIC_CRYPTO_AUTH_CMD:
                    {
                        /* Here Pin is requesting a complete
                         * authentication phase with the token */
		        token_unlock_operations ops[] = { TOKEN_UNLOCK_ASK_PET_PIN, TOKEN_UNLOCK_ESTABLISH_SECURE_CHANNEL, TOKEN_UNLOCK_PRESENT_PET_PIN, TOKEN_UNLOCK_CONFIRM_PET_NAME, TOKEN_UNLOCK_PRESENT_USER_PIN };
		        if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks)){
				goto err;
			}
                        // channel_state = CHAN_UNLOCKED; /* token_lock() set this var to CHAN_LOCKED */

                        break;
                    }

                /********* set user pin into smartcard *******/
                case MAGIC_SETTINGS_SET_USERPIN:
                    {
                        /*
                        if (channel_state != CHAN_UNLOCKED) {
                          printf("channel has not been unlocked. You must authenticate yourself first\n");
                          continue;
                        }
                         */
                        /* set the new user pin. The CRYPTO_AUTH_CMD must have been passed and the channel being unlocked */
                        printf("updated user pin to %s (len %d) in smartcard\n", ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size);

		        token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_USER_PIN };
		        if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks)){
                        	printf("Unable to change user pin !!!\n");
				goto err;
			}

                        break;
                    }

                /********* set pet pin into smartcard *******/
                case MAGIC_SETTINGS_SET_PETPIN:
                    {
                        printf("updated pet pin to %s (len %d) in smartcard\n", ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size);

		        token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_PIN };
		        if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks)){
                        	printf("Unable to change pet pin !!!\n");
				goto err;
			}

                        break;
                    }

                /********* set pet pin into smartcard *******/
                case MAGIC_SETTINGS_SET_PETNAME:
                    {
                        printf("updated pet name to %s (len %d) in smartcard\n", ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size);

#if 0
                        if (token_set_pet_name(&curr_token_channel, (const char*)ipc_sync_cmd_data.data.u8, ipc_sync_cmd_data.data_size))
                        {
                            printf("Unable to change PET name !!!\n");
                            goto err;
                        }
#endif

                        break;
                    }

                /********* lock the device (by rebooting) ***/
                case MAGIC_SETTINGS_LOCK:
                    {
                        sys_reset();
                        while (1);
                        break;
                    }




                    /********* defaulting to none    *************/
                default:
                    {
                        break;
                    }
            }

        }

        // nothing ? just wait for next event
        sys_yield();
    }

err:
    printf("Oops\n");
    while (1) {
        // wait 2secs and reset
        sys_sleep(2000, SLEEP_MODE_INTERRUPTIBLE);
        sys_reset();
    }
    return 0;
}
