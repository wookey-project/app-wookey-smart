/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

/**
 * @file main.c
 *
 * \brief Main of dummy
 *
 */

#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libcryp.h"
#include "libtoken_auth.h"
#include "libtoken_dfu.h"
#include "aes.h"
#include "wookey_ipc.h"
#include "autoconf.h"
#include "libc/sanhandlers.h"
#include "generated/bsram_keybag.h"

#define CONFIG_SMARTCARD_DEBUG 0

#ifdef CONFIG_APP_SMART_USE_BKUP_SRAM
/* Map and unmap the Backup SRAM */
static volatile bool bsram_keybag_is_mapped = false;
static volatile int  dev_bsram_keybag_desc = 0;
static int bsram_keybag_init(void){
    const char *name = "bsram-keybag";
    e_syscall_ret ret = 0;

    device_t dev;
    memset((void*)&dev, 0, sizeof(device_t));
    strncpy(dev.name, name, sizeof (dev.name));
    dev.address = bsram_keybag_dev_infos.address;
    dev.size = bsram_keybag_dev_infos.size;
    dev.map_mode = DEV_MAP_VOLUNTARY;

    dev.irq_num = 0;
    dev.gpio_num = 0;
    int dev_bsram_keybag_desc_ = dev_bsram_keybag_desc;
    ret = sys_init(INIT_DEVACCESS, &dev, (int*)&dev_bsram_keybag_desc_);
    if(ret != SYS_E_DONE){
        printf("Error: Backup SRAM keybag, sys_init error!\n");
        goto err;
    }
    dev_bsram_keybag_desc = dev_bsram_keybag_desc_;

    return 0;
err:
    return -1;
}

static int bsram_keybag_map(void){
    if(bsram_keybag_is_mapped == false){
        e_syscall_ret ret;
        ret = sys_cfg(CFG_DEV_MAP, dev_bsram_keybag_desc);
        if (ret != SYS_E_DONE) {
            printf("Unable to map Backup SRAM keybag!\n");
            goto err;
        }
        bsram_keybag_is_mapped = true;
    }

    return 0;
err:
    return -1;
}

static int bsram_keybag_unmap(void){
    if(bsram_keybag_is_mapped){
        e_syscall_ret ret;
        ret = sys_cfg(CFG_DEV_UNMAP, dev_bsram_keybag_desc);
        if (ret != SYS_E_DONE) {
            printf("Unable to unmap Backup SRAM keybag!\n");
            goto err;
        }
        bsram_keybag_is_mapped = false;
    }

    return 0;
err:
    return -1;
}
#endif


token_channel curr_token_channel = { .channel_initialized = 0, .secure_channel = 0, .IV = { 0 }, .first_IV = { 0 }, .AES_key = { 0 }, .HMAC_key = { 0 }, .pbkdf2_iterations = 0, .platform_salt_len = 0 };
uint8_t id_pin = 0;

char global_pin[32] = { 0 };
unsigned int global_pin_len = 0;
unsigned char sdpwd[16] = { 0 };

int auth_token_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action)
{
    struct sync_command_data ipc_sync_cmd = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("Request PIN for authentication\n");
        ipc_sync_cmd.data.req.sc_req = SC_REQ_AUTHENTICATE;
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("Request PIN for modification\n");
        ipc_sync_cmd.data.req.sc_req = SC_REQ_MODIFY;
    }
    else{
        goto err;
    }

    /*********************************************
     * Request PIN to pin task
     *********************************************/
    cmd_magic = MAGIC_CRYPTO_PIN_CMD;
    resp_magic = MAGIC_CRYPTO_PIN_RESP;

    if(pin_type == TOKEN_PET_PIN){
        printf("Ask pet pin to PIN task\n");
        ipc_sync_cmd.data.req.sc_type = SC_PET_PIN;
    } else if (pin_type == TOKEN_USER_PIN){
	printf("Ask user pin to PIN task\n");
        ipc_sync_cmd.data.req.sc_type = SC_USER_PIN;
    }
    else{
	printf("Error: asking for unknown type pin ...\n");
	goto err;
    }
    ipc_sync_cmd.magic = cmd_magic;
    ipc_sync_cmd.state = SYNC_ASK_FOR_DATA;

    ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_pin) failed! Exiting...\n");
        return 1;
    }

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }

    if (   (ipc_sync_cmd.magic == resp_magic)
            && (ipc_sync_cmd.state == SYNC_DONE)) {
        printf("received pin from PIN\n");
        if((*pin_len) < ipc_sync_cmd.data_size){
              goto err;
        }
        memcpy(pin, (void*)&(ipc_sync_cmd.data.u8), ipc_sync_cmd.data_size);
        *pin_len = ipc_sync_cmd.data_size;
        memcpy(global_pin, pin, *pin_len);
        global_pin_len = *pin_len;
        return 0;
    }

err:
    return -1;
}

int auth_token_acknowledge_pin(token_ack_state ack, token_pin_types pin_type, token_pin_actions action, uint32_t remaining_tries)
{
    struct sync_command_data   ipc_sync_cmd = { 0 };
    uint8_t ret;

    if(action == TOKEN_PIN_AUTHENTICATE){
        printf("acknowledge authentication PIN\n");
        /* int acknowledge of authentication, returning remaining tries */
        ipc_sync_cmd.data.u32[0] = remaining_tries;
        ipc_sync_cmd.data_size = 4;
    }
    else if (action == TOKEN_PIN_MODIFY){
        printf("acknowledge modification PIN\n");
    }
    else{
        goto err;
    }


    if ((pin_type == TOKEN_USER_PIN) || (pin_type == TOKEN_PET_PIN)) {
       ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_RESP;
    } else {
        goto err;
    }
    if(ack == TOKEN_ACK_VALID){
    	ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;
    } else{
    	ipc_sync_cmd.state = SYNC_FAILURE;
    }

    ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("unable to acknowledge!\n");
        while (1);
    }

    /* an invalid pin is considered as an error, we stop here, returning an error. */
    if (ack != TOKEN_ACK_VALID) {
        goto err;
    }
	return 0;
err:
	return -1;
}

int auth_token_request_pet_name(char *pet_name, unsigned int *pet_name_len)
{
    struct sync_command_data ipc_sync_cmd_data = { 0 };
    uint8_t ret;
    uint8_t id;
    logsize_t size = 0;
    uint32_t cmd_magic;
    uint32_t resp_magic;

    /*********************************************
     * Request PET name to pin task
     *********************************************/
    cmd_magic = MAGIC_CRYPTO_PIN_CMD;
    resp_magic = MAGIC_CRYPTO_PIN_RESP;

    ipc_sync_cmd_data.magic = cmd_magic;
    ipc_sync_cmd_data.state = SYNC_ASK_FOR_DATA;
    // TODO: set data_size please
    ipc_sync_cmd_data.data.req.sc_type = SC_PET_NAME;
    ipc_sync_cmd_data.data.req.sc_req = SC_REQ_MODIFY;

    ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_pin) failed! Exiting...\n");
        return 1;
    }

    /* Now wait for Acknowledge from pin */
    id = id_pin;
    size = sizeof(struct sync_command_data); /* max pin size: 32 */

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd_data);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }
    if (   (ipc_sync_cmd_data.magic == resp_magic)
            && (ipc_sync_cmd_data.state == SYNC_DONE)) {
        printf("received pet name from PIN: %s, size: %d\n",
                (char*)ipc_sync_cmd_data.data.u8,
                ipc_sync_cmd_data.data_size);
        if((*pet_name_len) < ipc_sync_cmd_data.data_size){
              printf("pet name len (%d) too long !\n", ipc_sync_cmd_data.data_size);
              goto err;
        }
        memcpy(pet_name, (void*)&(ipc_sync_cmd_data.data.u8), ipc_sync_cmd_data.data_size);
        *pet_name_len = ipc_sync_cmd_data.data_size;
        return 0;
    }

err:
    return -1;
}



int auth_token_request_pet_name_confirmation(const char *pet_name, unsigned int pet_name_len)
{
    /************* Send pet name to pin */
    struct sync_command_data ipc_sync_cmd = { 0 };
    logsize_t size = 0;
    uint8_t id = 0;
    uint8_t ret;

    ipc_sync_cmd.magic = MAGIC_CRYPTO_PIN_CMD;
    ipc_sync_cmd.state = SYNC_WAIT;
    ipc_sync_cmd.data.req.sc_type = SC_PET_NAME;
    ipc_sync_cmd.data.req.sc_req = SC_REQ_AUTHENTICATE;

    // FIXME: string length check to add
    if(pet_name_len > sizeof(ipc_sync_cmd.data.req.sc_petname)){
        printf("pet name length %d too long!\n", pet_name_len);
        goto err;
    }
    memcpy(ipc_sync_cmd.data.req.sc_petname, pet_name, pet_name_len);

    printf("requesting Pet name confirmation from PIN\n");

    ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_pin) failed! Exiting...\n");
        return 1;
    }

    printf("waiting for acknowledge from PIN for Pet name...\n");
    /* receiving user acknowledge for pet name */
    size = sizeof(struct sync_command);
    id = id_pin;
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }
    if ((ipc_sync_cmd.magic != MAGIC_CRYPTO_PIN_RESP) ||
        (ipc_sync_cmd.state != SYNC_ACKNOWLEDGE)) {
        printf("[AUTH Token] Pen name has not been acknowledged by the user\n");
        goto err;
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

    cryp_early_init(false, CRYP_MAP_VOLUNTARY, CRYP_CFG, &dma_in_desc, &dma_out_desc);

    tokenret = token_early_init(TOKEN_MAP_AUTO);
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

#ifdef CONFIG_APP_SMART_USE_BKUP_SRAM
    if(bsram_keybag_init()){
        goto err;
    }
#endif

    printf("set init as done\n");
    ret = sys_init(INIT_DONE);
    printf("sys_init returns %s !\n", strerror(ret));

    /*******************************************
     * let's synchronize with other tasks
     *******************************************/
    size = sizeof(struct sync_command);

    /* First, wait for pin to finish its init phase */
    id = id_pin;
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }
    if (   (ipc_sync_cmd.magic == MAGIC_TASK_STATE_CMD)
        && (ipc_sync_cmd.state == SYNC_READY)) {
        printf("pin has finished its init phase, acknowledge...\n");
    }

    ipc_sync_cmd.magic = MAGIC_TASK_STATE_RESP;
    ipc_sync_cmd.state = SYNC_ACKNOWLEDGE;

    size = sizeof(struct sync_command);
    ret = sys_ipc(IPC_SEND_SYNC, id_pin, size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_pin) failed! Exiting...\n");
        return 1;
    }

    /* Then Syncrhonize with crypto */
    size = sizeof(struct sync_command);

    printf("sending end_of_init synchronization to crypto\n");
    ipc_sync_cmd.magic = MAGIC_TASK_STATE_CMD;
    ipc_sync_cmd.state = SYNC_READY;

    ret = sys_ipc(IPC_SEND_SYNC, id_crypto, size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_SEND_SYNC, id_crypto) failed! Exiting...\n");
        return 1;
    }

    /* Now wait for Acknowledge from Crypto */
    id = id_crypto;

    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }

    if (   (ipc_sync_cmd.magic == MAGIC_TASK_STATE_RESP)
        && (ipc_sync_cmd.state == SYNC_ACKNOWLEDGE)) {
        printf("crypto has acknowledge end_of_init, continuing\n");
    }

    /*********************************************
     * Wait for crypto to ask for key injection
     *********************************************/

    /* First, wait for pin to finish its init phase */
    id = id_crypto;
    size = sizeof(struct sync_command);
    ret = sys_ipc(IPC_RECV_SYNC, &id, &size, (char*)&ipc_sync_cmd);
    if (ret != SYS_E_DONE) {
        printf("sys_ipc(IPC_RECV_SYNC) failed! Exiting...\n");
        return 1;
    }

    if (   (ipc_sync_cmd.magic == MAGIC_CRYPTO_INJECT_CMD)
        && (ipc_sync_cmd.state == SYNC_READY)) {
        printf("crypto is requesting key injection...\n");
    }

    /*********************************************
     * AUTH token communication, to get key from it
     *********************************************/
#ifdef CONFIG_APP_SMART_USE_BKUP_SRAM
    /* Map the Backup SRAM to get our keybags*/
    if(bsram_keybag_map()){
        goto err;
    }
#endif

    unsigned char CBC_ESSIV_key[32] = {0};
    unsigned char CBC_ESSIV_h_key[32] = {0};
    unsigned char sdpwd[16] = { 0 };

    /* Register smartcard removal handler */
    curr_token_channel.card.type = SMARTCARD_CONTACT;
    /* Register our callback */
    ADD_LOC_HANDLER(smartcard_removal_action)
    SC_register_user_handler_action(&(curr_token_channel.card), smartcard_removal_action);
    curr_token_channel.card.type = SMARTCARD_UNKNOWN;

    /* Token callbacks */
    cb_token_callbacks auth_token_callbacks = {
        .request_pin                   = auth_token_request_pin,
        .acknowledge_pin               = auth_token_acknowledge_pin,
        .request_pet_name              = auth_token_request_pet_name,
        .request_pet_name_confirmation = auth_token_request_pet_name_confirmation
    };
    /* Register our calbacks */
    ADD_LOC_HANDLER(auth_token_request_pin)
    ADD_LOC_HANDLER(auth_token_acknowledge_pin)
    ADD_LOC_HANDLER(auth_token_request_pet_name)
    ADD_LOC_HANDLER(auth_token_request_pet_name_confirmation)
    if(!tokenret && auth_token_exchanges(&curr_token_channel, &auth_token_callbacks, CBC_ESSIV_key, sizeof(CBC_ESSIV_key), CBC_ESSIV_h_key, sizeof(CBC_ESSIV_h_key), sdpwd, sizeof(sdpwd), NULL, 0))
    {
        goto err;
    }

#ifdef CONFIG_APP_SMART_USE_BKUP_SRAM
    if(bsram_keybag_unmap()){
        goto err;
    }
#endif

    /* Now that we have received our assets, we can lock the token.
     * We maintain the secure channel opened for a while, we only lock the
     * user PIN for now.
     */
    if(token_user_pin_lock(&curr_token_channel)){
        goto err;
    }

#if CONFIG_SMARTCARD_DEBUG
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
                        /* Is there a key schedule request ? */

                        if (ret == SYS_E_DONE) {
                            cryp_init_injector(CBC_ESSIV_key, KEY_256);

                            ipc_sync_cmd.magic = MAGIC_CRYPTO_INJECT_RESP;
                            ipc_sync_cmd.state = SYNC_DONE;

                            ret = sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command), (char*)&ipc_sync_cmd);
			    if(ret != SYS_E_DONE){
                                goto err;
			    }
                        }
                        break;
                    }
#endif
                case MAGIC_STORAGE_EJECTED:
                    {
                        printf("ejection event received\n");
                        sys_reset();
                        while (1);
                        break;
                    }

                case MAGIC_STORAGE_SCSI_BLOCK_NUM_RESP:
                    {
                        /* sending back size info to pin */
                        ret = sys_ipc(IPC_SEND_SYNC, id_pin, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);
   		        if(ret != SYS_E_DONE){
                            goto err;
			}
                        break;
                    }

                case MAGIC_REBOOT_REQUEST:
                    {
                        printf("Reset request!\n");
                        sys_reset();
                        break;
                    }
                case MAGIC_STORAGE_PASSWD:
                    {
                        /* First argument is the actual size of the password.
                         * Ask the token to give us the unlocking pass */
                        if(global_pin_len == 0){
                            goto err;
                        }
#if CONFIG_SMARTCARD_DEBUG
                        printf("SD password received:\n");
                        hexdump(sdpwd, sizeof(sdpwd));
#endif
                        ipc_sync_cmd_data.data.u32[0] = 16;
                        memcpy(ipc_sync_cmd_data.data.u8+sizeof(uint32_t), sdpwd, sizeof(sdpwd));
                        /* Indicate the actual size the the transmitted data */
                        ipc_sync_cmd_data.data_size=sizeof(sdpwd)+sizeof(uint32_t);
                        ret = sys_ipc(IPC_SEND_SYNC, id_crypto, sizeof(struct sync_command_data), (char*)&ipc_sync_cmd_data);
   		        if(ret != SYS_E_DONE){
                            goto err;
			}
                        break;

                    }

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
                /********* set user pin into smartcard *******/
                case MAGIC_SETTINGS_CMD:
                    {
                        if (   (ipc_sync_cmd_data.data.req.sc_type == SC_PET_PIN)
                            && (ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY)) {
                            /* set the new pet pin. The CRYPTO_AUTH_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a Pet Pin update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_PIN };
                            if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks, NULL, 0)){
                                printf("Unable to change pet pin !!!\n");
                                continue;
                            }
                            printf("New pet pin registered\n");
                        } else if (   (ipc_sync_cmd_data.data.req.sc_type == SC_USER_PIN)
                                   && (ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY)) {
                            /* set the new pet pin. The CRYPTO_AUTH_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a User Pin update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_USER_PIN };
                            if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks, NULL, 0)){
                                printf("Unable to change user pin !!!\n");
                                continue;
                            }
                            printf("New user pin registered\n");
                        } else if (   (ipc_sync_cmd_data.data.req.sc_type == SC_PET_NAME)
                                   && (ipc_sync_cmd_data.data.req.sc_req  == SC_REQ_MODIFY)) {
                            /* set the new pet pin. The CRYPTO_AUTH_CMD must have been passed and the channel being unlocked */
                            printf("PIN require a Pet Name update\n");

                            token_unlock_operations ops[] = { TOKEN_UNLOCK_PRESENT_USER_PIN, TOKEN_UNLOCK_CHANGE_PET_NAME };
                            if(auth_token_unlock_ops_exec(&curr_token_channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &auth_token_callbacks, NULL, 0)){
                                printf("Unable to change pet name !!!\n");
                                continue;
                            }
                            printf("New pet name registered\n");
                        } else {
                            printf("Invalid PIN command bag : sc_type = %d, sc_req = %d!\n",
                                    ipc_sync_cmd_data.data.req.sc_type,
                                    ipc_sync_cmd_data.data.req.sc_req);
                        }
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
                        printf("Unkown command received !\n");
                        goto err;
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
        sys_reset();
    }
    return 0;
}
