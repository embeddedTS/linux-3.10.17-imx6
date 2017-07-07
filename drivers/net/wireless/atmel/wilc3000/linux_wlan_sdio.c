/*
 * Atmel WILC 802.11 b/g/n driver
 *
 * Copyright (c) 2015 Atmel Corportation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/host.h>

#include "linux_wlan_sdio.h"
#include "linux_wlan_common.h"
#include "at_pwr_dev.h"

#define SDIO_MODALIAS "wilc_sdio"

struct wilc_wlan_os_context  g_linux_sdio_os_context;
struct sdio_func *local_sdio_func = NULL;
EXPORT_SYMBOL(local_sdio_func);

static isr_handler_t isr_handler;
extern int sdio_init(struct wilc_wlan_inp *inp);
extern int sdio_reset(void *pv);
void chip_wakeup(int source);
void chip_allow_sleep(int source);
extern void (*pf_chip_sleep_manually)(unsigned int , int );
extern int (*pf_get_num_conn_ifcs)(void);
extern void (*pf_host_wakeup_notify)(int);
extern void (*pf_host_sleep_notify)(int);
extern int (*pf_get_u8SuspendOnEvent_value)(void);

#define SDIO_VENDOR_ID_WILC 0x0296
#define SDIO_DEVICE_ID_WILC 0x5347

static const struct sdio_device_id wilc_sdio_ids[] = {
	{ SDIO_DEVICE(SDIO_VENDOR_ID_WILC, SDIO_DEVICE_ID_WILC) },

	{ }
};

#ifndef WILC_SDIO_IRQ_GPIO
enum sdio_host_lock {
	WILC_SDIO_HOST_NO_TAKEN = 0,
	WILC_SDIO_HOST_IRQ_TAKEN = 1,
	WILC_SDIO_HOST_DIS_TAKEN = 2,
};

static enum sdio_host_lock	sdio_intr_lock = WILC_SDIO_HOST_NO_TAKEN;
static wait_queue_head_t sdio_intr_waitqueue;
#endif /* WILC_SDIO_IRQ_GPIO */

static void wilc_sdio_interrupt(struct sdio_func *func)
{
#ifndef WILC_SDIO_IRQ_GPIO
	if (sdio_intr_lock == WILC_SDIO_HOST_DIS_TAKEN)
		return;
	sdio_intr_lock = WILC_SDIO_HOST_IRQ_TAKEN;

	sdio_release_host(func);
	if (NULL != isr_handler)
		isr_handler();
	sdio_claim_host(func);

	sdio_intr_lock = WILC_SDIO_HOST_NO_TAKEN;
	wake_up_interruptible(&sdio_intr_waitqueue);
#endif /* WILC_SDIO_IRQ_GPIO */
}

int linux_sdio_cmd52(struct sdio_cmd52_t *cmd)
{
	struct sdio_func *func = local_sdio_func;
	int ret;
	u8 data;

	sdio_claim_host(func);

	func->num = cmd->function;
	if (cmd->read_write) {
		if (cmd->raw) {
			sdio_writeb(func, cmd->data, cmd->address, &ret);
			data = sdio_readb(func, cmd->address, &ret);
			cmd->data = data;
		} else {
			sdio_writeb(func, cmd->data, cmd->address, &ret);
		}
	} else {
		data = sdio_readb(func, cmd->address, &ret);
		cmd->data = data;
	}

	sdio_release_host(func);

	if (ret < 0) {
		PRINT_ER("wilc_sdio_cmd52..failed, err(%d)\n", ret);
		return 0;
	}
	return 1;
}

int linux_sdio_cmd53(struct sdio_cmd53_t *cmd)
{
	struct sdio_func *func = local_sdio_func;
	int size, ret;

	sdio_claim_host(func);

	func->num = cmd->function;
	func->cur_blksize = cmd->block_size;
	if (cmd->block_mode)
		size = cmd->count * cmd->block_size;
	else
		size = cmd->count;

	if (cmd->read_write) {
		ret = sdio_memcpy_toio(func,
				       cmd->address,
				       (void *)cmd->buffer,
				       size);
	} else {
		ret = sdio_memcpy_fromio(func,
					 (void *)cmd->buffer,
					 cmd->address,
					 size);
	}

	sdio_release_host(func);

	if (ret < 0) {
		PRINT_ER("wilc_sdio_cmd53..failed, err(%d)\n", ret);
		return 0;
	}

	return 1;
}

static int linux_sdio_probe(struct sdio_func *func,
			    const struct sdio_device_id *id)
{
	PRINT_D(INIT_DBG, "probe function\n");

	local_sdio_func = func;

	up(&sdio_probe_sync);

	return 0;
}

static void linux_sdio_remove(struct sdio_func *func)
{
}

static int wilc_sdio_suspend(struct device *dev)
{
	printk("\n\n << SUSPEND >>\n\n");
	if((g_linux_sdio_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));

	chip_wakeup(0);

	if((g_linux_sdio_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_sdio_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));
		}
	}
	
	/*if there is no events , put the chip in low power mode */
	if(pf_get_u8SuspendOnEvent_value()== 0){
		/*BugID_5213*/
		/*Allow chip sleep, only if both interfaces are not connected*/
		if(!pf_get_num_conn_ifcs())
			pf_chip_sleep_manually(0xFFFFFFFF,0);
	}
	else{
		/*notify the chip that host will sleep*/
		pf_host_sleep_notify(0);
		chip_allow_sleep(0);
	}

	if((g_linux_sdio_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));

	/*reset SDIO to allow kerenl reintilaization at wake up*/
	sdio_reset(NULL);
	/*claim the host to prevent driver SDIO access before resume is called*/
	sdio_claim_host(local_sdio_func);
	return 0 ;
}

static int wilc_sdio_resume(struct device *dev)
{
	sdio_release_host(local_sdio_func);
	/*wake the chip to compelete the re-intialization*/
	chip_wakeup(0);
	printk("\n\n  <<RESUME>> \n\n");	
	/*Init SDIO block mode*/
	sdio_init(NULL);

	if((g_linux_sdio_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_sdio_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));
		}
	}

	/*if there is an event , notify the chip that the host is awake now*/
	if(pf_get_u8SuspendOnEvent_value()== 1)
		pf_host_wakeup_notify(0);

	if((g_linux_sdio_os_context.hif_critical_section) != NULL)
		mutex_lock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));

	chip_allow_sleep(0);

	if((g_linux_sdio_os_context.hif_critical_section)!= NULL){
		if (mutex_is_locked((struct mutex*)(g_linux_sdio_os_context.hif_critical_section))){
			mutex_unlock((struct mutex*)(g_linux_sdio_os_context.hif_critical_section));
		}
	}	
	
    return 0;

}

static const struct dev_pm_ops wilc_sdio_pm_ops = {	
     .suspend = wilc_sdio_suspend,    
     .resume    = wilc_sdio_resume,
    	};

struct sdio_driver wilc_bus = {
	.name		= SDIO_MODALIAS,
	.id_table	= wilc_sdio_ids,
	.probe		= linux_sdio_probe,
	.remove		= linux_sdio_remove,

    .drv      = {
                  .pm = &wilc_sdio_pm_ops,
               }
};

int enable_sdio_interrupt(isr_handler_t p_isr_handler)
{
	int ret = 0;
#ifndef WILC_SDIO_IRQ_GPIO
	sdio_intr_lock  = WILC_SDIO_HOST_NO_TAKEN;

	isr_handler = p_isr_handler;

	sdio_claim_host(local_sdio_func);
	ret = sdio_claim_irq(local_sdio_func, wilc_sdio_interrupt);
	sdio_release_host(local_sdio_func);

	if (ret < 0) {
		PRINT_ER("can't claim sdio_irq, err(%d)\n", ret);
		ret = -EIO;
	}
#endif /* WILC_SDIO_IRQ_GPIO */
	return ret;
}
EXPORT_SYMBOL(enable_sdio_interrupt);

void disable_sdio_interrupt(void)
{
#ifndef WILC_SDIO_IRQ_GPIO
	int ret;

	if (sdio_intr_lock  == WILC_SDIO_HOST_IRQ_TAKEN)
		wait_event_interruptible(sdio_intr_waitqueue,
				   sdio_intr_lock == WILC_SDIO_HOST_NO_TAKEN);
	sdio_intr_lock  = WILC_SDIO_HOST_DIS_TAKEN;

	sdio_claim_host(local_sdio_func);
	ret = sdio_release_irq(local_sdio_func);
	if (ret < 0)
		PRINT_ER("can't release sdio_irq, err(%d)\n", ret);

	sdio_release_host(local_sdio_func);
	sdio_intr_lock  = WILC_SDIO_HOST_NO_TAKEN;
#endif /* WILC_SDIO_IRQ_GPIO */
}
EXPORT_SYMBOL(disable_sdio_interrupt);

int linux_sdio_init(void *pv)
{
	PRINT_D(INIT_DBG, "SDIO speed: %d\n", 
		local_sdio_func->card->host->ios.clock);
#ifndef WILC_SDIO_IRQ_GPIO
	init_waitqueue_head(&sdio_intr_waitqueue);
#endif /* WILC_SDIO_IRQ_GPIO */
	memcpy(&g_linux_sdio_os_context,(struct wilc_wlan_os_context*) pv,sizeof(struct wilc_wlan_os_context));
	return 1;
}

void linux_sdio_deinit(void *pv)
{
	sdio_unregister_driver(&wilc_bus);
}

