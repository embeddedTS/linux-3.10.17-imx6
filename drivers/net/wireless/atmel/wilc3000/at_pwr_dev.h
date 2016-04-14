/*
 * Atmel WILC3000 802.11 b/g/n and Bluetooth Combo driver
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

#ifndef AT_PWR_DEV_H
#define AT_PWR_DEV_H


#define PWR_DEV_SRC_WIFI	0
#define PWR_DEV_SRC_BT		1
#define PWR_DEV_SRC_MAX		2

#include <linux/mutex.h>
#include "atl_error_support.h"
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/version.h>
#include "linux/string.h"
#include "linux_wlan_sdio.h"

#define HIF_SDIO		(0)
#define HIF_SPI			(1 << 0)
#define HIF_SDIO_GPIO_IRQ	(1 << 2)

#define N_INIT			0x00000001
#define N_ERR			0x00000002
#define N_TXQ			0x00000004
#define N_INTR			0x00000008
#define N_RXQ			0x00000010

enum BUS_ACQUIRE {
	ACQUIRE_ONLY		= 0,
	ACQUIRE_AND_WAKEUP	= 1,
};

enum BUS_RELEASE {
	RELEASE_ONLY		= 0,
	RELEASE_ALLOW_SLEEP	= 1,
};

struct wilc_wlan_os_context {
	void *os_private;
	void *hif_critical_section;
	uint32_t tx_buffer_size;
	void *txq_critical_section;
	void *txq_add_to_head_critical_section;
	void *txq_spin_lock;
	void *txq_wait_event;
#ifdef MEMORY_STATIC
	uint32_t rx_buffer_size;
#endif
	void *rxq_critical_section;
	void *rxq_wait_event;
	void *cfg_wait_event;
};

struct wilc_wlan_io_func {
	int io_type;
	int (*io_init)(void *);
	void (*io_deinit)(void *);
	union {
		struct {
			int (*sdio_cmd52)(struct sdio_cmd52_t *);
			int (*sdio_cmd53)(struct sdio_cmd53_t *);
		} sdio;
		struct {
			int (*spi_tx)(uint8_t *, uint32_t);
			int (*spi_rx)(uint8_t *, uint32_t);
			int (*spi_trx)(uint8_t *, uint8_t *, uint32_t);
		} spi;
	} u;
};

struct wilc_wlan_net_func {
	void (*rx_indicate)(uint8_t *, uint32_t, uint32_t);
	void (*rx_complete)(void);
};

struct wilc_wlan_indicate_func {
	void (*mac_indicate)(int);
};

struct wilc_wlan_inp {
	struct wilc_wlan_os_context os_context;
	struct wilc_wlan_io_func io_func;
	struct wilc_wlan_net_func net_func;
	struct wilc_wlan_indicate_func indicate_func;
};

struct wilc_hif_func {
	int (*hif_init)(struct wilc_wlan_inp *);
	int (*hif_deinit)(void *);
	int (*hif_read_reg)(uint32_t, uint32_t *);
	int (*hif_write_reg)(uint32_t, uint32_t);
	int (*hif_block_rx)(uint32_t, uint8_t *, uint32_t);
	int (*hif_block_tx)(uint32_t, uint8_t *, uint32_t);
	int (*hif_sync)(void);
	int (*hif_clear_int)(void);
	int (*hif_read_int)(uint32_t *);
	int (*hif_clear_int_ext)(uint32_t);
	int (*hif_read_size)(uint32_t *);
	int (*hif_block_tx_ext)(uint32_t, uint8_t *, uint32_t);
	int (*hif_block_rx_ext)(uint32_t, uint8_t *, uint32_t);
	int (*hif_sync_ext)(int);
};

/*TicketId883*/
#ifdef WILC_BT_COEXISTENCE
typedef int (*WILCpfChangeCoexMode)(u8);
#endif

extern struct wilc_hif_func hif_sdio;
extern struct wilc_hif_func hif_spi;


#ifdef WILC_SDIO
extern struct semaphore sdio_probe_sync;
#ifdef RESCAN_SDIO
extern struct mmc_host *mmc_host_backup[10];
extern void mmc_start_host(struct mmc_host *host);
extern void mmc_stop_host(struct mmc_host *host);
#endif /* RESCAN_SDIO */
#else
extern struct semaphore spi_probe_sync;
#endif /* WILC_SDIO */

/*
 * Initialize bluetooth power device
 */
int at_pwr_dev_init(void);

/*
 * Deinitialize bluetooth power device
 */
int at_pwr_dev_deinit(void);

/*
 * Register bus
 */
int at_pwr_register_bus(int source);

/*
 * Unregister bus
 */
int at_pwr_unregister_bus(int source);

/*
 * Power the chip up
 */
int at_pwr_power_up(int source);

/*
 * Power the chip down
 */
int at_pwr_power_down(int source);


#ifdef WILC_BT_COEXISTENCE
/*
 * Set pointer to function that changes coex mode
 * In case of WiFi is ON, BT when powering up needs to send a config WID to set coex mode ON
 */
void wilc_set_pf_change_coex_mode(WILCpfChangeCoexMode pfChangeCoexMode);
#endif

void chip_allow_sleep(int source);
void chip_wakeup(int source);
void set_pf_chip_sleep_manually(void (*chip_sleep_manually_address)(unsigned int , int ));


void set_pf_get_num_conn_ifcs(int (*get_num_conn_ifcs_address)(void));
void set_pf_host_wakeup_notify(void (*host_wakeup_notify_address)( int ));


void set_pf_host_sleep_notify(void (*host_sleep_notify_address)( int ));

void set_pf_get_u8SuspendOnEvent_value(int (*get_u8SuspendOnEvent_val)(void));
void set_pf_is_wilc3000_initalized(int (*is_wilc3000_initalized_address)(void ));

void acquire_bus(enum BUS_ACQUIRE acquire, int source);
void release_bus(enum BUS_RELEASE release, int source);
struct mutex *at_pwr_dev_get_bus_lock(void);
#endif /* AT_PWR_DEV_H */
