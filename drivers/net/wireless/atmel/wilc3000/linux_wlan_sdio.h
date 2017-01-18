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

#ifndef LINUX_WLAN_SDIO_H
#define LINUX_WLAN_SDIO_H

#include <linux/mmc/sdio_func.h>

#ifdef WILC_SDIO
extern struct sdio_func *local_sdio_func;
extern struct sdio_driver wilc_bus;
#endif /* WILC_SDIO */

struct sdio_cmd52_t {
	uint32_t read_write : 1;
	uint32_t function : 3;
	uint32_t raw : 1;
	uint32_t address : 17;
	uint32_t data : 8;
};

struct sdio_cmd53_t {
	uint32_t read_write : 1;
	uint32_t function : 3;
	uint32_t block_mode : 1;
	uint32_t increment : 1;
	uint32_t address : 17;
	uint32_t count : 9;
	uint8_t *buffer;
	uint32_t block_size;
};

typedef void (*isr_handler_t)(void);
int linux_sdio_init(void *);
void linux_sdio_deinit(void *);
int linux_sdio_cmd52(struct sdio_cmd52_t *cmd);
int linux_sdio_cmd53(struct sdio_cmd53_t *cmd);
int enable_sdio_interrupt(isr_handler_t isr_handler);
void disable_sdio_interrupt(void);

#endif /* LINUX_WLAN_SDIO_H */
