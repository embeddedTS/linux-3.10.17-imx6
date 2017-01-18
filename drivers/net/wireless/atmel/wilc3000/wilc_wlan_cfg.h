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

#ifndef WILC_WLAN_CFG_H
#define WILC_WLAN_CFG_H
#include "wilc_wlan.h"

struct wilc_cfg_byte_t {
	uint16_t id;
	uint16_t val;
};

struct wilc_cfg_hword_t {
	uint16_t id;
	uint16_t val;
};

struct wilc_cfg_word_t {
	uint32_t id;
	uint32_t val;
};

struct wilc_cfg_str_t {
	uint32_t id;
	uint8_t *str;
};

extern struct wilc_cfg_func mac_cfg;

/*ATWILCSW-403*/
typedef struct {
	uint32_t id;
	uint8_t *bin;
} wilc_cfg_bin_t;

#endif
