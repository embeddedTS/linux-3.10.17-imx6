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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/uaccess>
#include <linux/device.h>
#include <linux/spi/spi.h>

#include "linux_wlan_common.h"
#include "at_pwr_dev.h"

static uint32_t SPEED = MIN_SPEED;

struct spi_device *wilc_spi_dev;
EXPORT_SYMBOL(wilc_spi_dev);

static int wilc_bus_probe(struct spi_device *spi)
{
	PRINT_D(BUS_DBG, "spiModalias: %s\n", spi->modalias);
	PRINT_D(BUS_DBG, "spiMax-Speed: %d\n", spi->max_speed_hz);
	wilc_spi_dev = spi;

	up(&spi_probe_sync);
	return 0;
}

static int wilc_bus_remove(struct spi_device *spi)
{
	return 0;
}

struct spi_driver wilc_bus __refdata = {
	.driver = {
		.name = MODALIAS,
	},
	.probe =  wilc_bus_probe,
	.remove = __devexit_p(wilc_bus_remove),
};

void linux_spi_deinit(void *vp)
{
	spi_unregister_driver(&wilc_bus);
}

int linux_spi_init(void *vp)
{
	int ret = 1;
	static int called;

	if (called == 0) {
		called++;
		if (NULL == &wilc_bus) {
			PRINT_ER("wilc_bus address is NULL\n");
			return 0;	/* TODO */
		}

		ret = spi_register_driver(&wilc_bus);
	}

	(ret < 0) ? (ret = 0) : (ret = 1);

	return ret;
}

int linux_spi_write(uint8_t *b, uint32_t len)
{
	int ret;
	struct spi_message msg;

	if (len > 0 && NULL != b) {
		struct spi_transfer tr = {
			.tx_buf = b,
			.len = len,
			.speed_hz = SPEED,
			.delay_usecs = 0,
		};
		char *r_buffer = kzalloc(len, GFP_KERNEL);

		if (!r_buffer)
			return 0;	/* TODO: it should be return -ENOMEM */

		tr.rx_buf = r_buffer;
		PRINT_D(BUS_DBG, "Request writing %d bytes\n", len);

		spi_message_init(&msg);
		spi_message_add_tail(&tr, &msg);
		ret = spi_sync(wilc_spi_dev, &msg);
		if (ret < 0)
			PRINT_ER("SPI transaction failed\n");

		kfree(r_buffer);
	} else {
		PRINT_ER("can't write data due to NULL buffer or zero length\n");
		ret = -1;
	}

	(ret < 0) ? (ret = 0) : (ret = 1);

	return ret;
}

int linux_spi_read(u8 *rb, unsigned long rlen)
{
	int ret;

	if (rlen > 0) {
		char *t_buffer;
		struct spi_message msg;
		struct spi_transfer tr = {
			.rx_buf = rb,
			.len = rlen,
			.speed_hz = SPEED,
			.delay_usecs = 0,

		};
		t_buffer = kzalloc(rlen, GFP_KERNEL);

		if (!t_buffer)
			return 0; /* TODO: it should be return -ENOMEM */

		tr.tx_buf = t_buffer;

		spi_message_init(&msg);
		spi_message_add_tail(&tr, &msg);
		ret = spi_sync(wilc_spi_dev, &msg);
		if (ret < 0)
			PRINT_ER("SPI transaction failed\n");

		kfree(t_buffer);
	} else {
		PRINT_ER("can't read data due to zero length\n");
		ret = -1;
	}

	(ret < 0) ? (ret = 0) : (ret = 1);

	return ret;
}

int linux_spi_write_read(u8 *wb, u8 *rb, unsigned int rlen)
{
	int ret;

	if (rlen > 0) {
		struct spi_message msg;
		struct spi_transfer tr = {
			.rx_buf = rb,
			.tx_buf = wb,
			.len = rlen,
			.speed_hz = SPEED,
			.delay_usecs = 0,

		};

		spi_message_init(&msg);
		spi_message_add_tail(&tr, &msg);
		ret = spi_sync(wilc_spi_dev, &msg);
		if (ret < 0)
			PRINT_ER("SPI transaction failed\n");
	} else {
		PRINT_ER("can't read data due to zero length\n");
		ret = -1;
	}

	(ret < 0) ? (ret = 0) : (ret = 1);

	return ret;
}
