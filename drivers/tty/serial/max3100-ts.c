/*
 *
 *  Copyright (C) 2008 Christian Pellegrin <chripell@evolware.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *
 * Notes: the MAX3100 doesn't provide an interrupt on CTS so we have
 * to use polling for flow control. TX empty IRQ is unusable, since
 * writing conf clears FIFO buffer and we cannot have this interrupt
 * always asking us for attention.
 *
 * Example platform data:

 static struct plat_max3100 max3100_plat_data = {
 .loopback = 0,
 .crystal = 0,
 .poll_time = 100,
 };

 static struct spi_board_info spi_board_info[] = {
 {
 .modalias	= "max3100",
 .platform_data	= &max3100_plat_data,
 .irq		= IRQ_EINT12,
 .max_speed_hz	= 5*1000*1000,
 .chip_select	= 0,
 },
 };

 * The initial minor number is 209 in the low-density serial port:
 * mknod /dev/ttyMAX0 c 204 209
 */

 /*
    Modified from the original max3100.c to support the Technologic Systems
    MAX3100 extended UARTs.  This device puts 3 MAX3100-like uarts in one
    chip, but with only a single CS# line going to the chip, and a single
    IRQ pin.  This requires that all SPI transactions are preceded by a byte 
    to indicate which of the 3 uarts is being accessed.  On an interrupt,
    there's no way to tell which of the uarts generated it, so we have to
    check 'em all.
  */

#define MAX3100_MAJOR 204
#define MAX3100_MINOR 209
 /* 
    One max3100ts may contain up to 64 uarts.
    This driver supports only one max3100ts
  */
#define MAX_MAX3100 64

#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/serial_core.h>
#include <linux/serial.h>
#include <linux/spi/spi.h>
#include <linux/freezer.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>

#include <linux/serial_max3100.h>

#define MAX3100_C    (1<<14)
#define MAX3100_D    (0<<14)
#define MAX3100_W    (1<<15)
#define MAX3100_RX   (0<<15)

#define MAX3100_WC   (MAX3100_W  | MAX3100_C)
#define MAX3100_RC   (MAX3100_RX | MAX3100_C)
#define MAX3100_WD   (MAX3100_W  | MAX3100_D)
#define MAX3100_RD   (MAX3100_RX | MAX3100_D)
#define MAX3100_CMD  (3 << 14)

#define MAX3100_T    (1<<14)
#define MAX3100_R    (1<<15)

#define MAX3100_FEN  (1<<13)
#define MAX3100_SHDN (1<<12)
#define MAX3100_TM   (1<<11)
#define MAX3100_RM   (1<<10)
#define MAX3100_PM   (1<<9)
#define MAX3100_RAM  (1<<8)
#define MAX3100_IR   (1<<7)
#define MAX3100_ST   (1<<6)
#define MAX3100_PE   (1<<5)
#define MAX3100_L    (1<<4)
#define MAX3100_BAUD (0xf)

#define MAX3100_TE   (1<<10)
#define MAX3100_RAFE (1<<10)
#define MAX3100_RTS  (1<<9)
#define MAX3100_CTS  (1<<9)
#define MAX3100_PT   (1<<8)
#define MAX3100_DATA (0xff)

#define MAX3100_RT   (MAX3100_R | MAX3100_T)
#define MAX3100_RTC  (MAX3100_RT | MAX3100_CTS | MAX3100_RAFE)

/* the following simulate a status reg for ignore_status_mask */
#define MAX3100_STATUS_PE 1
#define MAX3100_STATUS_FE 2
#define MAX3100_STATUS_OE 4

#define MAX3100_CSI 0xc0

struct max3100ts_port {
	struct uart_port port;
	//struct spi_device *spi;

	int cts;		/* last CTS received for flow ctrl */
	int tx_empty;		/* last TX empty bit */

	spinlock_t conf_lock;	/* shared data */
	int conf_commit;	/* need to make changes */
	int conf;		/* configuration for the MAX31000
				 * (bits 0-7, bits 8-11 are irqs) */
	int rts_commit;		/* need to change rts */
	int rts;		/* rts status */
	int baud;		/* current baud rate */

	int parity;		/* keeps track if we should send parity */
#define MAX3100_PARITY_ON 1
#define MAX3100_PARITY_ODD 2
#define MAX3100_7BIT 4
	int rx_enabled;		/* if we should rx chars */

	//int irq;              /* irq assigned to the max3100 */

	int minor;		/* minor number */
	int crystal;		/* 1 if 3.6864Mhz crystal 0 for 1.8432 */
	int loopback;		/* 1 if we are in loopback mode */

	/* for handling irqs: need workqueue since we do spi_sync */
	struct workqueue_struct *workqueue;
	struct work_struct work;
	/* set to 1 to make the workhandler exit as soon as possible */
	int force_end_work;
	/* need to know we are suspending to avoid deadlock on workqueue */
	int suspending;

	/* hook for suspending MAX3100 via dedicated pin */
	void (*max3100_hw_suspend) (int suspend);

	/* poll time (in ms) for ctrl lines */
	int poll_time;
	/* and its timer */
	struct timer_list timer;

	int tx_fifo_size;
	int rx_fifo_size;

};

static struct s_max3100ts_common {
	struct max3100ts_port *max3100ts[MAX_MAX3100];	/* the chip */
	struct mutex portlock;	/* race on port usage */
	struct mutex max3100ts_lock;	/* race on probe */
	struct spi_device *spi;	/* all our uarts are on one spi */
	int irq;		/* single irq assigned to the max3100-ts */
	int uart_idx;		/* index into max3100ts[ ] */
	int uart_count;		/* number of uarts detected */
	int opencnt;		/* Reference count instances to know when to enable IRQ */
} max3100ts_common;

static int max3100_do_parity(struct max3100ts_port *s, u16 c)
{
	int parity;

	if (s->parity & MAX3100_PARITY_ODD)
		parity = 1;
	else
		parity = 0;

	if (s->parity & MAX3100_7BIT)
		c &= 0x7f;
	else
		c &= 0xff;

	parity = parity ^ (hweight8(c) & 1);
	return parity;
}

static int max3100_check_parity(struct max3100ts_port *s, u16 c)
{
	return max3100_do_parity(s, c) == ((c >> 8) & 1);
}

static void max3100_calc_parity(struct max3100ts_port *s, u16 * c)
{
	if (s->parity & MAX3100_7BIT)
		*c &= 0x7f;
	else
		*c &= 0xff;

	if (s->parity & MAX3100_PARITY_ON)
		*c |= max3100_do_parity(s, *c) << 8;
}

static void max3100_port_work(struct work_struct *w);

static void max3100_dowork(struct max3100ts_port *s)
{
	if(!work_pending(&s->work)){
		queue_work(s->workqueue, &s->work);
	}
}

static void max3100_timeout(unsigned long data)
{
	struct max3100ts_port *s = (struct max3100ts_port *)data;
	if (s->port.state) {
		max3100_dowork(s);
		mod_timer(&s->timer, jiffies + s->poll_time);
	}
}

static int max3100_sr(struct max3100ts_port *s, u16 tx, u16 * rx)
{
	struct spi_message message;
	u16 etx, erx;
	int status;
	struct spi_transfer tran = {
		.tx_buf = &etx,
		.rx_buf = &erx,
		.len = 2,
	};
	struct spi_transfer idx = {
		.rx_buf = NULL,
		.len = 1,
	};

	if (max3100ts_common.uart_idx != s->minor) {
		u8 cs = s->minor | MAX3100_CSI;
		idx.tx_buf = &cs;
		spi_message_init(&message);
		spi_message_add_tail(&idx, &message);
		status = spi_sync(max3100ts_common.spi, &message);
		if (status) {
			dev_warn(&max3100ts_common.spi->dev,
				 "error while calling spi_sync\n");
			return -EIO;
		}
		max3100ts_common.uart_idx = s->minor;
	}

	etx = cpu_to_be16(tx);

	spi_message_init(&message);
	spi_message_add_tail(&tran, &message);
	status = spi_sync(max3100ts_common.spi, &message);
	if (status) {
		dev_warn(&max3100ts_common.spi->dev,
			 "error while calling spi_sync\n");
		return -EIO;
	}
	*rx = be16_to_cpu(erx);
	s->tx_empty = (*rx & MAX3100_T) > 0;

	dev_dbg(&max3100ts_common.spi->dev, "%04x - %04x\n", tx, *rx);
	return 0;
}

static int max3100_handlerx(struct max3100ts_port *s, u16 rx)
{
	unsigned int ch, flg, status = 0;
	int ret = 0, cts;

	if (rx & MAX3100_R && s->rx_enabled) {
		dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

		ch = rx & (s->parity & MAX3100_7BIT ? 0x7f : 0xff);
		if (rx & MAX3100_RAFE) {
			s->port.icount.frame++;
			flg = TTY_FRAME;
			status |= MAX3100_STATUS_FE;
		} else {
			if (s->parity & MAX3100_PARITY_ON) {
				if (max3100_check_parity(s, rx)) {
					s->port.icount.rx++;
					flg = TTY_NORMAL;
				} else {
					s->port.icount.parity++;
					flg = TTY_PARITY;
					status |= MAX3100_STATUS_PE;
				}
			} else {
				s->port.icount.rx++;
				flg = TTY_NORMAL;
			}
		}
		uart_insert_char(&s->port, status, MAX3100_STATUS_OE, ch, flg);
		ret = 1;
	}

	cts = (rx & MAX3100_CTS) > 0;
	if (s->cts != cts) {
		s->cts = cts;
		uart_handle_cts_change(&s->port, cts ? TIOCM_CTS : 0);
	}

	return ret;
}

static void max3100_port_dowork(struct max3100ts_port *s)
{
	int rxchars, x;
	u16 tx, rx;
	int conf, cconf, rts, crts;
	struct circ_buf *xmit = &s->port.state->xmit;

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	rxchars = 0;
	do {
		spin_lock(&s->conf_lock);
		conf = s->conf;
		cconf = s->conf_commit;
		s->conf_commit = 0;
		rts = s->rts;
		crts = s->rts_commit;
		s->rts_commit = 0;
		spin_unlock(&s->conf_lock);

		if (cconf)
			max3100_sr(s, MAX3100_WC | conf, &rx);
		if (crts) {
			max3100_sr(s, MAX3100_WD | MAX3100_TE |
				   (s->rts ? MAX3100_RTS : 0), &rx);
			rxchars += max3100_handlerx(s, rx);
		}

		x = 0;
		if (s->port.x_char) {
			tx = s->port.x_char;
			x = 1;
		} else{
			if(!s->force_end_work){
				if (!uart_circ_empty(xmit) && !uart_tx_stopped(&s->port)) {
					tx = xmit->buf[xmit->tail];
					x = 2;
				}
			}
		}
		if (x) {	/* we have something to send, so send it! */
			max3100_calc_parity(s, &tx);
			tx |= MAX3100_WD | (s->rts ? MAX3100_RTS : 0);
			max3100_sr(s, tx, &rx);
			rxchars += max3100_handlerx(s, rx);

			if (rx & MAX3100_T) {	/* Tx buffer is/was empty, so tx was sent */
				if (x == 1) {
					s->port.icount.tx++;
					s->port.x_char = 0;
				} else if (x == 2) {
					xmit->tail = (xmit->tail + 1) &
					    (UART_XMIT_SIZE - 1);
					s->port.icount.tx++;
				}
			}
		} else {
			max3100_sr(s, MAX3100_RD, &rx);
			rxchars += max3100_handlerx(s, rx);
		}

		if (rxchars > 16) {
			tty_flip_buffer_push(&s->port.state->port);
			rxchars = 0;
		}

		if (uart_circ_chars_pending(xmit) < 4){
			if(s->port.state->port.tty)
				uart_write_wakeup(&s->port);
		}
	} while (!s->force_end_work &&
		 !freezing(current) &&
		 ((rx & MAX3100_R) ||
		  (!uart_circ_empty(xmit) && !uart_tx_stopped(&s->port))));
	if (rxchars > 0){
		tty_flip_buffer_push(&s->port.state->port);
	}
}

static void max3100_port_work(struct work_struct *w)
{
	struct max3100ts_port *s = container_of(w, struct max3100ts_port, work);
	mutex_lock(&max3100ts_common.portlock);
	max3100_port_dowork(s);
	mutex_unlock(&max3100ts_common.portlock);
}

static irqreturn_t max3100_thread_irq(int irqno, void *dev_id)
{
	int i;

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	for (i = 0; i < max3100ts_common.uart_count; i++) {
		struct max3100ts_port *s = max3100ts_common.max3100ts[i];
		mutex_lock(&max3100ts_common.portlock);
		max3100_port_dowork(s);
		mutex_unlock(&max3100ts_common.portlock);
	}

	return IRQ_HANDLED;
}

static void max3100_enable_ms(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	if (s->poll_time > 0)
		mod_timer(&s->timer, jiffies);
	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);
}

static void max3100_start_tx(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	max3100_dowork(s);
}

static void max3100_stop_rx(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	s->rx_enabled = 0;
	spin_lock(&s->conf_lock);
	s->conf &= ~MAX3100_RM;
	s->conf_commit = 1;
	spin_unlock(&s->conf_lock);
}

static unsigned int max3100_tx_empty(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	/* may not be truly up-to-date */
	max3100_dowork(s);
	return s->tx_empty;
}

static unsigned int max3100_get_mctrl(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	/* always assert DCD and DSR since these lines are not wired */
	return (s->cts ? TIOCM_CTS : 0) | TIOCM_DSR | TIOCM_CAR;
}

static void max3100_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);
	int rts;

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	rts = (mctrl & TIOCM_RTS) > 0;

	spin_lock(&s->conf_lock);
	if (s->rts != rts) {
		s->rts = rts;
		s->rts_commit = 1;
	}
	spin_unlock(&s->conf_lock);
}

static void
max3100_set_termios(struct uart_port *port, struct ktermios *termios,
		    struct ktermios *old)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);
	int baud = 0;
	int i;
	unsigned cflag;
	u32 param_new, param_mask, parity = 0;

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	cflag = termios->c_cflag;
	param_new = 0;
	param_mask = 0;

	baud = tty_termios_baud_rate(termios);
	param_new = s->conf & MAX3100_BAUD;
	switch (baud) {
	case 300:
		if (s->crystal)
			baud = s->baud;
		else
			param_new = 15;
		break;
	case 600:
		param_new = 14 + s->crystal;
		break;
	case 1200:
		param_new = 13 + s->crystal;
		break;
	case 2400:
		param_new = 12 + s->crystal;
		break;
	case 4800:
		param_new = 11 + s->crystal;
		break;
	case 9600:
		param_new = 10 + s->crystal;
		break;
	case 19200:
		param_new = 9 + s->crystal;
		break;
	case 38400:
		param_new = 8 + s->crystal;
		break;
	case 57600:
		param_new = 1 + s->crystal;
		break;
	case 115200:
		param_new = 0 + s->crystal;
		break;
	case 230400:
		if (s->crystal)
			param_new = 0;
		else
			baud = s->baud;
		break;
	default:
		baud = s->baud;
	}
	tty_termios_encode_baud_rate(termios, baud, baud);
	s->baud = baud;
	param_mask |= MAX3100_BAUD;

	if ((cflag & CSIZE) == CS8) {
		param_new &= ~MAX3100_L;
		parity &= ~MAX3100_7BIT;
	} else {
		param_new |= MAX3100_L;
		parity |= MAX3100_7BIT;
		cflag = (cflag & ~CSIZE) | CS7;
	}
	param_mask |= MAX3100_L;

	if (cflag & CSTOPB)
		param_new |= MAX3100_ST;
	else
		param_new &= ~MAX3100_ST;
	param_mask |= MAX3100_ST;

	if (cflag & PARENB) {
		param_new |= MAX3100_PE;
		parity |= MAX3100_PARITY_ON;
	} else {
		param_new &= ~MAX3100_PE;
		parity &= ~MAX3100_PARITY_ON;
	}
	param_mask |= MAX3100_PE;

	if (cflag & PARODD)
		parity |= MAX3100_PARITY_ODD;
	else
		parity &= ~MAX3100_PARITY_ODD;

	/* mask termios capabilities we don't support */
	cflag &= ~CMSPAR;
	termios->c_cflag = cflag;

	s->port.ignore_status_mask = 0;
	if (termios->c_iflag & IGNPAR)
		s->port.ignore_status_mask |=
		    MAX3100_STATUS_PE | MAX3100_STATUS_FE | MAX3100_STATUS_OE;

	/* we are sending char from a workqueue so enable */
	s->port.state->port.low_latency = 1;

	if (s->poll_time > 0)
		del_timer_sync(&s->timer);

	uart_update_timeout(port, termios->c_cflag, baud);

	spin_lock(&s->conf_lock);
	s->conf = (s->conf & ~param_mask) | (param_new & param_mask);
	s->conf_commit = 1;
	s->parity = parity;
	spin_unlock(&s->conf_lock);

	for (i = 0; i < max3100ts_common.uart_count; i++) {
		struct max3100ts_port *s = max3100ts_common.max3100ts[i];
		max3100_port_dowork(s);
	}

	if (UART_ENABLE_MS(&s->port, termios->c_cflag))
		max3100_enable_ms(&s->port);
}

static void max3100_shutdown(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	max3100ts_common.opencnt--;

	if(max3100ts_common.opencnt == 0) {
		free_irq(max3100ts_common.spi->irq, &max3100ts_common);
	}

	if (s->suspending)
		return;

	/* Make sure any dowork from the irq thread are finished */
	s->force_end_work = 1;
	mutex_lock(&max3100ts_common.portlock);
	mutex_unlock(&max3100ts_common.portlock);

	if (s->poll_time > 0)
		del_timer_sync(&s->timer);

	if (s->workqueue) {
		flush_workqueue(s->workqueue);
		destroy_workqueue(s->workqueue);
		s->workqueue = NULL;
	}

	/* set shutdown mode to save power */
	if (s->max3100_hw_suspend)
		s->max3100_hw_suspend(1);
	else {
		u16 tx, rx;

		tx = MAX3100_WC | MAX3100_SHDN;
		mutex_lock(&max3100ts_common.portlock);
		max3100_sr(s, tx, &rx);
		mutex_unlock(&max3100ts_common.portlock);
	}
}

static int max3100_startup(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);
	char b[12];

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	s->conf = MAX3100_RM | MAX3100_TM;
	s->baud = s->crystal ? 230400 : 115200;
	s->rx_enabled = 1;

	if (s->suspending)
		return 0;

	s->force_end_work = 0;
	s->parity = 0;
	s->rts = 0;

	sprintf(b, "max3100-%d", s->minor);
	s->workqueue = create_singlethread_workqueue(b);
	if (!s->workqueue) {
		dev_warn(&max3100ts_common.spi->dev,
			 "cannot create workqueue\n");
		return -EBUSY;
	}
	INIT_WORK(&s->work, max3100_port_work);

	if (s->loopback) {
		u16 tx, rx;
		tx = 0x4001;
		max3100_sr(s, tx, &rx);
	}

	if (s->max3100_hw_suspend)
		s->max3100_hw_suspend(0);
	s->conf_commit = 1;

	/* wait for clock to settle */
	if (s->port.line == 0)
		msleep(50);

	max3100_enable_ms(&s->port);

	max3100ts_common.opencnt++;
	if(max3100ts_common.opencnt == 1){
		int ret;
		ret = request_threaded_irq(max3100ts_common.spi->irq,
				  NULL,
				  max3100_thread_irq,
				  IRQF_TRIGGER_LOW | IRQF_ONESHOT,
				  "max3100-ts",
				  &max3100ts_common);
		if (ret) {
			dev_warn(&max3100ts_common.spi->dev, "cannot allocate irq %d\n", max3100ts_common.spi->irq);
			return ret;
		}
	}

	return 0;
}

static const char *max3100_type(struct uart_port *port)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	return s->port.type == PORT_MAX3100 ? "MAX3100" : NULL;
}

static void max3100_release_port(struct uart_port *port)
{
	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);
}

static void max3100_config_port(struct uart_port *port, int flags)
{
	struct max3100ts_port *s = container_of(port,
						struct max3100ts_port,
						port);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	if (flags & UART_CONFIG_TYPE)
		s->port.type = PORT_MAX3100;
}

static int max3100_verify_port(struct uart_port *port,
			       struct serial_struct *ser)
{
	int ret = -EINVAL;

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	if (ser->type == PORT_UNKNOWN || ser->type == PORT_MAX3100)
		ret = 0;
	return ret;
}

static void max3100_stop_tx(struct uart_port *port)
{
	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);
}

static int max3100_request_port(struct uart_port *port)
{
	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);
	return 0;
}

static void max3100_break_ctl(struct uart_port *port, int break_state)
{
	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);
}

static struct uart_ops max3100_ops = {
	.tx_empty = max3100_tx_empty,
	.set_mctrl = max3100_set_mctrl,
	.get_mctrl = max3100_get_mctrl,
	.stop_tx = max3100_stop_tx,
	.start_tx = max3100_start_tx,
	.stop_rx = max3100_stop_rx,
	.enable_ms = max3100_enable_ms,
	.break_ctl = max3100_break_ctl,
	.startup = max3100_startup,
	.shutdown = max3100_shutdown,
	.set_termios = max3100_set_termios,
	.type = max3100_type,
	.release_port = max3100_release_port,
	.request_port = max3100_request_port,
	.config_port = max3100_config_port,
	.verify_port = max3100_verify_port,
};

static struct uart_driver max3100_uart_driver = {
	.owner = THIS_MODULE,
	.driver_name = "ttyMAX",
	.dev_name = "ttyMAX",
	.major = MAX3100_MAJOR,
	.minor = MAX3100_MINOR,
	.nr = MAX_MAX3100,
};

static int uart_driver_registered;

#ifdef CONFIG_OF
static const struct of_device_id max3100_dt_ids[] = {
	{.compatible = "max3100-ts"},
	{}
};

MODULE_DEVICE_TABLE(of, max3100_dt_ids);

static const struct plat_max3100 *max3100_probe_dt(struct device *dev)
{
	struct plat_max3100 *pdata;
	struct device_node *node = dev->of_node;
	const struct of_device_id *match;

	if (!node) {
		dev_err(dev, "Device does not have associated DT data\n");
		return ERR_PTR(-EINVAL);
	}

	match = of_match_device(max3100_dt_ids, dev);
	if (!match) {
		dev_err(dev, "Unknown device model\n");
		return ERR_PTR(-EINVAL);
	}

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	// Force MAX310 into loopback
	of_property_read_u32(node, "loopback", &pdata->loopback);
	// Crystal <1 = 3.6864MHz> <0 = 1.8432MHz>
	of_property_read_u32(node, "crystal", &pdata->crystal);
	// Poll time in ms, 0 disables CTS, 100 typical
	of_property_read_u32(node, "poll-time", &pdata->poll_time);
	// Size of the Tx FIFO, in bytes
	of_property_read_u32(node, "tx-fifo-size", &pdata->tx_fifo_size);
	// Size of the Rx FIFO, in bytes
	of_property_read_u32(node, "rx-fifo-size", &pdata->rx_fifo_size);
	return pdata;
}

#else

static const struct plat_max3100 *max3100_probe_dt(struct device *dev)
{
	dev_err(dev, "no platform data defined\n");
	return ERR_PTR(-EINVAL);
}

#endif

static int max3100_probe(struct spi_device *spi)
{
	int i, retval;
	const struct plat_max3100 *pdata;
	u16 tx, rx;

	mutex_init(&max3100ts_common.max3100ts_lock);
	mutex_init(&max3100ts_common.portlock);

	mutex_lock(&max3100ts_common.max3100ts_lock);

	if (!uart_driver_registered) {
		uart_driver_registered = 1;
		retval = uart_register_driver(&max3100_uart_driver);
		if (retval) {
			printk(KERN_ERR
			       "Couldn't register max3100 uart driver\n");
			mutex_unlock(&max3100ts_common.max3100ts_lock);
			return retval;
		}
	}

	pdata = max3100_probe_dt(&spi->dev);
	if (IS_ERR(pdata)) {
		mutex_unlock(&max3100ts_common.max3100ts_lock);
		return PTR_ERR(pdata);
	}

	max3100ts_common.spi = spi;
	max3100ts_common.irq = spi->irq;
	max3100ts_common.uart_idx = -1;
	max3100ts_common.uart_count = 0;

	for (i = 0; i < MAX_MAX3100; i++) {
		max3100ts_common.max3100ts[i] =
		    kzalloc(sizeof(struct max3100ts_port), GFP_KERNEL);
		if (!max3100ts_common.max3100ts[i]) {
			dev_warn(&spi->dev,
				 "kmalloc for max3100 structure %d failed!\n",
				 i);
			mutex_unlock(&max3100ts_common.max3100ts_lock);
			return -ENOMEM;
		}

		spin_lock_init(&max3100ts_common.max3100ts[i]->conf_lock);
		spi_set_drvdata(spi, max3100ts_common.max3100ts[i]);

		max3100ts_common.max3100ts[i]->minor = i;

		tx = MAX3100_WC | MAX3100_SHDN | 5;
		max3100_sr(max3100ts_common.max3100ts[i], tx, &rx);
		tx = MAX3100_RC;
		rx = 0;
		max3100_sr(max3100ts_common.max3100ts[i], tx, &rx);
		if ((rx & MAX3100_BAUD) != 5) {
			kfree(max3100ts_common.max3100ts[i]);
			max3100ts_common.max3100ts[i] = NULL;
			break;
		} else
			max3100ts_common.uart_count++;

		max3100ts_common.max3100ts[i]->crystal = pdata->crystal;
		max3100ts_common.max3100ts[i]->loopback = pdata->loopback;
		max3100ts_common.max3100ts[i]->poll_time =
		    pdata->poll_time * HZ / 1000;
		if (pdata->poll_time > 0
		    && max3100ts_common.max3100ts[i]->poll_time == 0)
			max3100ts_common.max3100ts[i]->poll_time = 1;
		max3100ts_common.max3100ts[i]->max3100_hw_suspend =
		    pdata->max3100_hw_suspend;
		init_timer(&max3100ts_common.max3100ts[i]->timer);
		max3100ts_common.max3100ts[i]->timer.function = max3100_timeout;
		max3100ts_common.max3100ts[i]->timer.data =
		    (unsigned long)max3100ts_common.max3100ts[i];

		dev_dbg(&spi->dev, "%s: adding port %d\n", __func__, i);
		max3100ts_common.max3100ts[i]->port.irq = max3100ts_common.irq;
		max3100ts_common.max3100ts[i]->port.uartclk =
		    max3100ts_common.max3100ts[i]->crystal ? 3686400 : 1843200;
		max3100ts_common.max3100ts[i]->port.fifosize = 16;
		max3100ts_common.max3100ts[i]->port.ops = &max3100_ops;
		max3100ts_common.max3100ts[i]->port.flags =
		    UPF_SKIP_TEST | UPF_BOOT_AUTOCONF;
		max3100ts_common.max3100ts[i]->port.line = i;
		max3100ts_common.max3100ts[i]->port.type = PORT_MAX3100;
		max3100ts_common.max3100ts[i]->port.dev = &spi->dev;

		retval =
		    uart_add_one_port(&max3100_uart_driver,
				      &max3100ts_common.max3100ts[i]->port);
		if (retval < 0)
			dev_warn(&spi->dev,
				 "uart_add_one_port failed for line %d with error %d\n",
				 i, retval);
		tx = MAX3100_WC | MAX3100_SHDN;
		max3100_sr(max3100ts_common.max3100ts[i], tx, &rx);
	}

	mutex_unlock(&max3100ts_common.max3100ts_lock);

	dev_info(&spi->dev, "Detected %d uarts\n", max3100ts_common.uart_count);
	return 0;
}

static int max3100_remove(struct spi_device *spi)
{
	int i;

	mutex_lock(&max3100ts_common.max3100ts_lock);

	/* find out the index for the chip we are removing */
	for (i = MAX_MAX3100 - 1; i >= 0; i--)
		if (max3100ts_common.max3100ts[i]) {

			dev_dbg(&spi->dev, "%s: removing port %d\n", __func__,
				i);
			uart_remove_one_port(&max3100_uart_driver,
					     &max3100ts_common.max3100ts[i]->
					     port);

			kfree(max3100ts_common.max3100ts[i]);
			max3100ts_common.max3100ts[i] = NULL;
		}

	if (max3100ts_common.irq) {
		free_irq(max3100ts_common.irq, &max3100ts_common);
		max3100ts_common.irq = 0;
	}

	pr_debug("removing max3100 driver\n");
	uart_unregister_driver(&max3100_uart_driver);

	mutex_unlock(&max3100ts_common.max3100ts_lock);
	return 0;
}

#ifdef CONFIG_PM_SLEEP

static int max3100_suspend(struct device *dev)
{
	struct max3100ts_port *s = dev_get_drvdata(dev);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	disable_irq(max3100ts_common.irq);

	s->suspending = 1;
	uart_suspend_port(&max3100_uart_driver, &s->port);

	if (s->max3100_hw_suspend)
		s->max3100_hw_suspend(1);
	else {
		/* no HW suspend, so do SW one */
		u16 tx, rx;
		tx = MAX3100_WC | MAX3100_SHDN;
		mutex_lock(&max3100ts_common.portlock);
		max3100_sr(s, tx, &rx);
		mutex_unlock(&max3100ts_common.portlock);
	}
	return 0;
}

static int max3100_resume(struct device *dev)
{
	struct max3100ts_port *s = dev_get_drvdata(dev);

	dev_dbg(&max3100ts_common.spi->dev, "%s\n", __func__);

	if (s->max3100_hw_suspend)
		s->max3100_hw_suspend(0);
	uart_resume_port(&max3100_uart_driver, &s->port);
	s->suspending = 0;

	enable_irq(max3100ts_common.irq);

	s->conf_commit = 1;
	if (s->workqueue)
		max3100_dowork(s);

	return 0;
}

static SIMPLE_DEV_PM_OPS(max3100_pm_ops, max3100_suspend, max3100_resume);
#define MAX3100_PM_OPS (&max3100_pm_ops)

#else
#define MAX3100_PM_OPS NULL
#endif

static struct spi_driver max3100_driver = {
	.driver = {
		   .name = "max3100-ts",
		   .owner = THIS_MODULE,
		   .pm = MAX3100_PM_OPS,
		   },
	.probe = max3100_probe,
	.remove = max3100_remove,
};

module_spi_driver(max3100_driver);

MODULE_DESCRIPTION("MAX3100 driver");
MODULE_AUTHOR("Christian Pellegrin <chripell@evolware.org>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("spi:max3100");