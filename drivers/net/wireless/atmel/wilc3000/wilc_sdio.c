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

#include "at_pwr_dev.h"
#include "wilc_wlan_if.h"
#include "wilc_wlan.h"


#define WILC_SDIO_BLOCK_SIZE 512

struct wilc_sdio {
	void *os_context;
	uint32_t block_size;
	int (*sdio_cmd52)(struct sdio_cmd52_t *);
	int (*sdio_cmd53)(struct sdio_cmd53_t *);
	int nint;
	/* Max num interrupts allowed in registers 0xf7, 0xf8 */
	#define MAX_NUN_INT_THRPT_ENH2 (5)
	int has_thrpt_enh3;
};

static struct wilc_sdio g_sdio;

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_write_reg(uint32_t addr, uint32_t data);
static int sdio_read_reg(uint32_t addr, uint32_t *data);
#endif /* WILC_SDIO_IRQ_GPIO */

static int sdio_set_func0_csa_address(uint32_t adr)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0x10c;
	cmd.data = (uint8_t)adr;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x10c data\n");
		goto _fail_;
	}

	cmd.address = 0x10d;
	cmd.data = (uint8_t)(adr >> 8);
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x10d data\n");
		goto _fail_;
	}

	cmd.address = 0x10e;
	cmd.data = (uint8_t)(adr >> 16);
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x10e data\n");
		goto _fail_;
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_set_func0_csa_address_byte0(uint32_t adr)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0x10c;
	cmd.data = (uint8_t)adr;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x10c data\n");
		goto _fail_;
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_set_func0_block_size(uint32_t block_size)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0x10;
	cmd.data = (uint8_t)block_size;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x10 data\n");
		goto _fail_;
	}

	cmd.address = 0x11;
	cmd.data = (uint8_t)(block_size >> 8);
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x11 data\n");
		goto _fail_;
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_set_func1_block_size(uint32_t block_size)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0x110;
	cmd.data = (uint8_t)block_size;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x110 data\n");
		goto _fail_;
	}
	cmd.address = 0x111;
	cmd.data = (uint8_t)(block_size >> 8);
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Failed cmd52, set 0x111 data\n");
		goto _fail_;
	}

	return 1;
_fail_:
	return 0;
}

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_clear_int(void)
{
	uint32_t reg;

	if (!sdio_read_reg(WILC_HOST_RX_CTRL_0, &reg)) {
		PRINT_ER("Failed read reg %08x\n", WILC_HOST_RX_CTRL_0);
		return 0;
	}

	reg &= ~0x1;
	sdio_write_reg(WILC_HOST_RX_CTRL_0, reg);

	return 1;
}
#else
static int sdio_clear_int(void)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 0;
	cmd.function = 1;
	cmd.raw = 0;
	cmd.address = 0x4;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);

	return cmd.data;
}
#endif /* WILC_SDIO_IRQ_GPIO */

uint32_t sdio_xfer_cnt(void)
{
	uint32_t cnt = 0;
	struct sdio_cmd52_t cmd;

	cmd.read_write = 0;
	cmd.function = 1;
	cmd.raw = 0;
	cmd.address = 0x1C;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	cnt = cmd.data;

	cmd.read_write = 0;
	cmd.function = 1;
	cmd.raw = 0;
	cmd.address = 0x1D;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	cnt |= (cmd.data << 8);

	cmd.read_write = 0;
	cmd.function = 1;
	cmd.raw = 0;
	cmd.address = 0x1E;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	cnt |= (cmd.data << 16);

	return cnt;
}

int sdio_check_bs(void)
{
	struct sdio_cmd52_t cmd;

	cmd.read_write = 0;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0xc;
	cmd.data = 0;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Fail cmd 52, get BS register\n");
		goto _fail_;
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_write_reg(uint32_t addr, uint32_t data)
{
#ifdef BIG_ENDIAN
	data = BYTE_SWAP(data);
#endif
	if ((addr >= 0xf0) && (addr <= 0xff)) {
		struct sdio_cmd52_t cmd;

		cmd.read_write = 1;
		cmd.function = 0;
		cmd.raw = 0;
		cmd.address = addr;
		cmd.data = data;
		if (!g_sdio.sdio_cmd52(&cmd)) {
			PRINT_ER("Failed cmd 52, write reg %08x\n", addr);
			goto _fail_;
		}
	} else {
		struct sdio_cmd53_t cmd;

		/*
		 * set the AHB address
		 */
		if (!sdio_set_func0_csa_address(addr))
			goto _fail_;

		cmd.read_write = 1;
		cmd.function = 0;
		cmd.address = 0x10f;
		cmd.block_mode = 0;
		cmd.increment = 1;
		cmd.count = 4;
		cmd.buffer = (uint8_t *)&data;
		cmd.block_size = g_sdio.block_size;

		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53, write reg %08x\n", addr);
			goto _fail_;
		}
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_write(uint32_t addr, uint8_t *buf, uint32_t size)
{
	uint32_t block_size = g_sdio.block_size;
	struct sdio_cmd53_t cmd;
	int nblk, nleft;

	cmd.read_write = 1;
	if (addr > 0) {
		/*
		 * has to be word aligned...
		 */
		if (size & 0x3) {
			size += 4;
			size &= ~0x3;
		}

		/*
		 * func 0 access
		 */
		cmd.function = 0;
		cmd.address = 0x10f;
	} else {
		/*
		 * has to be word aligned...
		 */
		if (size & 0x3) {
			size += 4;
			size &= ~0x3;
		}

		/*
		 * func 1 access
		 */
		cmd.function = 1;
		cmd.address = 0;
	}

	nblk = size / block_size;
	nleft = size % block_size;

	if (nblk > 0) {
		cmd.block_mode = 1;
		cmd.increment = 1;
		cmd.count = nblk;
		cmd.buffer = buf;
		cmd.block_size = block_size;
		if (addr > 0) {
			if (!sdio_set_func0_csa_address(addr))
				goto _fail_;
		}
		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53 [%x], block send\n", addr);
			goto _fail_;
		}
		if (addr > 0)
			addr += nblk * block_size;

		buf += nblk * block_size;
	}

	if (nleft > 0) {
		cmd.block_mode = 0;
		cmd.increment = 1;
		cmd.count = nleft;
		cmd.buffer = buf;

		cmd.block_size = block_size;

		if (addr > 0) {
			if (!sdio_set_func0_csa_address(addr))
				goto _fail_;
		}
		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53 [%x], bytes send\n", addr);
			goto _fail_;
		}
	}

	return 1;
_fail_:
	return 0;
}

static int sdio_read_reg(uint32_t addr, uint32_t *data)
{
	if ((addr >= 0xf0) && (addr <= 0xff)) {
		struct sdio_cmd52_t cmd;

		cmd.read_write = 0;
		cmd.function = 0;
		cmd.raw = 0;
		cmd.address = addr;
		if (!g_sdio.sdio_cmd52(&cmd)) {
			PRINT_ER("Failed cmd 52, read reg %08x\n", addr);
			goto _fail_;
		}
		*data = cmd.data;
	} else {
		struct sdio_cmd53_t cmd;

		if (!sdio_set_func0_csa_address(addr))
			goto _fail_;

		cmd.read_write = 0;
		cmd.function = 0;
		cmd.address = 0x10f;
		cmd.block_mode = 0;
		cmd.increment = 1;
		cmd.count = 4;
		cmd.buffer = (uint8_t *)data;

		cmd.block_size = g_sdio.block_size;

		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53, read reg %08x\n", addr);
			goto _fail_;
		}
	}

#ifdef BIG_ENDIAN
	*data = BYTE_SWAP(*data);
#endif
	return 1;
_fail_:
	return 0;
}

static int sdio_read(uint32_t addr, uint8_t *buf, uint32_t size)
{
	uint32_t block_size = g_sdio.block_size;
	struct sdio_cmd53_t cmd;
	int nblk, nleft;

	cmd.read_write = 0;
	if (addr > 0) {
		/*
		 * has to be word aligned...
		 */
		if (size & 0x3) {
			size += 4;
			size &= ~0x3;
		}

		/*
		 * func 0 access
		 */
		cmd.function = 0;
		cmd.address = 0x10f;
	} else {
		/*
		 * has to be word aligned...
		 */
		if (size & 0x3) {
			size += 4;
			size &= ~0x3;
		}

		/*
		 * func 1 access
		 */
		cmd.function = 1;
		cmd.address = 0;
	}

	nblk = size / block_size;
	nleft = size % block_size;

	if (nblk > 0) {
		cmd.block_mode = 1;
		cmd.increment = 1;
		cmd.count = nblk;
		cmd.buffer = buf;
		cmd.block_size = block_size;
		if (addr > 0) {
			if (!sdio_set_func0_csa_address(addr))
				goto _fail_;
		}
		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53 [%x], block read\n", addr);
			goto _fail_;
		}
		if (addr > 0)
			addr += nblk * block_size;

		buf += nblk * block_size;
	}

	if (nleft > 0) {
		cmd.block_mode = 0;
		cmd.increment = 1;
		cmd.count = nleft;
		cmd.buffer = buf;

		cmd.block_size = block_size;

		if (addr > 0) {
			if (!sdio_set_func0_csa_address(addr))
				goto _fail_;
		}
		if (!g_sdio.sdio_cmd53(&cmd)) {
			PRINT_ER("Failed cmd53 [%x], bytes read\n", addr);
			goto _fail_;
		}
	}

	return 1;
_fail_:
	return 0;
}

int sdio_deinit(void *pv)
{

	struct sdio_cmd52_t cmd;

	PRINT_INFO(BUS_DBG, "De Init SDIO\n");
	/*
	 * func 1 interrupt enable
	 */
	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 1;
	cmd.address = 0x6;
	cmd.data = 0x8;
	if (!g_sdio.sdio_cmd52(&cmd))
		PRINT_ER("Fail cmd 52, reset cmd\n");
	return 1;
}

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_sync(void)
{
	uint32_t reg;
	int ret;

	/*
	 * Disable power sequencer
	 */
	if (!sdio_read_reg(WILC_MISC, &reg)) {
		PRINT_ER("Failed read misc reg\n");
		return 0;
	}

	reg &= ~(1 << 8);
	if (!sdio_write_reg(WILC_MISC, reg)) {
		PRINT_ER("Failed write misc reg\n");
		return 0;
	}

	/*
	 * interrupt pin mux select
	 */
	ret = sdio_read_reg(WILC_PIN_MUX_0, &reg);
	if (!ret) {
		PRINT_ER("Failed read reg %08x\n", WILC_PIN_MUX_0);
		return 0;
	}
	reg |= (1 << 8);
	ret = sdio_write_reg(WILC_PIN_MUX_0, reg);
	if (!ret) {
		PRINT_ER("Failed write reg %08x\n", WILC_PIN_MUX_0);
		return 0;
	}

	/**
	 *	interrupt enable
	 **/
	ret = sdio_read_reg(WILC_INTR_ENABLE, &reg);
	if (!ret) {
		PRINT_ER("Failed read reg %08x\n", WILC_INTR_ENABLE);
		return 0;
	}
	reg |= (1 << 16);
	ret = sdio_write_reg(WILC_INTR_ENABLE, reg);
	if (!ret) {
		PRINT_ER("Failed write reg %08x\n", WILC_INTR_ENABLE);
		return 0;
	}

	return 1;
}
#else
static int sdio_sync(void)
{
	uint32_t reg;

	/*
	 * Disable power sequencer
	 */
	if (!sdio_read_reg(WILC_MISC, &reg)) {
		PRINT_ER("Failed read misc reg\n");
		return 0;
	}

	reg &= ~(1 << 8);
	if (!sdio_write_reg(WILC_MISC, reg)) {
		PRINT_ER("Failed write misc reg\n");
		return 0;
	}

	return 1;
}
#endif

int sdio_init(struct wilc_wlan_inp *inp)
{
	struct sdio_cmd52_t cmd;
	int loop;
	uint32_t chipid;
	if(inp != NULL)
	{
		memset(&g_sdio, 0, sizeof(struct wilc_sdio));

		g_sdio.os_context = inp->os_context.os_private;

		if (inp->io_func.io_init) {
			if (!inp->io_func.io_init(g_sdio.os_context)) {
				PRINT_ER("Failed io init bus\n");
				return 0;
			}
		} else {
			return 0;
		}

		g_sdio.sdio_cmd52	= inp->io_func.u.sdio.sdio_cmd52;
		g_sdio.sdio_cmd53	= inp->io_func.u.sdio.sdio_cmd53;
	}
	/*
	 * function 0 csa enable
	 */
	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 1;
	cmd.address = 0x100;
	cmd.data = 0x80;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Fail cmd 52, enable csa\n");
		goto _fail_;
	}

	/*
	 * function 0 block size
	 */
	if (!sdio_set_func0_block_size(WILC_SDIO_BLOCK_SIZE)) {
		PRINT_ER("Fail cmd 52, set func 0 block size\n");
		goto _fail_;
	}

	g_sdio.block_size = WILC_SDIO_BLOCK_SIZE;

	/*
	 * enable func1 IO
	 */
	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 1;
	cmd.address = 0x2;
	cmd.data = 0x2;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Fail cmd 52, set IOE register\n");
		goto _fail_;
	}

	/*
	 * make sure func 1 is up
	 */
	cmd.read_write = 0;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0x3;
	loop = 3;
	do {
		cmd.data = 0;
		if (!g_sdio.sdio_cmd52(&cmd)) {
			PRINT_ER("Fail cmd 52, get IOR register\n");
			goto _fail_;
		}
		if (cmd.data == 0x2)
			break;
	} while (loop--);

	if (loop <= 0) {
		PRINT_ER("Fail func 1 is not ready\n");
		goto _fail_;
	}

	/*
	 * func 1 is ready, set func 1 block size
	 */
	if (!sdio_set_func1_block_size(WILC_SDIO_BLOCK_SIZE)) {
		PRINT_ER("Fail set func 1 block size\n");
		goto _fail_;
	}

	/*
	 * func 1 interrupt enable
	 */
	cmd.read_write = 1;
	cmd.function = 0;
	cmd.raw = 1;
	cmd.address = 0x4;
	cmd.data = 0x3;
	if (!g_sdio.sdio_cmd52(&cmd)) {
		PRINT_ER("Fail cmd 52, set IEN register\n");
		goto _fail_;
	}

	/*
	 * make sure can read back chip id correctly
	 */
	 if(inp != NULL)
	{
	if (!sdio_read_reg(0x3b0000, &chipid)) {
		PRINT_ER("Fail cmd read chip id\n");
		goto _fail_;
	}

	PRINT_D(BUS_DBG, "chipid %08x\n", chipid);
	g_sdio.has_thrpt_enh3 = 1;
	PRINT_D(BUS_DBG, "has_thrpt_enh3 = %d\n", g_sdio.has_thrpt_enh3);
	 	}

	return 1;
_fail_:
	return 0;
}

static int sdio_read_size(uint32_t *size)
{
	uint32_t tmp;
	struct sdio_cmd52_t cmd;

	/*
	 * Read DMA count in words
	 */
	cmd.read_write = 0;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0xf2;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	tmp = cmd.data;
	cmd.address = 0xf3;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	tmp |= (cmd.data << 8);

	*size = tmp;

	return 1;
}

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_read_int(uint32_t *int_status)
{
	uint32_t tmp = 0;
	struct sdio_cmd52_t cmd;
	uint32_t irq_flags;

	sdio_read_size(&tmp);

	cmd.read_write = 0;
	cmd.function = 0;
	cmd.raw = 0;
	cmd.address = 0xfe;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	irq_flags = cmd.data & 0x0f;
	tmp |= ((irq_flags >> 0) << IRG_FLAGS_OFFSET);

	*int_status = tmp;

	return 1;
}
#else
static int sdio_read_int(uint32_t *int_status)
{
	uint32_t tmp = 0;
	struct sdio_cmd52_t cmd;
	int i;

	sdio_read_size(&tmp);

	cmd.function = 1;
	cmd.address = 0x04;
	cmd.data = 0;
	g_sdio.sdio_cmd52(&cmd);
	if (cmd.data & (1 << 0))
		tmp |= INT_0;

	if (cmd.data & (1 << 2))
		tmp |= INT_1;

	if (cmd.data & (1 << 3))
		tmp |= INT_2;

	if (cmd.data & (1 << 4))
		tmp |= INT_3;

	if (cmd.data & (1 << 5))
		tmp |= INT_4;

	if (cmd.data & (1 << 6))
		tmp |= INT_5;

	for (i = g_sdio.nint; i < MAX_NUM_INT; i++) {
		if ((tmp >> (IRG_FLAGS_OFFSET + i)) & 0x1) {
			PRINT_ER("Unexpected int\n");
			break;
		}
	}

	*int_status = tmp;

	return 1;
}
#endif

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_clear_int_ext(uint32_t val)
{
	int ret;

	if (g_sdio.has_thrpt_enh3) {
		uint32_t reg;

		reg = val & ((1 << MAX_NUN_INT_THRPT_ENH2) - 1);
		if (reg) {
			struct sdio_cmd52_t cmd;

			cmd.read_write = 1;
			cmd.function = 0;
			cmd.raw = 0;
			cmd.address = 0xfe;
			cmd.data = reg;

			ret = g_sdio.sdio_cmd52(&cmd);
			if (!ret) {
				PRINT_ER("Failed cmd52\n");
				goto _fail_;
			}
		}

		reg = 0;
		/* select VMM table 0 */
		if ((val & SEL_VMM_TBL0) == SEL_VMM_TBL0)
			reg |= (1 << 0);
		/* select VMM table 1 */
		if ((val & SEL_VMM_TBL1) == SEL_VMM_TBL1)
			reg |= (1 << 1);
		/* enable VMM */
		if ((val & EN_VMM) == EN_VMM)
			reg |= (1 << 2);
		if (reg) {
			struct sdio_cmd52_t cmd;

			cmd.read_write = 1;
			cmd.function = 0;
			cmd.raw = 0;
			cmd.address = 0xf1;
			cmd.data = reg;

			ret = g_sdio.sdio_cmd52(&cmd);
			if (!ret) {
				PRINT_ER("Failed cmd52\n");
				goto _fail_;
			}
		}
	} else {
		/*
		 * see below. has_thrpt_enh2 uses register 0xf8 to clear
		 * interrupts.
		 * We Cannot clear multiple interrupts.
		 * we must clear each interrupt individually
		 */
		uint32_t flags;
		uint32_t vmm_ctl;

		flags = val & ((1 << MAX_NUM_INT) - 1);

		if (flags) {
			int i;

			ret = 1;
			for (i = 0; i < g_sdio.nint; i++) {
				if (flags & 1) {
					struct sdio_cmd52_t cmd;

					cmd.read_write = 1;
					cmd.function = 0;
					cmd.raw = 0;
					cmd.address = 0xf8;
					cmd.data = (1 << i);

					ret = g_sdio.sdio_cmd52(&cmd);
					if (!ret) {
						PRINT_ER("Failed cmd52\n");
						goto _fail_;
					}
				}

				if (!ret)
					break;
				flags >>= 1;
			}
			if (!ret)
				goto _fail_;

			for (i = g_sdio.nint; i < MAX_NUM_INT; i++) {
				if (flags & 1)
					PRINT_ER("Unexpected int cleared\n");

				flags >>= 1;
			}
		}

		vmm_ctl = 0;
		/* select VMM table 0 */
		if ((val & SEL_VMM_TBL0) == SEL_VMM_TBL0)
			vmm_ctl |= (1 << 0);
		/* select VMM table 1 */
		if ((val & SEL_VMM_TBL1) == SEL_VMM_TBL1)
			vmm_ctl |= (1 << 1);
		/* enable VMM */
		if ((val & EN_VMM) == EN_VMM)
			vmm_ctl |= (1 << 2);

		if (vmm_ctl) {
			struct sdio_cmd52_t cmd;

			cmd.read_write = 1;
			cmd.function = 0;
			cmd.raw = 0;
			cmd.address = 0xf1;
			cmd.data = vmm_ctl;
			ret = g_sdio.sdio_cmd52(&cmd);
			if (!ret) {
				PRINT_ER("Failed cmd52\n");
				goto _fail_;
			}
		}
	}

	return 1;
_fail_:
	return 0;
}
#else
static int sdio_clear_int_ext(uint32_t val)
{
	int ret;

	if (g_sdio.has_thrpt_enh3) {
		uint32_t reg = 0;

		/* select VMM table 0 */
		if ((val & SEL_VMM_TBL0) == SEL_VMM_TBL0)
			reg |= (1 << 0);
		/* select VMM table 1 */
		if ((val & SEL_VMM_TBL1) == SEL_VMM_TBL1)
			reg |= (1 << 1);
		/* enable VMM */
		if ((val & EN_VMM) == EN_VMM)
			reg |= (1 << 2);
		if (reg) {
			struct sdio_cmd52_t cmd;

			cmd.read_write = 1;
			cmd.function = 0;
			cmd.raw = 0;
			cmd.address = 0xf1;
			cmd.data = reg;

			ret = g_sdio.sdio_cmd52(&cmd);
			if (!ret) {
				PRINT_ER("Failed cmd52\n");
				goto _fail_;
			}
		}
	} else {
		uint32_t vmm_ctl = 0;

		/* select VMM table 0 */
		if ((val & SEL_VMM_TBL0) == SEL_VMM_TBL0)
			vmm_ctl |= (1 << 0);
		/* select VMM table 1 */
		if ((val & SEL_VMM_TBL1) == SEL_VMM_TBL1)
			vmm_ctl |= (1 << 1);
		/* enable VMM */
		if ((val & EN_VMM) == EN_VMM)
			vmm_ctl |= (1 << 2);

		if (vmm_ctl) {
			struct sdio_cmd52_t cmd;

			cmd.read_write = 1;
			cmd.function = 0;
			cmd.raw = 0;
			cmd.address = 0xf1;
			cmd.data = vmm_ctl;
			ret = g_sdio.sdio_cmd52(&cmd);
			if (!ret) {
				PRINT_ER("Failed cmd52\n");
				goto _fail_;
			}
		}
	}

	return 1;
_fail_:
	return 0;
}
#endif

#ifdef WILC_SDIO_IRQ_GPIO
static int sdio_sync_ext(int nint)
{
	uint32_t reg;
	int ret, i;

	if (nint > MAX_NUM_INT) {
		PRINT_ER("too many interupts %d\n", nint);
		return 0;
	}
	if (nint > MAX_NUN_INT_THRPT_ENH2) {
		PRINT_ER("not support more than 5 ints when has_thrpt_enh2=1\n");
		return 0;
	}

	g_sdio.nint = nint;

	/*
	 * Disable power sequencer
	 */
	if (!sdio_read_reg(WILC_MISC, &reg)) {
		PRINT_ER("Failed read misc reg\n");
		return 0;
	}

	reg &= ~(1 << 8);
	if (!sdio_write_reg(WILC_MISC, reg)) {
		PRINT_ER("Failed write misc reg\n");
		return 0;
	}

	/*
	 * interrupt pin mux select
	 */
	ret = sdio_read_reg(WILC_PIN_MUX_0, &reg);
	if (!ret) {
		PRINT_ER("Failed read reg %08x\n", WILC_PIN_MUX_0);
		return 0;
	}
	reg |= (1 << 8);
	ret = sdio_write_reg(WILC_PIN_MUX_0, reg);
	if (!ret) {
		PRINT_ER("Failed write reg %08x\n", WILC_PIN_MUX_0);
		return 0;
	}

	/**
	 *      interrupt enable
	 **/
	ret = sdio_read_reg(WILC_INTR_ENABLE, &reg);
	if (!ret) {
		PRINT_ER("Failed read reg %08x\n", WILC_INTR_ENABLE);
		return 0;
	}

	for (i = 0; (i < 5) && (nint > 0); i++, nint--)
		reg |= (1 << (27 + i));

	ret = sdio_write_reg(WILC_INTR_ENABLE, reg);
	if (!ret) {
		PRINT_ER("Failed write reg %08x\n", WILC_INTR_ENABLE);
		return 0;
	}
	if (nint) {
		ret = sdio_read_reg(WILC_INTR2_ENABLE, &reg);
		if (!ret) {
			PRINT_ER("Failed read reg %08x\n", WILC_INTR2_ENABLE);
			return 0;
		}

		for (i = 0; (i < 3) && (nint > 0); i++, nint--)
			reg |= (1 << i);

		ret = sdio_read_reg(WILC_INTR2_ENABLE, &reg);
		if (!ret) {
			PRINT_ER("Failed write reg %08x\n", WILC_INTR2_ENABLE);
			return 0;
		}
	}

	return 1;
}
#else
static int sdio_sync_ext(int nint)
{
	uint32_t reg;

	if (nint > MAX_NUM_INT) {
		PRINT_ER("too many interupts %d\n", nint);
		return 0;
	}
	if (nint > MAX_NUN_INT_THRPT_ENH2) {
		PRINT_ER("not support more than 5 int when has_thrpt_enh2=1\n");
		return 0;
	}

	g_sdio.nint = nint;

	/*
	 * Disable power sequencer
	 */
	if (!sdio_read_reg(WILC_MISC, &reg)) {
		PRINT_ER("Failed read misc reg\n");
		return 0;
	}

	reg &= ~(1 << 8);
	if (!sdio_write_reg(WILC_MISC, reg)) {
		PRINT_ER("Failed write misc reg\n");
		return 0;
	}

	return 1;
}
#endif

/*
 * Global sdio HIF function table
 */
struct wilc_hif_func hif_sdio = {
	sdio_init,
	sdio_deinit,
	sdio_read_reg,
	sdio_write_reg,
	sdio_read,
	sdio_write,
	sdio_sync,
	sdio_clear_int,
	sdio_read_int,
	sdio_clear_int_ext,
	sdio_read_size,
	sdio_write,
	sdio_read,
	sdio_sync_ext,
};
EXPORT_SYMBOL(hif_sdio);

