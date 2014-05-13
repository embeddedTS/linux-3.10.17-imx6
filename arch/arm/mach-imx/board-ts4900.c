
#include <linux/delay.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <linux/gpio_keys.h>
#include <linux/wl12xx.h>

#include <linux/platform_device.h>
#include <linux/platform_data/mmc-ts4900.h>


#include <asm/mach-types.h>
#include <asm/mach/arch.h>

/* Convert GPIO signal to GPIO pin number */
#define GPIO_TO_PIN(bank, gpio)	(16 * (bank) + (gpio))

#if (defined(CONFIG_WL12XX) || defined(CONFIG_WL12XX_MODULE))

#define TS4900_WLAN_EN			GPIO_TO_PIN(6, 9)
#define TS4900_WLAN_IRQ			GPIO_TO_PIN(6, 10)

static void wl12xx_set_power(int index, bool power_on)
{
	static bool power_state;

	pr_debug("Powering %s wl12xx", power_on ? "on" : "off");

	if (power_on == power_state)
		return;
	power_state = power_on;

	if (power_on) {
		/* Power up sequence required for wl127x devices */
		gpio_set_value(TS4900_WLAN_EN, 1);
		usleep_range(15000, 15000);
		gpio_set_value(TS4900_WLAN_EN, 0);
		usleep_range(1000, 1000);
		gpio_set_value(TS4900_WLAN_EN, 1);
		msleep(70);
	} else {
		gpio_set_value(TS4900_WLAN_EN, 0);
	}
}

static struct ts4900_mmc_config ts4900_wl12xx_mmc_config = {
	.set_power	= wl12xx_set_power,
	.wires		= 4,
	.max_freq	= 25000000,
	.caps		= MMC_CAP_4_BIT_DATA | MMC_CAP_NONREMOVABLE |
			  MMC_CAP_POWER_OFF_CARD,
};
/*
static const short ts4900_wl12xx_pins[] __initconst = {
	TS4900_MMCSD1_DAT_0, TS4900_MMCSD1_DAT_1, TS4900_MMCSD1_DAT_2,
	TS4900_MMCSD1_DAT_3, TS4900_MMCSD1_CLK, TS4900_MMCSD1_CMD,
	TS4900_GPIO6_9, TS4900_GPIO6_10,
	-1
};
*/

static struct wl12xx_platform_data ts4900_wl12xx_wlan_data __initdata = {
	.irq			= -1,
	.board_ref_clock	= WL12XX_REFCLOCK_38,
	.platform_quirks	= WL12XX_PLATFORM_QUIRK_EDGE_IRQ,
};

static __init int ts4900_wl12xx_init(void)
{
	int ret;

	/*
	ret = davinci_cfg_reg_list(ts4900_wl12xx_pins);
	if (ret) {
		pr_err("wl12xx/mmc mux setup failed: %d\n", ret);
		goto exit;
	}
*/

	//ret = ts4900_register_mmcsd1(&ts4900_wl12xx_mmc_config);
	if (ret) {
		pr_err("wl12xx/mmc registration failed: %d\n", ret);
		goto exit;
	}

	ret = gpio_request_one(TS4900_WLAN_EN, GPIOF_OUT_INIT_LOW, "wl12xx_en");
	if (ret) {
		pr_err("Could not request wl12xx enable gpio: %d\n", ret);
		goto exit;
	}

	ret = gpio_request_one(TS4900_WLAN_IRQ, GPIOF_IN, "wl12xx_irq");
	if (ret) {
		pr_err("Could not request wl12xx irq gpio: %d\n", ret);
		goto free_wlan_en;
	}

	ts4900_wl12xx_wlan_data.irq = gpio_to_irq(TS4900_WLAN_IRQ);

	ret = wl12xx_set_platform_data(&ts4900_wl12xx_wlan_data);
	if (ret) {
		pr_err("Could not set wl12xx data: %d\n", ret);
		goto free_wlan_irq;
	}

	return 0;

free_wlan_irq:
	gpio_free(TS4900_WLAN_IRQ);

free_wlan_en:
	gpio_free(TS4900_WLAN_EN);

exit:
	return ret;
}

#endif

void imx6q_ts4900_init(void)
{
   printk("imx6q_ts4900_init()\n");   
}