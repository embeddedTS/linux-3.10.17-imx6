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

#include "at_pwr_dev.h"
#include "linux_wlan_common.h"
#include "host_interface.h"
#include "wilc_wlan.h"

#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/cdev.h>
#include <linux/firmware.h>
#ifdef WILC_SDIO
#include "linux_wlan_sdio.h"
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#else
#include "linux_wlan_spi.h"
#endif /* WILC_SDIO */


#define DRV_NAME  "at_pwr_dev"

/* GPIO definitions */
int reset_gpio;
int chip_en_gpio;

typedef int (cmd_handler)(int, char*);

struct cmd_handle_entry {
	const char *cmd_str;
	cmd_handler *handle_cmd;
};


static dev_t chc_dev_no; /* Global variable for the first device number */
static struct cdev str_chc_dev; /* Global variable for the character
				   device structure */
static struct class *chc_dev_class; /* Global variable for the device class */
struct device *dev;
struct pwr_dev_t pwr_dev;
int bt_init_done=0;
int (*pf_is_wilc3000_initalized)(void)=NULL;

static struct platform_device *at_pwr_platform_dev;

#ifdef WILC_SDIO
struct semaphore sdio_probe_sync;
#else
struct semaphore spi_probe_sync;
#endif /* WILC_SDIO */


static int at_pwr_probe(struct platform_device *pdev);
static int at_pwr_remove(struct platform_device *pdev);

/* Character device operations*/
static int pwr_dev_open(struct inode *i, struct file *f);
static int pwr_dev_close(struct inode *i, struct file *f);
static ssize_t pwr_dev_read(struct file *f, char __user *buf, size_t len,
			    loff_t *off);
static ssize_t pwr_dev_write(struct file *f, const char __user *buff,
			     size_t len, loff_t *off);
/* Command handlers */
static int cmd_handle_bt_download_fw(int source, char* param);
static int cmd_handle_bt_power_up(int source, char* param);
static int cmd_handle_bt_power_down(int source, char* param);
static int cmd_handle_bt_fw_chip_wake_up(int source, char* param);
static int cmd_handle_bt_fw_chip_allow_sleep(int source, char* param);
static int cmd_handle_wilc_review_current_status(int source, char* param);
static int cmd_handle_wilc_cca_threshold(int source, char* param);

int wilc_bt_firmware_download(void);
int wilc_bt_start(void);
static int linux_wlan_device_power(int on_off);
static int linux_wlan_device_detection(int on_off);
static void prepare_inp(struct wilc_wlan_inp *nwi);

static const struct cmd_handle_entry cmd_table[] = {
	{"BT_DOWNLOAD_FW", cmd_handle_bt_download_fw},
	{"BT_POWER_UP", cmd_handle_bt_power_up},
	{"BT_POWER_DOWN", cmd_handle_bt_power_down},
	{"BT_FW_CHIP_WAKEUP", cmd_handle_bt_fw_chip_wake_up},
	{"BT_FW_CHIP_ALLOW_SLEEP", cmd_handle_bt_fw_chip_allow_sleep},
	{"WILC_CURRENT_STATUS", cmd_handle_wilc_review_current_status},
	{"CCA_THRESHOLD", cmd_handle_wilc_cca_threshold},
	/* Keep the NULL handler at the end of the table */
	{(const char *) NULL, NULL},
};

static const struct file_operations pugs_fops = {
	.owner = THIS_MODULE,
	.open = pwr_dev_open,
	.release = pwr_dev_close,
	.read = pwr_dev_read,
	.write = pwr_dev_write
};


static struct platform_driver at_pwr_driver = {
	.probe = at_pwr_probe,
	.remove = at_pwr_remove,
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
	},
};


static int at_pwr_probe(struct platform_device *pdev)
{
	struct device_node *node;
	int ret;

	const struct firmware *wilc_firmware;
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: probe\n");

	/* Get GPIO numbers from DT */
#ifdef WILC_SDIO
	node = of_find_node_by_name(NULL, "wilc_sdio");
#else
	node = of_find_node_by_name(NULL, "wilc_spi");
#endif

	if (node == NULL) {
		PRINT_ER("Couldn't get device node\n");
	return -EIO;
	}

	if ((reset_gpio = of_get_named_gpio(node, "wilc3000,reset-gpios", 0)) < 0) {
		PRINT_ER("Failed to get reset GPIO\n");
		return -EIO;
	} else {
		ret = gpio_request(reset_gpio, "wilc3000_reset");
		if(ret == -EPROBE_DEFER){
		printk(KERN_INFO "HERE, %s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return -EPROBE_DEFER;
		} else if (ret != 0) {
			PRINT_ER("Failed to request reset GPIO, %d\n", ret);
			return -EIO;
		} else {
			gpio_direction_output(reset_gpio, 0);
		}
	}

	if ((chip_en_gpio = of_get_named_gpio(node, "wilc3000,chip-en-gpios", 0)) < 0) {
		PRINT_ER("Failed to get chip EN GPIO\n");
		return -EIO;
	} else {
		ret = gpio_request(chip_en_gpio, "wilc3000_chip_en");
		if(ret == -EPROBE_DEFER){
		printk(KERN_INFO "HERE, %s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return -EPROBE_DEFER;
		} else if (ret != 0) {
			PRINT_ER("Failed to request chip EN GPIO, %d\n", ret);
			return -EIO;
		} else {
			gpio_direction_output(chip_en_gpio, 0);
		}
	}
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: reset_gpio = GPIO #%d, chip_en_gpio = GPIO #%d\n", 
	reset_gpio, chip_en_gpio);

	if (chip_en_gpio < 0)
		return chip_en_gpio;
	if (reset_gpio < 0)
		return reset_gpio;

	linux_wlan_device_power(0);
	return 0;
}

static int at_pwr_remove(struct platform_device *pdev)
{
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: remove\n");
   
   if (reset_gpio > 0)
	   gpio_free(reset_gpio);
	if (chip_en_gpio > 0)   
	   gpio_free(chip_en_gpio);
	   
   return 0;
}


int at_pwr_dev_init(void)
{
	int ret = 0;

	PRINT_D(PWRDEV_DBG, "at_pwr_dev: init\n");
	
	at_pwr_platform_dev = platform_device_alloc(DRV_NAME, 0);
	
	if (at_pwr_platform_dev == NULL) {
	   printk("Failed to allocate platform device '" DRV_NAME "'\n");
	   return -ENOMEM;
	}
	
	ret = platform_device_add(at_pwr_platform_dev);
	if (ret) {
	   printk("Failed to add platform device '" DRV_NAME "'\n");
	   platform_device_put(at_pwr_platform_dev);
	}   
	
	ret = platform_driver_register(&at_pwr_driver);
	if (ret) {
		printk("Failed to register platform driver '" DRV_NAME "'\n");
		goto exit_free_device;
	}
	
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: registered\n");
	memset(&pwr_dev, 0, sizeof(pwr_dev));
	ret = alloc_chrdev_region(&chc_dev_no, 0, 1, "atmel");
	if (ret < 0)
		return ret;
	chc_dev_class = class_create(THIS_MODULE, "atmel");
	if (IS_ERR(chc_dev_class)) {
		unregister_chrdev_region(chc_dev_no, 1);
		return PTR_ERR(chc_dev_class);
	}
	dev = device_create(chc_dev_class, NULL, chc_dev_no, NULL,
			    "at_pwr_dev");
	if (IS_ERR(dev)) {
		class_destroy(chc_dev_class);
		unregister_chrdev_region(chc_dev_no, 1);
		return PTR_ERR(dev);
	}

	cdev_init(&str_chc_dev, &pugs_fops);
	cdev_add(&str_chc_dev, chc_dev_no, 1);
	if (ret < 0) {
		device_destroy(chc_dev_class, chc_dev_no);
		class_destroy(chc_dev_class);
		unregister_chrdev_region(chc_dev_no, 1);
		return ret;
	}

#ifdef WILC_SDIO
	sema_init(&sdio_probe_sync, 0);
#else
	sema_init(&spi_probe_sync, 0);
#endif /* WILC_SDIO */

	mutex_init(&pwr_dev.cs);
	mutex_init(&pwr_dev.hif_cs);
	
	/*initialize Chip_En and ResetN */
	//linux_wlan_device_power(0);

	return 0;
	
exit_free_device:
  	platform_device_unregister(at_pwr_platform_dev);	
	return ret;
}

void at_pwr_dev_deinit(void)
{
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: deinit\n");
	
	if (&pwr_dev.hif_cs != NULL)
		mutex_destroy(&pwr_dev.hif_cs);

	if (&pwr_dev.cs != NULL)
		mutex_destroy(&pwr_dev.cs);

	cdev_del(&str_chc_dev);
	device_destroy(chc_dev_class, chc_dev_no);
	class_destroy(chc_dev_class);
	unregister_chrdev_region(chc_dev_no, 1);
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: unregistered\n");
	
  	platform_driver_unregister(&at_pwr_driver);	
	platform_device_unregister(at_pwr_platform_dev);
	
	return;
}

struct mutex *at_pwr_dev_get_bus_lock()
{
	return &pwr_dev.hif_cs;
}
EXPORT_SYMBOL(at_pwr_dev_get_bus_lock);

int at_pwr_power_down(int source)
{
	if(source == PWR_DEV_SRC_BT)
	{
		int ret;
		uint32_t reg;

		PRINT_D(PWRDEV_DBG, "AT PWR: bt_power_down\n");

		if ((pwr_dev.bus_registered[PWR_DEV_SRC_BT] == false)
		    && (pwr_dev.power_status[PWR_DEV_SRC_BT] == true)) {
			at_pwr_register_bus(PWR_DEV_SRC_BT);
		}

		/* Adjust coexistence module. This should be done from the FW in the future*/
		if (pwr_dev.bus_registered[PWR_DEV_SRC_BT] == true) {
			acquire_bus(ACQUIRE_AND_WAKEUP, PWR_DEV_SRC_BT);

			ret = pwr_dev.hif_func.hif_read_reg(rGLOBAL_MODE_CONTROL, &reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail read reg %x ...\n",
				       rGLOBAL_MODE_CONTROL);
				
					release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);

				return ret;
			}
			/* Clear BT mode*/
			reg &= ~BIT1;
			ret = pwr_dev.hif_func.hif_write_reg(rGLOBAL_MODE_CONTROL, reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail write reg %x ...\n",
				       rGLOBAL_MODE_CONTROL);
			
					release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				
				return ret;
			}

			ret = pwr_dev.hif_func.hif_read_reg(rCOEXIST_CTL, &reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail read reg %x ...\n",
				       rCOEXIST_CTL);
				
					release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);

				return ret;
			}
			/* Stop forcing BT and force Wifi */
			reg &= ~BIT9;
			reg |= BIT11;
			ret = pwr_dev.hif_func.hif_write_reg(rCOEXIST_CTL, reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail write reg %x ...\n",
				       rCOEXIST_CTL);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}

			/*TicketId1115*/
			/*Disable awake coex null frames*/
			ret = pwr_dev.hif_func.hif_read_reg(rCOE_AUTO_PS_ON_NULL_PKT, &reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOE_AUTO_PS_ON_NULL_PKT);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}
			reg &= ~BIT30;
			ret = pwr_dev.hif_func.hif_write_reg(rCOE_AUTO_PS_ON_NULL_PKT, reg);
			if (!ret) {
				PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOE_AUTO_PS_ON_NULL_PKT);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}

			/*TicketId1115*/
			/*Disable doze coex null frames*/
			ret = pwr_dev.hif_func.hif_read_reg(rCOE_AUTO_PS_OFF_NULL_PKT, &reg);
			if (!ret) {
				PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOE_AUTO_PS_OFF_NULL_PKT);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}
			reg &= ~BIT30;
			ret = pwr_dev.hif_func.hif_write_reg(rCOE_AUTO_PS_OFF_NULL_PKT, reg);
			if (!ret) {
				PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOE_AUTO_PS_OFF_NULL_PKT);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}
			// Disable BT wakeup
			ret = pwr_dev.hif_func.hif_read_reg(rPWR_SEQ_MISC_CTRL, &reg);
			if (!ret) {
				PRINT_ER( "[wilc start]: fail read reg %x ...\n", rPWR_SEQ_MISC_CTRL);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}
			reg &= ~ BIT29;
			ret = pwr_dev.hif_func.hif_write_reg(rPWR_SEQ_MISC_CTRL, reg);
			if (!ret) {
				PRINT_ER( "[wilc start]: fail write reg %x ...\n", rPWR_SEQ_MISC_CTRL);
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
				return ret;
			}


			release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
		
		}

		bt_init_done=0;
		at_pwr_unregister_bus(PWR_DEV_SRC_BT);
	}
	
	mutex_lock(&pwr_dev.cs);

	PRINT_D(PWRDEV_DBG, "source: %s, current bus status Wifi: %d, BT: %d\n",
		 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"),
		 pwr_dev.power_status[PWR_DEV_SRC_WIFI],
		 pwr_dev.power_status[PWR_DEV_SRC_BT]);

	if (pwr_dev.power_status[source] == false) {
		PRINT_ER("power down request for already powered down source %s\n",
		       (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else if (((source == PWR_DEV_SRC_WIFI) &&
		  (pwr_dev.power_status[PWR_DEV_SRC_BT] == true)) ||
		  ((source == PWR_DEV_SRC_BT) &&
		  (pwr_dev.power_status[PWR_DEV_SRC_WIFI] == true))) {
		PRINT_WRN(PWRDEV_DBG, "Another device is preventing power down. request source is %s\n",
			(source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else {
		linux_wlan_device_detection(0);
		linux_wlan_device_power(0);
#ifdef DOWNLOAD_BT_FW_ONCE
		pwr_dev.is_bt_fw_ready = false;
#endif
	}
	pwr_dev.power_status[source] = false;

	mutex_unlock(&pwr_dev.cs);

	return 0;
}
EXPORT_SYMBOL(at_pwr_power_down);

int at_pwr_register_bus(int source)
{
	int ret = 0;

	mutex_lock(&pwr_dev.cs);

	PRINT_D(PWRDEV_DBG, "source: %s, current bus status Wifi: %d, BT: %d\n",
		 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"),
		 pwr_dev.bus_registered[PWR_DEV_SRC_WIFI],
		 pwr_dev.bus_registered[PWR_DEV_SRC_BT]);

	if (pwr_dev.bus_registered[source] == true) {
		PRINT_WRN(PWRDEV_DBG, "Registering bus request for already registered source %s\n",
		       (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else {
		if ((pwr_dev.bus_registered[PWR_DEV_SRC_WIFI] == true) ||
		    (pwr_dev.bus_registered[PWR_DEV_SRC_BT] == true)) {
			pwr_dev.bus_registered[source] = true;

			if (source == PWR_DEV_SRC_BT) {
#ifdef WILC_SDIO
				memcpy((void *)&pwr_dev.hif_func, &hif_sdio,
				       sizeof(struct wilc_hif_func));
#else
				memcpy((void *)&pwr_dev.hif_func, &hif_spi,
				       sizeof(struct wilc_hif_func));
#endif /* WILC_SDIO */
			}
		} else {
			struct wilc_wlan_inp inp;

			prepare_inp(&inp);
			linux_wlan_device_detection(1);

#ifdef WILC_SDIO
			ret = sdio_register_driver(&wilc_bus);
			if (ret < 0) {
				PRINT_D(PWRDEV_DBG, "init_wilc_driver: Failed to register sdio driver\n");
			} else {
				PRINT_D(PWRDEV_DBG, "Waiting for sdio probe\n");

				if (down_timeout(&sdio_probe_sync, msecs_to_jiffies(1000)) < 0)	{
					PRINT_D(PWRDEV_DBG, "sdio probe TimedOUT\n");
					ret = -1;
				} else {
					PRINT_D(PWRDEV_DBG, "sdio probe is called\n");
					pwr_dev.bus_registered[source] = true;
					if (!hif_sdio.hif_init(&inp)){
						ret = -5
					}
					memcpy((void *)&pwr_dev.hif_func, &hif_sdio, sizeof(struct wilc_hif_func));
				}
			}
#else
			if (!linux_spi_init(&inp)) {
				PRINT_ER("Can't initialize SPI\n");
				ret = -1;
			} else {
				PRINT_D(PWRDEV_DBG, "Waiting for spi probe\n");

				if (down_timeout(&spi_probe_sync, msecs_to_jiffies(1000)) < 0) {
					PRINT_D(PWRDEV_DBG, "spi probe TimedOUT\n");
					ret = -1;
				} else {
					PRINT_D(PWRDEV_DBG, "spi probe is called\n");
					pwr_dev.bus_registered[source] = true;
					if (!hif_spi.hif_init(&inp)){
						ret = -ENODEV;
					}
					memcpy((void *)&pwr_dev.hif_func, &hif_spi, sizeof(struct wilc_hif_func));
				}
			}
#endif /* WILC_SDIO */
		}
	}

	mutex_unlock(&pwr_dev.cs);
	return ret;
}
EXPORT_SYMBOL(at_pwr_register_bus);

int at_pwr_unregister_bus(int source)
{
	mutex_lock(&pwr_dev.cs);

	PRINT_D(PWRDEV_DBG, "source: %s, current bus status Wifi: %d, BT: %d\n",
		 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"),
		 pwr_dev.bus_registered[PWR_DEV_SRC_WIFI],
		 pwr_dev.bus_registered[PWR_DEV_SRC_BT]);

	if (pwr_dev.bus_registered[source] == false) {
		PRINT_WRN(PWRDEV_DBG, "Unregistering bus request for already unregistered source %s\n",
		       (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else if (((source == PWR_DEV_SRC_WIFI) &&
		   (pwr_dev.bus_registered[PWR_DEV_SRC_BT] == true)) ||
		   ((source == PWR_DEV_SRC_BT) &&
		   (pwr_dev.bus_registered[PWR_DEV_SRC_WIFI] == true))) {
		PRINT_WRN(PWRDEV_DBG, "Another device is preventing bus unregisteration. request source is %s\n",
			(source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else {
#ifndef WILC_SDIO
		hif_spi.hif_deinit(NULL);
		PRINT_D(PWRDEV_DBG, "SPI unregsiter...\n");
		spi_unregister_driver(&wilc_bus);
#else
		PRINT_D(PWRDEV_DBG, "SDIO unregsiter...\n");
		hif_sdio.hif_deinit(NULL);
		sdio_unregister_driver(&wilc_bus);
#endif /* WILC_SDIO */
	}

	pwr_dev.bus_registered[source] = false;
	mutex_unlock(&pwr_dev.cs);
	return 0;
}
EXPORT_SYMBOL(at_pwr_unregister_bus);

/*TicketId883*/
#ifdef WILC_BT_COEXISTENCE
void wilc_set_pf_change_coex_mode(WILCpfChangeCoexMode pfChangeCoexMode)
{
	pwr_dev.pfChangeCoexMode = pfChangeCoexMode;
}
EXPORT_SYMBOL(wilc_set_pf_change_coex_mode);
#endif

static int pwr_dev_open(struct inode *i, struct file *f)
{
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: open()\n");
	return 0;
}

static int pwr_dev_close(struct inode *i, struct file *f)
{
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: close()\n");
	return 0;
}

static ssize_t pwr_dev_read(struct file *f, char __user *buf, size_t len,
			    loff_t *off)
{
	PRINT_D(PWRDEV_DBG, "at_pwr_dev: read()\n");
	return 0;
}

static ssize_t pwr_dev_write(struct file *f, const char __user *buff,
			     size_t len, loff_t *off)
{
	struct cmd_handle_entry *cmd_entry;
	char *param = (char*)kmalloc(len+1 ,GFP_ATOMIC);
	
	strncpy(param, buff, len);
	param[len] = '\0';

	if (len > 0) {
		PRINT_D(PWRDEV_DBG, "received %s, len %d\n", param, len);
		/* call the appropriate command handler */
		cmd_entry = (struct cmd_handle_entry *)cmd_table;
		while (cmd_entry->handle_cmd != NULL) {
			if (strncmp(cmd_entry->cmd_str, param,
			    strlen(cmd_entry->cmd_str)) == 0) {
				PRINT_D(PWRDEV_DBG, "param len: %d, string: %s\n", len - strlen(cmd_entry->cmd_str), param);
				cmd_entry->handle_cmd(PWR_DEV_SRC_BT, param + strlen(cmd_entry->cmd_str));
				
				break;
			}
			cmd_entry++;
		}
	} else {
		PRINT_D(PWRDEV_DBG, "received invalid size <=0: %d\n", len);
	}
	kfree(param);
	return len;
}


static int cmd_handle_bt_power_up(int source, char* param)
{
	int ret;
	
	PRINT_D(PWRDEV_DBG, "AT PWR: bt_power_up\n");
	bt_init_done=0;
	ret = at_pwr_power_up(PWR_DEV_SRC_BT);
	if(ret != 0){
		return ret; 
	}
	
	return 0;
}


static int cmd_handle_bt_power_down(int source, char* param)
{	
	at_pwr_power_down(PWR_DEV_SRC_BT);

	return 0;
}

static int cmd_handle_bt_download_fw(int source, char* param)
{
	PRINT_D(PWRDEV_DBG, "AT PWR: bt_download_fw\n");

	if (wilc_bt_firmware_download() != 0)	{
		PRINT_ER("Failed to download BT FW\n");
		return -1;
	}

	if (wilc_bt_start() != 0) {
		PRINT_ER("Failed to start BT FW\n");
		return -1;
	}

	at_pwr_unregister_bus(PWR_DEV_SRC_BT);

	return 0;
}



static int cmd_handle_bt_fw_chip_wake_up(int source, char* param)
{
	chip_wakeup(source);
	return 0;
}



static int cmd_handle_bt_fw_chip_allow_sleep(int source, char* param)
{
	bt_init_done=1;
	chip_allow_sleep(source);
	return 0;
}


static int cmd_handle_wilc_review_current_status(int source, char* param)
{
	PRINT_D(PWRDEV_DBG, "WILC Devices current status Wifi: %d, BT: %d\n",
		 pwr_dev.power_status[PWR_DEV_SRC_WIFI],
		 pwr_dev.power_status[PWR_DEV_SRC_BT]);
	
	return 0;
}

static int cmd_handle_wilc_cca_threshold(int source, char* param)
{
	int carrier_thrshold, noise_thrshold;
	unsigned int carr_thrshold_frac, noise_thrshold_frac, carr_thrshold_int, 
		noise_thrshold_int, reg;
	
	if(param == NULL) {
		PRINT_ER("Invalid parameter\n");
		return -1;
	}

	if(!(pwr_dev.bus_registered[PWR_DEV_SRC_WIFI] || pwr_dev.bus_registered[PWR_DEV_SRC_BT])) {
		PRINT_ER("Bus not registered\n");
		return -1;
	}

	if(sscanf(param, " %d %d", &noise_thrshold, &carrier_thrshold) != 2) {
		PRINT_ER("Failed to parse input parameters. Usage:\n echo CCA_THRESHOLD "
			"NOISE_THRESHOLD CARRIER_THRESHOLD > /dev/at_pwr_dev\n"
			"where threshold values are in dB * 10\ne.g."
			"echo CCA_THRESHOLD -625 -826 > /dev/at_pwr_dev to set thresholds "
			"to -62.5 and -82.6\n\n");
		return -1;
	}
	
	PRINT_D(PWRDEV_DBG, 
		"Changing CCA noise threshold to %d and carrier thresholds to %d \n",
		noise_thrshold, carrier_thrshold);

	carr_thrshold_int = carrier_thrshold/10;
	if(carrier_thrshold < 0)
		carr_thrshold_frac = (carr_thrshold_int * 10) - carrier_thrshold;
	else
		carr_thrshold_frac = carrier_thrshold - (carr_thrshold_int * 10);

	noise_thrshold_int = noise_thrshold/10;
	if(noise_thrshold < 0)
		noise_thrshold_frac = (noise_thrshold_int * 10) - noise_thrshold;
	else
		noise_thrshold_frac = noise_thrshold - (noise_thrshold_int * 10);

	pwr_dev.hif_func.hif_read_reg(rCCA_CTL_2, &reg);
	reg &= ~(0x7FF0000);
	reg |= ((noise_thrshold_frac & 0x7) | ((noise_thrshold_int & 0x1FF) << 3)) << 16;
	pwr_dev.hif_func.hif_write_reg(rCCA_CTL_2, reg);
	
	pwr_dev.hif_func.hif_read_reg(rCCA_CTL_7, &reg);
	reg &= ~(0x7FF0000);
	reg |= ((carr_thrshold_frac & 0x7) | ((carr_thrshold_int & 0x1FF) << 3)) << 16;
	pwr_dev.hif_func.hif_write_reg(rCCA_CTL_7, reg);
	
	return 0;
}


void prepare_inp(struct wilc_wlan_inp *nwi)
{
	nwi->os_context.os_private = (void *)&pwr_dev;
	nwi->os_context.hif_critical_section= (void *)&(pwr_dev.hif_cs);

#ifdef WILC_SDIO
	nwi->io_func.io_type = HIF_SDIO;
	nwi->io_func.io_init = linux_sdio_init;
	nwi->io_func.io_deinit = linux_sdio_deinit;
	nwi->io_func.u.sdio.sdio_cmd52 = linux_sdio_cmd52;
	nwi->io_func.u.sdio.sdio_cmd53 = linux_sdio_cmd53;
#else
	nwi->io_func.io_type = HIF_SPI;
	nwi->io_func.io_init = linux_spi_init;
	nwi->io_func.io_deinit = linux_spi_deinit;
	nwi->io_func.u.spi.spi_tx = linux_spi_write;
	nwi->io_func.u.spi.spi_rx = linux_spi_read;
	nwi->io_func.u.spi.spi_trx = linux_spi_write_read;
#endif /* WILC_SDIO */
}


void chip_allow_sleep(int source)
{
	uint32_t reg = 0;

	if (((source == PWR_DEV_SRC_WIFI) &&
	    (pwr_dev.keep_awake[PWR_DEV_SRC_BT] == true)) ||
	    ((source == PWR_DEV_SRC_BT) &&
	    (pwr_dev.keep_awake[PWR_DEV_SRC_WIFI] == true))) {
		PRINT_WRN(PWRDEV_DBG, "Another device is preventing allow sleep operation. request source is %s\n",
			  (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else {
#ifdef WILC_SDIO
		pwr_dev.hif_func.hif_read_reg(0xf0, &reg);
		pwr_dev.hif_func.hif_write_reg(0xf0, reg & ~(1 << 0));
#else
		pwr_dev.hif_func.hif_read_reg(0x1, &reg);
		pwr_dev.hif_func.hif_write_reg(0x1, reg & ~(1 << 1));
#endif /* WILC_SDIO */
	}

	pwr_dev.keep_awake[source] = false;
}
EXPORT_SYMBOL(chip_allow_sleep);

void chip_wakeup(int source)
{
	uint32_t wakeup_reg_val, clk_status_reg_val, trials = 0;
#ifdef WILC_SDIO
	uint32_t u32WakeupReg = 0xf0;
	uint32_t u32ClkStsReg = 0xf0;
	uint32_t u32WakepBit = BIT0;
	uint32_t u32ClkStsBit = BIT4;
#else
	uint32_t u32WakeupReg = 0x1;
	uint32_t u32ClkStsReg = 0x13;
	uint32_t u32WakepBit = BIT1;
	uint32_t u32ClkStsBit = BIT2;
#endif /* WILC_SDIO */

	int wake_seq_trials = 5;

	if(pwr_dev.bus_registered[source] != true){
		PRINT_ER("Wakeup request for source that didn't register bus!");
		return;
	}

	pwr_dev.hif_func.hif_read_reg(u32WakeupReg, &wakeup_reg_val);
	do {
		pwr_dev.hif_func.hif_write_reg(u32WakeupReg, wakeup_reg_val | u32WakepBit);
		/* Check the clock status */
		pwr_dev.hif_func.hif_read_reg(u32ClkStsReg, &clk_status_reg_val);

		/*
		 * in case of clocks off, wait 2ms, and check it again.
		 * if still off, wait for another 2ms, for a total wait of 6ms.
		 * If still off, redo the wake up sequence
		 */
		while (((clk_status_reg_val & u32ClkStsBit) == 0) &&
		       (((++trials) % 3) == 0)) {
			/* Wait for the chip to stabilize*/
			usleep_range(1000, 1000);

			/*
			 * Make sure chip is awake. This is an extra step that can be removed
			 * later to avoid the bus access overhead
			 * g_wlan.hif_func.hif_read_reg(0xf0, &clk_status_reg_val);
			 */
			pwr_dev.hif_func.hif_read_reg(u32ClkStsReg,
						      &clk_status_reg_val);

			if ((clk_status_reg_val & u32ClkStsBit) == 0)
				PRINT_ER("clocks still OFF. Wake up failed\n");
		}
		/* in case of failure, Reset the wakeup bit to introduce a new edge on the next loop */
		if ((clk_status_reg_val & u32ClkStsBit) == 0)
			pwr_dev.hif_func.hif_write_reg(u32WakeupReg,
					     wakeup_reg_val & (~u32WakepBit));
	} while (((clk_status_reg_val & u32ClkStsBit) == 0)
		 && (wake_seq_trials-- > 0));


	pwr_dev.keep_awake[source] = true;
}

void acquire_bus(enum BUS_ACQUIRE acquire, int source)
{
	mutex_lock(&pwr_dev.hif_cs);

	if (acquire == ACQUIRE_AND_WAKEUP)
		chip_wakeup(source);
	
}
EXPORT_SYMBOL(acquire_bus);

void release_bus(enum BUS_RELEASE release, int source)
{
	if (release == RELEASE_ALLOW_SLEEP)
		chip_allow_sleep(source);

	if (mutex_is_locked(&pwr_dev.hif_cs))
		mutex_unlock(&pwr_dev.hif_cs);
}
EXPORT_SYMBOL(release_bus);

 #if defined(SAMA5D4_BOARD)
 extern void atmci_rescan_card(unsigned id,unsigned insert);
 #define WILC_SDIO_CARD_ID	0
 #define _linux_wlan_device_detection()		atmci_rescan_card(WILC_SDIO_CARD_ID,1)
 #define _linux_wlan_device_removal()		atmci_rescan_card(WILC_SDIO_CARD_ID,0)
 #define _linux_wlan_device_power_on()		wifi_pm_power(1)
 #define _linux_wlan_device_power_off()		wifi_pm_power(0) 
 #elif defined(PANDA_BOARD)
 #define _linux_wlan_device_detection()		mmc_start_host(mmc_host_backup[2])
 #define _linux_wlan_device_removal()		mmc_stop_host(mmc_host_backup[2])
 #define _linux_wlan_device_power_on()		{}
 #define _linux_wlan_device_power_off()		{} 
 #elif defined(PLAT_ALLWINNER_A31)
 extern void sw_mci_rescan_card(unsigned id, unsigned insert);

 #define ATWILC_SDIO_CARD_ID	1
 #define _linux_wlan_device_power_on()          wifi_pm_power(1)
 #define _linux_wlan_device_power_off()         wifi_pm_power(0)
 #define _linux_wlan_device_detection()         sw_mci_rescan_card(ATWILC_SDIO_CARD_ID,1)
 #define _linux_wlan_device_removal()           sw_mci_rescan_card(ATWILC_SDIO_CARD_ID,0)
#endif


#if (0)
void wifi_pm_power(int power)
{

	PRINT_D(INIT_DBG, "wifi_pm : %d \n", power);
	if (gpio_request(GPIO_NUM_CHIP_EN, "CHIP_EN") == 0 && gpio_request(GPIO_NUM_RESET, "RESET") == 0)
	{
		gpio_direction_output(GPIO_NUM_CHIP_EN, 0);
		gpio_direction_output(GPIO_NUM_RESET, 0);
		if (power)
		{
			gpio_set_value(GPIO_NUM_CHIP_EN , 1);
			mdelay(5);
			gpio_set_value(GPIO_NUM_RESET , 1);
		}
		else
		{
			gpio_set_value(GPIO_NUM_RESET , 0);
			gpio_set_value(GPIO_NUM_CHIP_EN , 0);
		}
		gpio_free(GPIO_NUM_CHIP_EN);
		gpio_free(GPIO_NUM_RESET);
	}
}
#else
void wifi_pm_power(int power)
{
	PRINT_D(INIT_DBG, "wifi_pm : %d \n", power);
	
	if (reset_gpio > 0 && chip_en_gpio > 0) {
	
	   gpio_direction_output(reset_gpio, 0);
	   gpio_direction_output(chip_en_gpio, 0);
	   msleep(100);

	   if (power) {
		   gpio_set_value_cansleep(chip_en_gpio, 1);
		   msleep(5);
		   gpio_set_value_cansleep(reset_gpio, 1);
	   } else {
		   gpio_set_value_cansleep(chip_en_gpio, 0);
		   gpio_set_value_cansleep(reset_gpio, 0);
	   }
	} else printk("Can't enable wifi; chip_en and/or reset gpio not assigned\n");
	
}
#endif

static int linux_wlan_device_power(int on_off)
{
    PRINT_D(INIT_DBG,"linux_wlan_device_power.. (%d)\n", on_off);

    if ( on_off )
    {
        _linux_wlan_device_power_on();
    }
    else
    {
        _linux_wlan_device_power_off();
    }

    return 0;
}

static int linux_wlan_device_detection(int on_off)
{
    PRINT_D(INIT_DBG,"linux_wlan_device_detection.. (%d)\n", on_off);

#ifdef WILC_SDIO
    if ( on_off )
        _linux_wlan_device_detection();
    else
        _linux_wlan_device_removal();
#endif

    return 0;
}

int at_pwr_power_up(int source)
{
	int count=0;
	int ret;
	int reg;
	
	mutex_lock(&pwr_dev.cs);

	PRINT_D(PWRDEV_DBG, "source: %s, current bus status Wifi: %d, BT: %d\n",
		 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"),
		 pwr_dev.power_status[PWR_DEV_SRC_WIFI],
		 pwr_dev.power_status[PWR_DEV_SRC_BT]);

	if (pwr_dev.power_status[source] == true) {
		PRINT_ER("power up request for already powered up source %s\n",
			 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
		}
	else
	{
		/*Bug 215*/
		/*Avoid overlapping between BT and Wifi intialization*/
		if((pwr_dev.power_status[PWR_DEV_SRC_WIFI]==true))
		{
			while(!pf_is_wilc3000_initalized())
			{
				msleep(100);
				if(++count>20)
				{
					PRINT_D(GENERIC_DBG,"Error: Wifi has taken too much time to initialize \n");
					break;
				}
			}
		}
		else if((pwr_dev.power_status[PWR_DEV_SRC_BT]==true))
		{
			while(!bt_init_done)
			{
				msleep(200);
				if(++count>30)
				{
					PRINT_D(GENERIC_DBG,"Error: BT has taken too much time to initialize \n");
					break;
				}
			}
			/*An additional wait to give BT firmware time to do CPLL update as the time 
			measured since the start of BT Fw till the end of function "rf_nmi_init_tuner" was 71.2 ms */	
			msleep(100);
		}
	}

	if ((pwr_dev.power_status[PWR_DEV_SRC_WIFI] == true) ||
		   (pwr_dev.power_status[PWR_DEV_SRC_BT] == true)) {
		PRINT_WRN(PWRDEV_DBG, "Device already up. request source is %s\n",
			 (source == PWR_DEV_SRC_WIFI ? "Wifi" : "BT"));
	} else {
		PRINT_D(PWRDEV_DBG, "WILC POWER UP\n");
		linux_wlan_device_power(0);
		linux_wlan_device_power(1);
		msleep(100);
	}
	pwr_dev.power_status[source] = true;
	mutex_unlock(&pwr_dev.cs);

	if(source == PWR_DEV_SRC_BT)
	{			
		ret = at_pwr_register_bus(PWR_DEV_SRC_BT);
		if(ret != 0){
			goto _fail_2; 
		}

		/*TicketId1092*/
		/*If WiFi is off, force BT*/
		if(pwr_dev.power_status[PWR_DEV_SRC_WIFI] == false)
		{
			if(pwr_dev.bus_registered[PWR_DEV_SRC_BT] == true)
			{		
				acquire_bus(ACQUIRE_AND_WAKEUP,PWR_DEV_SRC_BT);
			
				ret = pwr_dev.hif_func.hif_read_reg(rCOEXIST_CTL, &reg);
				if (!ret) {
					PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOEXIST_CTL);
					goto _fail_3;
				}
				/*Force BT*/
				reg |= BIT0 | BIT9;
				reg &= ~BIT11;
				ret = pwr_dev.hif_func.hif_write_reg(rCOEXIST_CTL, reg);
				if (!ret) {
					PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOEXIST_CTL);
					goto _fail_3;
				}

				/*TicketId1115*/
				/*Disable awake coex null frames*/
				ret = pwr_dev.hif_func.hif_read_reg(rCOE_AUTO_PS_ON_NULL_PKT, &reg);
				if (!ret) {
					PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOE_AUTO_PS_ON_NULL_PKT);
					goto _fail_3;
				}
				reg &= ~BIT30;
				ret = pwr_dev.hif_func.hif_write_reg(rCOE_AUTO_PS_ON_NULL_PKT, reg);
				if (!ret) {
					PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOE_AUTO_PS_ON_NULL_PKT);
					goto _fail_3;
				}

				/*TicketId1115*/
				/*Disable doze coex null frames*/
				ret = pwr_dev.hif_func.hif_read_reg(rCOE_AUTO_PS_OFF_NULL_PKT, &reg);
				if (!ret) {
					PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOE_AUTO_PS_OFF_NULL_PKT);
					goto _fail_3;
				}
				reg &= ~BIT30;
				ret = pwr_dev.hif_func.hif_write_reg(rCOE_AUTO_PS_OFF_NULL_PKT, reg);
				if (!ret) {
					PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOE_AUTO_PS_OFF_NULL_PKT);
					goto _fail_3;
				}
				
				release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);	
			}
		}

		// Enable BT wakeup
		acquire_bus(ACQUIRE_AND_WAKEUP, PWR_DEV_SRC_BT);

		ret = pwr_dev.hif_func.hif_read_reg(rPWR_SEQ_MISC_CTRL, &reg);
		if (!ret) {
			PRINT_ER( "[wilc start]: fail read reg %x ...\n", rPWR_SEQ_MISC_CTRL);
			goto _fail_3;
		}
		reg |= BIT29;
		ret = pwr_dev.hif_func.hif_write_reg(rPWR_SEQ_MISC_CTRL, reg);
		if (!ret) {
			PRINT_ER( "[wilc start]: fail write reg %x ...\n", rPWR_SEQ_MISC_CTRL);
			goto _fail_3;
		}

		release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);

		at_pwr_unregister_bus(PWR_DEV_SRC_BT);
	}

	return 0;

_fail_3:
	release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
	at_pwr_unregister_bus(PWR_DEV_SRC_BT);
_fail_2:
	at_pwr_power_down(PWR_DEV_SRC_BT);
	return ret;
}

EXPORT_SYMBOL(at_pwr_power_up);

int wilc_bt_firmware_download(void)
{
	uint32_t offset;
	uint32_t addr, size, size2, blksz;
	uint8_t *dma_buffer;
	int ret = 0;
	uint32_t reg;
	const struct firmware *wilc_bt_firmware;
	const u8 *buffer;
	size_t buffer_size;

#ifdef DOWNLOAD_BT_FW_ONCE
	mutex_lock(&pwr_dev.cs);
	if (pwr_dev.is_bt_fw_ready == true) {
		PRINT_WRN(PWRDEV_DBG, "BT FW already downloaded. Skip!\n");
		mutex_unlock(&pwr_dev.cs);
		return 0;
	}
	mutex_unlock(&pwr_dev.cs);
#endif /* DOWNLOAD_BT_FW_ONCE */

	ret = at_pwr_register_bus(PWR_DEV_SRC_BT);
	if(ret != 0)
	{
		return ret; 
	}

	PRINT_WRN(PWRDEV_DBG, "Bluetooth firmware: %s\n", BT_FIRMWARE);
#ifdef WILC_SDIO
	if (request_firmware(&wilc_bt_firmware, BT_FIRMWARE, dev) != 0) {
		PRINT_ER("%s - firmare not available. Skip!\n", BT_FIRMWARE);
		ret = -1;
		goto _fail_1;
	}
#else
	if (request_firmware(&wilc_bt_firmware, BT_FIRMWARE, dev) != 0) {
		PRINT_ER("%s - firmare not available. Skip!\n", BT_FIRMWARE);
		ret = -1;
		goto _fail_1;
	}
#endif /* WILC_SDIO */

	buffer = wilc_bt_firmware->data;
	buffer_size = (size_t)wilc_bt_firmware->size;
	if (buffer_size <= 0) {
		PRINT_ER("Firmware size = 0!\n");
		ret = -1;
		goto _fail_1;
	}
	acquire_bus(ACQUIRE_AND_WAKEUP, PWR_DEV_SRC_BT);

	ret = pwr_dev.hif_func.hif_write_reg(0x4f0000, 0x71);
	if (!ret) {
		PRINT_ER("[wilc start]: fail write reg 0x4f0000 ...\n");
			release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
	

		goto _fail_1;
	}

	/*
	 * Avoid booting from BT boot ROM. Make sure that Drive IRQN [SDIO platform]
	 * or SD_DAT3 [SPI platform] to ?1?
	 */
	/* Set cortus reset register to register control. */
	ret = pwr_dev.hif_func.hif_read_reg(0x3b0090, &reg);
	if (!ret) {
		PRINT_ER("[wilc start]: fail read reg 0x3b0090 ...\n");
	
			release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
	

		goto _fail_1;
	}
	reg |= (1 << 0);
	ret = pwr_dev.hif_func.hif_write_reg(0x3b0090, reg);
	if (!ret) {
		PRINT_ER("[wilc start]: fail write reg 0x3b0090 ...\n");

			release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
	
		goto _fail_1;
	}

	pwr_dev.hif_func.hif_read_reg(0x3B0400, &reg);

	if (reg & (1ul << 2)) {
		reg &= ~(1ul << 2);
	} else {
		reg |= (1ul << 2);
		pwr_dev.hif_func.hif_write_reg(0x3B0400, reg);
		reg &= ~(1ul << 2);
	}
	pwr_dev.hif_func.hif_write_reg(0x3B0400, reg);

		release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);


	/* blocks of sizes > 512 causes the wifi to hang! */
	blksz = (1ul << 9);
	/* Allocate a DMA coherent  buffer. */
	dma_buffer = kmalloc(blksz, GFP_KERNEL);
	if (dma_buffer == NULL) {
		ret = -5;
		PRINT_ER("Can't allocate buffer for BT firmware download IO error\n");
		goto _fail_1;
	}

	PRINT_D(PWRDEV_DBG, "Downloading BT firmware size = %d ...\n", buffer_size);
	/* load the firmware */

	offset = 0;
	addr = 0x400000;
	size = buffer_size;
#ifdef BIG_ENDIAN
	addr = BYTE_SWAP(addr);
	size = BYTE_SWAP(size);
#endif
	offset = 0;

	while (((int)size) && (offset < buffer_size)) {
		if (size <= blksz)
			size2 = size;
		else
			size2 = blksz;

		/* Copy firmware into a DMA coherent buffer */
		memcpy(dma_buffer, &buffer[offset], size2);

		acquire_bus(ACQUIRE_AND_WAKEUP, PWR_DEV_SRC_BT);

		ret = pwr_dev.hif_func.hif_block_tx(addr, dma_buffer, size2);

		release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);
	
		if (!ret)
			break;

		addr += size2;
		offset += size2;
		size -= size2;
	}

	if (!ret) {
		ret = -5;
		PRINT_ER("Can't download BT firmware IO error\n");
		goto _fail_;
	}
	PRINT_D(PWRDEV_DBG, "BT Offset = %d\n", offset);

#ifdef DOWNLOAD_BT_FW_ONCE
	mutex_lock(&pwr_dev.cs);
	pwr_dev.is_bt_fw_ready = true;
	mutex_unlock(&pwr_dev.cs);
#endif /* DOWNLOAD_BT_FW_ONCE */

_fail_:
	kfree(dma_buffer);
_fail_1:

	/* Freeing FW buffer */
	PRINT_D(PWRDEV_DBG, "Freeing BT FW buffer ...\n");
	PRINT_D(PWRDEV_DBG, "Releasing BT firmware\n");
	release_firmware(wilc_bt_firmware);

	if (ret >= 0)
		PRINT_D(PWRDEV_DBG, "BT Download Succeeded\n");

	at_pwr_unregister_bus(PWR_DEV_SRC_BT);

	return (ret < 0) ? ret : 0;
}
EXPORT_SYMBOL(wilc_bt_firmware_download);

int wilc_bt_start(void)
{
	uint32_t val32 = 0;
	int ret = 0;
	int reg = 0;

	ret = at_pwr_register_bus(PWR_DEV_SRC_BT);
	if(ret != 0)
	{
		return ret; 
	}

	acquire_bus(ACQUIRE_AND_WAKEUP, PWR_DEV_SRC_BT);

	if(pwr_dev.power_status[PWR_DEV_SRC_WIFI] == true)
	{
		/*If WiFi is on, send config packet to change coex mode and coex null frames transmission*/
#ifdef WILC_BT_COEXISTENCE	
		ret = pwr_dev.hif_func.hif_read_reg(rCOEXIST_CTL, &reg);
		if (!ret) {
			PRINT_ER("[wilc start]: fail read reg %x ...\n", rCOEXIST_CTL);
			goto _fail_1;
		}
		/*Coex ON*/
		reg |= BIT0;
		reg &= ~(BIT9|BIT11);
		ret = pwr_dev.hif_func.hif_write_reg(rCOEXIST_CTL, reg);
		if (!ret) {
			PRINT_ER( "[wilc start]: fail write reg %x ...\n", rCOEXIST_CTL);
			goto _fail_1;
		}
#endif /*WILC_BT_COEXISTENCE*/
	}

	PRINT_D(PWRDEV_DBG, "Starting BT firmware\n");

	/*
	 * Write the firmware download complete magic value 0x10ADD09E at 
	 * location 0xFFFF000C (Cortus map) or C000C (AHB map).
	 * This will let the boot-rom code execute from RAM.
	 */
	pwr_dev.hif_func.hif_write_reg(0x4F000c, 0x10add09e);


	pwr_dev.hif_func.hif_read_reg(0x3B0400, &val32);
	val32 &= ~((1ul << 2) | (1ul << 3));
	pwr_dev.hif_func.hif_write_reg(0x3B0400, val32);

	msleep(100);

	val32 |= ((1ul << 2) | (1ul << 3));

	pwr_dev.hif_func.hif_write_reg(0x3B0400, val32);

	PRINT_D(PWRDEV_DBG, "BT Start Succeeded\n");

_fail_1:
	release_bus(RELEASE_ALLOW_SLEEP, PWR_DEV_SRC_BT);

	at_pwr_unregister_bus(PWR_DEV_SRC_BT);

	return (ret < 0) ? ret : 0;
}
EXPORT_SYMBOL(wilc_bt_start);



void (*pf_chip_sleep_manually)(unsigned int , int )=NULL;
int (*pf_get_num_conn_ifcs)(void)=NULL;
void (*pf_host_wakeup_notify)(int)=NULL;
void (*pf_host_sleep_notify)(int)=NULL;
int (*pf_get_u8SuspendOnEvent_value)(void)=NULL;

void set_pf_chip_sleep_manually(void (*chip_sleep_manually_address)(unsigned int , int ))
{
	pf_chip_sleep_manually=chip_sleep_manually_address;
}
EXPORT_SYMBOL(set_pf_chip_sleep_manually);

void set_pf_get_num_conn_ifcs(int (*get_num_conn_ifcs_address)(void))
{
	pf_get_num_conn_ifcs=get_num_conn_ifcs_address;
}
EXPORT_SYMBOL(set_pf_get_num_conn_ifcs);

void set_pf_host_wakeup_notify(void (*host_wakeup_notify_address)( int ))
{
	pf_host_wakeup_notify=host_wakeup_notify_address;
}
EXPORT_SYMBOL(set_pf_host_wakeup_notify);

void set_pf_host_sleep_notify(void (*host_sleep_notify_address)( int ))
{
	pf_host_sleep_notify=host_sleep_notify_address;
}
EXPORT_SYMBOL(set_pf_host_sleep_notify);

void set_pf_get_u8SuspendOnEvent_value(int (*get_u8SuspendOnEvent_val)(void))
{
	pf_get_u8SuspendOnEvent_value=get_u8SuspendOnEvent_val;
}
EXPORT_SYMBOL(set_pf_get_u8SuspendOnEvent_value);

void set_pf_is_wilc3000_initalized(int (*is_wilc3000_initalized_address)( void ))
{
	pf_is_wilc3000_initalized=is_wilc3000_initalized_address;
	
}
EXPORT_SYMBOL(set_pf_is_wilc3000_initalized);

module_init(at_pwr_dev_init);
module_exit(at_pwr_dev_deinit);

MODULE_LICENSE("GPL");

