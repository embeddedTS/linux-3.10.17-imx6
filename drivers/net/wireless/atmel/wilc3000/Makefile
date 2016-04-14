obj-$(CONFIG_WILC3000) += wilc3000.o

ccflags-$(CONFIG_WILC3000_DEBUG) += -DDEBUG
ccflags-$(CONFIG_WILC3000_SDIO) += -DWILC_SDIO
ccflags-$(CONFIG_WILC3000_SPI) += -DWILC_SPI
ccflags-$(CONFIG_WILC3000_HW_OOB_INTR) += -DWILC_SDIO_IRQ_GPIO

ccflags-y += -DCONNECT_DIRECT -DWILC_PARSE_SCAN_IN_HOST
ccflags-y += -DAGING_ALG -DDISABLE_PWRSAVE_AND_SCAN_DURING_IP -DHW_HAS_EFUSED_MAC_ADDR
ccflags-y += -Wno-unused-function
ccflags-y += -DWILC_BT_COEXISTENCE -DDOWNLOAD_BT_FW

wilc3000-y += atl_msg_queue.o
wilc3000-y += wilc_wfi_cfg_operations.o
wilc3000-y += wilc_wlan.o
wilc3000-y += wilc_wlan_cfg.o
wilc3000-y += core_configurator.o
wilc3000-y += host_interface.o
wilc3000-y += linux_mon.o
wilc3000-y += linux_wlan.o

obj-$(CONFIG_WILC3000) += at_pwr_dev.o

at_pwr_dev-y += at_pwr_dev_main.o
at_pwr_dev-y += wilc_sdio.o
at_pwr_dev-y += wilc_spi.o
at_pwr_dev-$(CONFIG_WILC3000_SDIO) += linux_wlan_sdio.o
at_pwr_dev-$(CONFIG_WILC3000_SPI) += linux_wlan_spi.o
