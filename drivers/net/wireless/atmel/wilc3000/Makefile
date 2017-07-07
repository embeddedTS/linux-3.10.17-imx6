obj-$(CONFIG_WILC3000) += at_pwr_dev.o
obj-$(CONFIG_WILC3000) += wilc3000.o

ccflags-$(CONFIG_WILC3000_DEBUG) += -DDEBUG
ccflags-$(CONFIG_WILC3000_SDIO) += -DWILC_SDIO -DRESCAN_SDIO
ccflags-$(CONFIG_WILC3000_SPI) += -DWILC_SPI
ccflags-$(CONFIG_WILC3000_HW_OOB_INTR) += -DWILC_SDIO_IRQ_GPIO

ccflags-y += -I$(src)/ -DEXPORT_SYMTAB  -D__CHECK_ENDIAN__ -Wno-unused-function

ccflags-y += -DCONNECT_DIRECT -DWILC_PARSE_SCAN_IN_HOST
ccflags-y += -DAGING_ALG -DDISABLE_PWRSAVE_AND_SCAN_DURING_IP -DHW_HAS_EFUSED_MAC_ADDR
ccflags-y += -DTCP_ACK_FILTER -DTCP_ENHANCEMENTS
ccflags-y += -DWILC_BT_COEXISTENCE

ccflags-y += -DWILC_SLEEP_CLK_SRC_RTC
ccflags-y += -DSAMA5D4_BOARD
#EXTRA_CFLAGS += -DANT_SWTCH_SNGL_GPIO_CTRL
#EXTRA_CFLAGS += -DANT_SWTCH_DUAL_GPIO_CTRL
#EXTRA_CFLAGS += -DANT_1_GPIO_NUM=4
#EXTRA_CFLAGS += -DANT_2_GPIO_NUM=20

wilc3000-y += wilc_wfi_cfgoperations.o
wilc3000-y += wilc_wlan.o
wilc3000-y += wilc_wlan_cfg.o
wilc3000-y += coreconfigurator.o
wilc3000-y += host_interface.o
wilc3000-y += linux_mon.o
wilc3000-y += linux_wlan.o

at_pwr_dev-y += at_pwr_dev_main.o
at_pwr_dev-y += wilc_msgqueue.o
at_pwr_dev-y += wilc_sdio.o
at_pwr_dev-y += wilc_spi.o
at_pwr_dev-$(CONFIG_WILC3000_SDIO) += linux_wlan_sdio.o
at_pwr_dev-$(CONFIG_WILC3000_SPI) += linux_wlan_spi.o
