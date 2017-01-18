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

#ifndef WILC_WFI_NETDEVICE
#define WILC_WFI_NETDEVICE

/* These are the flags in the statusword */
#define WILC_WFI_RX_INTR 0x0001
#define WILC_WFI_TX_INTR 0x0002

/*
 * Default timeout period in Jiffies
 */
#define WILC_WFI_TIMEOUT	5

#define WILC_MAX_NUM_PMKIDS  16
#define PMKID_LEN		16
#define PMKID_FOUND		1
#define NUM_STA_ASSOCIATED	8

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>
#include <linux/if_arp.h>
#include <linux/in6.h>
#include <asm/checksum.h>
#include "host_interface.h"
#include "wilc_wlan.h"
#include "wilc_wlan_if.h"
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,30)
#include <net/wireless.h>
#else
#include <linux/wireless.h>
#endif

#define FLOW_CONTROL_LOWER_THRESHOLD	128
#define FLOW_CONTROL_UPPER_THRESHOLD	256

enum stats_flags {
	WILC_WFI_RX_PKT = 1 << 0,
	WILC_WFI_TX_PKT = 1 << 1,
};

struct WILC_WFI_stats {
	unsigned long rx_packets;
	unsigned long tx_packets;
	unsigned long rx_bytes;
	unsigned long tx_bytes;
	u64 rx_time;
	u64 tx_time;
};

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
#define RX_BH_KTHREAD		0
#define RX_BH_WORK_QUEUE	1
#define RX_BH_THREADED_IRQ	2

#define num_reg_frame		2
/*
 * If you use RX_BH_WORK_QUEUE on LPC3131: You may lose the first interrupt on
 * LPC3131 which is important to get the MAC start status when you are blocked
 * inside linux_wlan_firmware_download() which blocks mac_open().
 */
#define RX_BH_TYPE		RX_BH_THREADED_IRQ

struct wilc_wfi_key {
	u8 *key;
	u8 *seq;
	int key_len;
	int seq_len;
	u32 cipher;
};

struct wilc_wfi_wep_key {
	u8 *key;
	u8 key_len;
	u8 key_idx;
};

struct sta_info {
	u8 au8Sta_AssociatedBss[MAX_NUM_STA][ETH_ALEN];
};

#ifdef WILC_P2P
/*
 * Parameters needed for host interface
 * for remaining on channel
 */
struct wilc_wfi_p2pListenParams {
	struct ieee80211_channel *pstrListenChan;
	enum nl80211_channel_type tenuChannelType;
	u32 u32ListenDuration;
	unsigned long long u64ListenCookie;
	u32 u32ListenSessionID;
};
#endif  /*WILC_P2P*/

/* Struct to buffer eapol 1/4 frame */
struct wilc_buffered_eap {
	unsigned int u32Size;
	unsigned int u32PktOffset;
	u8 *pu8buff;
};

struct WILC_WFI_priv {
	struct wireless_dev *wdev;
	struct cfg80211_scan_request *pstrScanReq;
#ifdef WILC_P2P
	struct wilc_wfi_p2pListenParams strRemainOnChanParams;
	unsigned long long u64tx_cookie;
#endif
	bool bCfgScanning;
	u32 u32RcvdChCount;
	u8 au8AssociatedBss[ETH_ALEN];
	struct sta_info assoc_stainfo;
	struct net_device_stats stats;
	u8 monitor_flag;
	int status;
	struct WILC_WFI_packet *ppool;
	struct WILC_WFI_packet *rx_queue; /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
	struct WFIDrvHandle *hWILCWFIDrv;
	struct WFIDrvHandle *hWILCWFIDrv_2;
	struct tstrHostIFpmkidAttr pmkid_list;
	struct WILC_WFI_stats netstats;
	u8 WILC_WFI_wep_default;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#define WLAN_KEY_LEN_WEP104 13
#endif
	u8 WILC_WFI_wep_key[4][WLAN_KEY_LEN_WEP104];
	u8 WILC_WFI_wep_key_len[4];
	/* the real interface that the monitor is on  */
	struct net_device *real_ndev;
	struct wilc_wfi_key *wilc_gtk[MAX_NUM_STA];
	struct wilc_wfi_key *wilc_ptk[MAX_NUM_STA];
	u8 wilc_groupkey;
	/* semaphores */
	struct semaphore SemHandleUpdateStats;
	struct semaphore hSemScanReq;
	bool gbAutoRateAdjusted;
	bool bInP2PlistenState;
	struct wilc_buffered_eap *pStrBufferedEAP;
};

struct frame_reg {
	u16 frame_type;
	bool reg;
};

struct InterfaceInfo {
	uint8_t aSrcAddress[ETH_ALEN];
	uint8_t aBSSID[ETH_ALEN];
	uint32_t drvHandler;
	uint8_t u8IfcType;
	struct net_device *wilc_netdev;
};

struct linux_wlan {
	int mac_status;
	int wilc_initialized;
	u16 dev_irq_num;
	struct wilc_wlan_oup oup;
	int close;
	uint8_t u8NoIfcs;
	struct InterfaceInfo strInterfaceInfo[NUM_CONCURRENT_IFC];
	uint8_t open_ifcs;
	struct mutex txq_cs;
	struct semaphore txq_add_to_head_cs;
	spinlock_t txq_spinlock;
	struct mutex rxq_cs;
	struct mutex *hif_cs;
	struct semaphore rxq_event;
	struct semaphore cfg_event;
	struct semaphore sync_event;
	struct semaphore txq_event;
#if (RX_BH_TYPE == RX_BH_WORK_QUEUE)
	struct work_struct rx_work_queue;
#elif (RX_BH_TYPE == RX_BH_KTHREAD)
	struct task_struct *rx_bh_thread;
	struct semaphore rx_sem;
#endif
	struct semaphore rxq_thread_started;
	struct semaphore txq_thread_started;
	struct semaphore wdt_thread_sem;
	struct task_struct *rxq_thread;
	struct task_struct *txq_thread;
	struct task_struct *wdt_thread;
	u8 eth_src_address[NUM_CONCURRENT_IFC][6];
	const struct firmware *wilc_firmware;
#ifdef DOWNLOAD_BT_FW
	const struct firmware *wilc_bt_firmware;
#endif
	struct net_device *real_ndev;
#ifdef WILC_SDIO
	int already_claim;
	struct sdio_func *wilc_sdio_func;
#else
	struct spi_device *wilc_spidev;
#endif
};

struct perInterface_wlan {
	uint8_t u8IfIdx;
	u8 iftype;
	int monitor_flag;
	int mac_opened;
#ifdef WILC_P2P
	struct frame_reg g_struct_frame_reg[num_reg_frame];
#endif
	struct net_device *wilc_netdev;
	struct net_device_stats netstats;
};

struct WILC_WFI_mon_priv {
	struct net_device *real_ndev;
};
#endif
