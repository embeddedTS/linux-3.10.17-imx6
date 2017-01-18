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

#ifndef NM_WFI_CFGOPERATIONS
#define NM_WFI_CFGOPERATIONS

#include "wilc_wfi_netdevice.h"

extern u8 g_wilc_initialized;
extern int connecting;
extern struct timer_list hEAPFrameBuffTimer;

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
extern struct timer_list hDuringIpTimer;
#endif

/*
 * The following macros describe the bitfield map
 * used by the firmware to determine its 11i mode
 */
#define NO_ENCRYPT			0
#define ENCRYPT_ENABLED			(1 << 0)
#define WEP				(1 << 1)
#define WEP_EXTENDED			(1 << 2)
#define WPA				(1 << 3)
#define WPA2				(1 << 4)
#define AES				(1 << 5)
#define TKIP				(1 << 6)

#ifdef WILC_P2P
/*Public action frame index IDs*/
#define   FRAME_TYPE_ID			0
#define   ACTION_CAT_ID			24
#define   ACTION_SUBTYPE_ID		25
#define   P2P_PUB_ACTION_SUBTYPE	30

/*Public action frame Attribute IDs*/
#define	ACTION_FRAME			0xd0
#define	GO_INTENT_ATTR_ID		0x04
#define	CHANLIST_ATTR_ID		0x0b
#define	OPERCHAN_ATTR_ID		0x11
#ifdef	USE_SUPPLICANT_GO_INTENT
#define	GROUP_BSSID_ATTR_ID		0x07
#endif
#define	PUB_ACTION_ATTR_ID		0x04
#define P2PELEM_ATTR_ID			0xdd

/*Public action subtype values*/
#define	GO_NEG_REQ			0x00
#define	GO_NEG_RSP			0x01
#define	GO_NEG_CONF			0x02
#define P2P_INV_REQ			0x03
#define P2P_INV_RSP			0x04
#define	PUBLIC_ACT_VENDORSPEC		0x09
#define GAS_INTIAL_REQ			0x0a
#define GAS_INTIAL_RSP			0x0b

#define	INVALID_CHANNEL			0
#ifdef	USE_SUPPLICANT_GO_INTENT
#define	SUPPLICANT_GO_INTENT		6
#define	GET_GO_INTENT(a)		(((a) >> 1) & 0x0f)
#define	GET_TIE_BREAKER(a)		(((a)) & 0x01)
#else
#endif
#endif

#define nl80211_SCAN_RESULT_EXPIRE	(3 * HZ)
#define SCAN_RESULT_EXPIRE		(40 * HZ)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
static const u32 cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
static const struct ieee80211_txrx_stypes
	wilc_wfi_cfg80211_mgmt_types[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
	},
	[NL80211_IFTYPE_AP] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_DISASSOC >> 4) |
			BIT(IEEE80211_STYPE_AUTH >> 4) |
			BIT(IEEE80211_STYPE_DEAUTH >> 4) |
			BIT(IEEE80211_STYPE_ACTION >> 4)
	},
	[NL80211_IFTYPE_P2P_CLIENT] = {
		.tx = 0xffff,
		.rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			BIT(IEEE80211_STYPE_DISASSOC >> 4) |
			BIT(IEEE80211_STYPE_AUTH >> 4) |
			BIT(IEEE80211_STYPE_DEAUTH >> 4)
	}
};
#endif
/* Time to stay on the channel */
#define WILC_WFI_DWELL_PASSIVE	100
#define WILC_WFI_DWELL_ACTIVE	40

struct wireless_dev *WILC_WFI_CfgAlloc(void);
struct wireless_dev *WILC_WFI_WiphyRegister(struct net_device *net);
void WILC_WFI_WiphyFree(struct net_device *net);
int WILC_WFI_update_stats(struct wiphy *wiphy, u32 pktlen, u8 changed);
int WILC_WFI_DeInitHostInt(struct net_device *net);
int WILC_WFI_InitHostInt(struct net_device *net);
int WILC_WFI_deinit_mon_interface(void);
struct net_device *WILC_WFI_init_mon_interface(const char *name,
					       struct net_device *real_dev);
void WILC_WFI_p2p_rx(struct net_device *dev, uint8_t *buff, uint32_t size);

#ifdef TCP_ENHANCEMENTS
#define TCP_ACK_FILTER_LINK_SPEED_THRESH	54
#define DEFAULT_LINK_SPEED			72
void Enable_TCP_ACK_Filter(bool value);
#endif
int	WILC_WFI_get_u8SuspendOnEvent_value(void);
#endif
