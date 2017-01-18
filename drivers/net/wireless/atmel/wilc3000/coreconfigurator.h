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

#ifndef CORECONFIGURATOR_H
#define CORECONFIGURATOR_H

#include "wilc_errorsupport.h"
#include "wilc_wlan_if.h"
#include <linux/kthread.h>
#include <linux/semaphore.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/version.h>
#include "linux/string.h"

/* Number of WID Options Supported */
#define NUM_BASIC_SWITCHES	45
#define NUM_FHSS_SWITCHES	0
#define NUM_RSSI		5

#ifdef MAC_802_11N
#define NUM_11N_BASIC_SWITCHES	25
#define NUM_11N_HUT_SWITCHES	47
#else /* MAC_802_11N */
#define NUM_11N_BASIC_SWITCHES	0
#define NUM_11N_HUT_SWITCHES	0
#endif /* MAC_802_11N */

/* No Address4 - non-ESS*/
#define MAC_HDR_LEN		24
#define MAX_SSID_LEN		33
#define FCS_LEN			4
#define TIME_STAMP_LEN		8
#define BEACON_INTERVAL_LEN	2
#define CAP_INFO_LEN		2
#define STATUS_CODE_LEN		2
#define AID_LEN			2
#define IE_HDR_LEN		2
/* Operating Mode: SET */
#define SET_CFG			0
/* Operating Mode: GET */
#define GET_CFG			1

#define MAX_PACKET_BUFF_SIZE	1596

#define MAX_STRING_LEN			256
#define MAX_SURVEY_RESULT_FRAG_SIZE	MAX_STRING_LEN
#define SURVEY_RESULT_LENGTH		44
#define MAX_ASSOC_RESP_FRAME_SIZE	MAX_STRING_LEN
#define STATUS_MSG_LEN			12
#define MAC_CONNECTED			1
#define MAC_DISCONNECTED		0
#define MAKE_WORD16(lsb, msb) ((((u16)(msb) << 8) & 0xFF00) | (lsb))
#define MAKE_WORD32(lsw, msw) ((((u32)(msw) << 16) & 0xFFFF0000) \
			      | (lsw))

extern uint32_t cfg_timed_out_cnt;

/* Frame Type and Subtype Codes (6-bit) */
enum tenuFrmSubtype {
	ASSOC_REQ	      = 0x00,
	ASSOC_RSP	      = 0x10,
	REASSOC_REQ	      = 0x20,
	REASSOC_RSP	      = 0x30,
	PROBE_REQ	      = 0x40,
	PROBE_RSP	      = 0x50,
	BEACON		      = 0x80,
	ATIM		      = 0x90,
	DISASOC		      = 0xA0,
	AUTH		      = 0xB0,
	DEAUTH		      = 0xC0,
	ACTION		      = 0xD0,
	PS_POLL		      = 0xA4,
	RTS		      = 0xB4,
	CTS		      = 0xC4,
	ACK		      = 0xD4,
	CFEND		      = 0xE4,
	CFEND_ACK	      = 0xF4,
	DATA		      = 0x08,
	DATA_ACK	      = 0x18,
	DATA_POLL	      = 0x28,
	DATA_POLL_ACK	      = 0x38,
	NULL_FRAME	      = 0x48,
	CFACK		      = 0x58,
	CFPOLL		      = 0x68,
	CFPOLL_ACK	      = 0x78,
	QOS_DATA	      = 0x88,
	QOS_DATA_ACK	      = 0x98,
	QOS_DATA_POLL	      = 0xA8,
	QOS_DATA_POLL_ACK     = 0xB8,
	QOS_NULL_FRAME	      = 0xC8,
	QOS_CFPOLL	      = 0xE8,
	QOS_CFPOLL_ACK	      = 0xF8,
	BLOCKACK_REQ	      = 0x84,
	BLOCKACK	      = 0x94,
	FRAME_SUBTYPE_FORCE_32BIT  = 0xFFFFFFFF
};


/* Status Codes for Authentication and Association Frames */
enum tenuConnectSts {
	SUCCESSFUL_STATUSCODE		= 0,
	UNSPEC_FAIL			= 1,
	UNSUP_CAP			= 10,
	REASOC_NO_ASOC			= 11,
	FAIL_OTHER			= 12,
	UNSUPT_ALG			= 13,
	AUTH_SEQ_FAIL			= 14,
	CHLNG_FAIL			= 15,
	AUTH_TIMEOUT			= 16,
	AP_FULL				= 17,
	UNSUP_RATE			= 18,
	SHORT_PREAMBLE_UNSUP		= 19,
	PBCC_UNSUP			= 20,
	CHANNEL_AGIL_UNSUP		= 21,
	SHORT_SLOT_UNSUP		= 25,
	OFDM_DSSS_UNSUP			= 26,
	CONNECT_STS_FORCE_16_BIT	= 0xFFFF
};

struct tstrWID {
	u16 u16WIDid;
	enum tenuWIDtype enuWIDtype;
	s32 s32ValueSize;
	s8 *ps8WidVal;
};
struct tstrRSSI {
	u8 u8Full;
	u8 u8Index;
	s8 as8RSSI[NUM_RSSI];
};

/* This structure is used to support parsing of the received 'N' message */
struct tstrNetworkInfo {
	s8 s8rssi;
	u16 u16CapInfo;
	u8 au8ssid[MAX_SSID_LEN];
	u8 u8SsidLen;
	u8 au8bssid[6];
	u16 u16BeaconPeriod;
	u8 u8DtimPeriod;
	u8 u8channel;
	/*
	 * of type unsigned long to be accepted by the linux kernel
	 *macro time_after()
	 */
	unsigned long u32TimeRcvdInScanCached;
	unsigned long u32TimeRcvdInScan;
	bool bNewNetwork;
#ifdef AGING_ALG
	u8 u8Found;
#endif
#ifdef WILC_P2P
	u32 u32Tsf; /* time-stamp [Low only 32 bit] */
#endif
	u8 *pu8IEs;
	u16 u16IEsLen;
	void *pJoinParams;
	struct tstrRSSI strRssi;
	unsigned long long u64Tsf; /* time-stamp [Low and High 64 bit] */
};

/*
 * This structure is used to support parsing of the received Association
 * Response frame
 */
struct tstrConnectRespInfo {
	u16 u16capability;
	u16 u16ConnectStatus;
	u16 u16AssocID;
	u8 *pu8RespIEs;
	u16 u16RespIEsLen;
};

struct tstrConnectInfo {
	u8 au8bssid[6];
	u8 *pu8ReqIEs;
	size_t ReqIEsLen;
	u8 *pu8RespIEs;
	u16 u16RespIEsLen;
	u16 u16ConnectStatus;
};

struct tstrDisconnectNotifInfo {
	u16 u16reason;
	u8 *ie;
	size_t ie_len;
};

#ifndef CONNECT_DIRECT
struct wid_site_survey_reslts {
	char SSID[MAX_SSID_LEN];
	u8 BssType;
	u8 Channel;
	u8 SecurityStatus;
	u8 BSSID[6];
	char RxPower;
	u8 Reserved;
};
#endif /* CONNECT_DIRECT */

s32 CoreConfiguratorInit(void);
s32 CoreConfiguratorDeInit(void);
s32 SendConfigPkt(u8 u8Mode, struct tstrWID *pstrWIDs,
				u32 u32WIDsCount,
				bool bRespRequired,
				u32 drvHandler);
s32 ParseNetworkInfo(u8 *pu8MsgBuffer, struct tstrNetworkInfo **ppstrNetworkInfo);
s32 DeallocateNetworkInfo(struct tstrNetworkInfo *pstrNetworkInfo);
s32 ParseAssocRespInfo(u8 *pu8Buffer, u32 u32BufferLen,
				     struct tstrConnectRespInfo **ppstrConnectRespInfo);
s32 DeallocateAssocRespInfo(struct tstrConnectRespInfo *pstrConnectRespInfo);
#ifndef CONNECT_DIRECT
s32 ParseSurveyResults(u8 ppu8RcvdSiteSurveyResults[][MAX_SURVEY_RESULT_FRAG_SIZE],
				     struct wid_site_survey_reslts **ppstrSurveyResults,
				     u32 *pu32SurveyResultsCount);
s32 DeallocateSurveyResults(struct wid_site_survey_reslts *pstrSurveyResults);
#endif /* CONNECT_DIRECT */
s32 SendRawPacket(s8 *pspacket, s32 s32PacketLen);
void NetworkInfoReceived(u8 *pu8Buffer, u32 u32Length);
void GnrlAsyncInfoReceived(u8 *pu8Buffer, u32 u32Length);
void host_int_ScanCompleteReceived(u8 *pu8Buffer, u32 u32Length);
#endif /* CORECONFIGURATOR_H */
