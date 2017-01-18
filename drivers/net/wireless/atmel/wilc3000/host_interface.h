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

#ifndef HOST_INT_H
#define HOST_INT_H

#include "coreconfigurator.h"

#define FAIL			0x0000
#define SUCCESS			0x0001
#define IP_ALEN			4
#define AP_MODE			0x01
#define STATION_MODE	0x02
#define GO_MODE			0x03
#define CLIENT_MODE		0x04

#define P2P_IFC		0x00
#define WLAN_IFC	0x01
#define DEFAULT_IFC		0x03

#define IFC_0 "wlan0"
#define IFC_1 "p2p0"

/*TicketId1092*/
#ifdef WILC_BT_COEXISTENCE
typedef enum{
	COEX_OFF = 0,
	COEX_ON, 		
	COEX_FORCE_WIFI,
	COEX_FORCE_BT,
} tenuCoexMode;

/*TicketId1115*/
typedef enum{
	COEX_NULL_FRAMES_OFF = 0,
	COEX_NULL_FRAMES_ON, 		
} tenuCoexNullFramesMode;
#endif /*WILC_BT_COEXISTENCE*/


#define MAX_NUM_STA                 9
#define ACTIVE_SCAN_TIME			10
#define PASSIVE_SCAN_TIME			1200
#define MIN_SCAN_TIME				10
#define MAX_SCAN_TIME				1200
#define DEFAULT_SCAN				0
#define USER_SCAN					BIT0
#define OBSS_PERIODIC_SCAN			BIT1
#define OBSS_ONETIME_SCAN			BIT2
#define GTK_RX_KEY_BUFF_LEN			24
#define ADDKEY						0x1
#define REMOVEKEY					0x2
#define DEFAULTKEY					0x4
#define ADDKEY_AP					0x8

#define MAX_NUM_SCANNED_NETWORKS	100 /* 30 */
#define MAX_NUM_SCANNED_NETWORKS_SHADOW	130
/*One more than the number of scanned ssids*/
#define MAX_NUM_PROBED_SSID		10
#define CHANNEL_SCAN_TIME		250 /* 250 */

#define TX_MIC_KEY_LEN		8
#define RX_MIC_KEY_LEN		8
#define PTK_KEY_LEN			16
#define TX_MIC_KEY_MSG_LEN	26
#define RX_MIC_KEY_MSG_LEN	48
#define PTK_KEY_MSG_LEN		39
#define PMKSA_KEY_LEN		22
#define ETH_ALEN			6
#define PMKID_LEN			16
#define WILC_MAX_NUM_PMKIDS	16
#define WILC_SUPP_MCS_SET_SIZE	16
/* Not including the rates field cause it has variable length*/
#define WILC_ADD_STA_LENGTH	40
#define SCAN_EVENT_DONE_ABORTED
#define NUM_CONCURRENT_IFC 2

#define WILC_MULTICAST_TABLE_SIZE	8

extern bool gbScanWhileConnected;
extern unsigned int gu8FlushedJoinReqDrvHandler;
extern u8 *gu8FlushedInfoElemAsoc;
extern u8 *gu8FlushedJoinReq;
extern u8 gau8MulticastMacAddrList[WILC_MULTICAST_TABLE_SIZE][ETH_ALEN];
extern u8 u8ConnectedSSID[6];

struct tstrStatistics {
	u8 u8LinkSpeed;
	s8 s8RSSI;
	unsigned int u32TxCount;
	unsigned int u32RxCount;
	unsigned int u32TxFailureCount;
};

enum tenuHostIFstate {
	HOST_IF_IDLE				= 0,
	HOST_IF_SCANNING			= 1,
	HOST_IF_CONNECTING			= 2,
	HOST_IF_WAITING_CONN_RESP	= 3,
	HOST_IF_CONNECTED			= 4,
	HOST_IF_P2P_LISTEN			= 5,
	HOST_IF_FORCE_32BIT			= 0xFFFFFFFF
};

struct tstrHostIFpmkid {
	u8 bssid[ETH_ALEN];
	u8 pmkid[PMKID_LEN];
};

struct tstrHostIFpmkidAttr {
	u8 numpmkid;
	struct tstrHostIFpmkid pmkidlist[WILC_MAX_NUM_PMKIDS];
};

enum CURRENT_TX_RATE_T {
	AUTORATE     = 0,
	MBPS_1       = 1,
	MBPS_2       = 2,
	MBPS_5_5     = 5,
	MBPS_11      = 11,
	MBPS_6       = 6,
	MBPS_9       = 9,
	MBPS_12      = 12,
	MBPS_18      = 18,
	MBPS_24      = 24,
	MBPS_36      = 36,
	MBPS_48      = 48,
	MBPS_54      = 54
};

struct tstrCfgParamVal {
	unsigned int u32SetCfgFlag;
	u8 ht_enable;
	u8 bss_type;
	u8 auth_type;
	u16 auth_timeout;
	u8 power_mgmt_mode;
	u16 short_retry_limit;
	u16 long_retry_limit;
	u16 frag_threshold;
	u16 rts_threshold;
	u16 preamble_type;
	u8 short_slot_allowed;
	u8 txop_prot_disabled;
	u16 beacon_interval;
	u16 dtim_period;
	enum SITE_SURVEY_E site_survey_enabled;
	u16 site_survey_scan_time;
	u8 scan_source;
	u16 active_scan_time;
	u16 passive_scan_time;
	enum CURRENT_TX_RATE_T curr_tx_rate;
};

enum tenuCfgParam {
	RETRY_SHORT		= 1 << 0,
	RETRY_LONG		= 1 << 1,
	FRAG_THRESHOLD		= 1 << 2,
	RTS_THRESHOLD		= 1 << 3,
	BSS_TYPE		= 1 << 4,
	AUTH_TYPE		= 1 << 5,
	AUTHEN_TIMEOUT		= 1 << 6,
	POWER_MANAGEMENT	= 1 << 7,
	PREAMBLE		= 1 << 8,
	SHORT_SLOT_ALLOWED	= 1 << 9,
	TXOP_PROT_DISABLE	= 1 << 10,
	BEACON_INTERVAL		= 1 << 11,
	DTIM_PERIOD		= 1 << 12,
	SITE_SURVEY		= 1 << 13,
	SITE_SURVEY_SCAN_TIME	= 1 << 14,
	ACTIVE_SCANTIME		= 1 << 15,
	PASSIVE_SCANTIME	= 1 << 16,
	CURRENT_TX_RATE		= 1 << 17,
	HT_ENABLE		= 1 << 18,
};

struct tstrFoundNetworkInfo {
	u8 au8bssid[6];
	s8 s8rssi;
};

enum tenuScanEvent {
	SCAN_EVENT_NETWORK_FOUND	= 0,
	SCAN_EVENT_DONE			= 1,
	SCAN_EVENT_ABORTED		= 2,
	SCAN_EVENT_FORCE_32BIT		= 0xFFFFFFFF
};

enum tenuConnDisconnEvent {
	CONN_DISCONN_EVENT_CONN_RESP		= 0,
	CONN_DISCONN_EVENT_DISCONN_NOTIF	= 1,
	CONN_DISCONN_EVENT_FORCE_32BIT		= 0xFFFFFFFF
};

enum tenuKeyType {
	WEP_Key,
	WPARxGtk,
	/* WPATxGtk, */
	WPAPtk,
	PMKSA,
};

/*Scan callBack function definition*/
typedef void (*tWILCpfScanResult)(enum tenuScanEvent, struct tstrNetworkInfo *,
				  void *, void *);

/*Connect callBack function definition*/
typedef void (*tWILCpfConnectResult)(enum tenuConnDisconnEvent,
				     struct tstrConnectInfo *,
				     u8,
				     struct tstrDisconnectNotifInfo *,
				     void *);

#ifdef WILC_P2P
/*Remain on channel expiration callback function*/
typedef void (*tWILCpfRemainOnChanExpired)(void *, unsigned int);
/*Remain on channel callback function*/
typedef void (*tWILCpfRemainOnChanReady)(void *);
#endif

typedef void (*tWILCpfFrmToLinux)(u8 *, unsigned int, unsigned int, u8);
typedef void (*tWILCpfFreeEAPBuffParams)(void *);

struct WFIDrvHandle {
	signed int s32Dummy;
};

/*
 * Structure to hold Received Asynchronous Network info
 */
struct tstrRcvdNetworkInfo {
	u8 *pu8Buffer;
	unsigned int u32Length;
};

struct tstrHiddenNetworkInfo {
	u8  *pu8ssid;
	u8 u8ssidlen;
};

struct tstrHiddenNetwork {
	/* MAX_SSID_LEN */
	struct tstrHiddenNetworkInfo *pstrHiddenNetworkInfo;
	u8 u8ssidnum;
};

struct tstrWILC_UsrScanReq {
	/* Scan user call back function */
	tWILCpfScanResult pfUserScanResult;

	/*
	 *User specific parameter to be delivered through the Scan User
	 * Callback function
	 */
	void *u32UserScanPvoid;

	unsigned int u32RcvdChCount;
	struct tstrFoundNetworkInfo astrFoundNetworkInfo[MAX_NUM_SCANNED_NETWORKS];
};

struct tstrWILC_UsrConnReq {
	u8 *pu8bssid;
	u8 *pu8ssid;
	u8 u8security;
	enum AUTHTYPE tenuAuth_type;
	size_t ssidLen;
	u8 *pu8ConnReqIEs;
	size_t ConnReqIEsLen;
	/* Connect user call back function */
	tWILCpfConnectResult pfUserConnectResult;
	bool IsHTCapable;
	/*
	 * User specific parameter to be delivered through the Connect User
	 * Callback function
	 */
	void *u32UserConnectPvoid;
};

struct tstrHostIfSetDrvHandler {
	unsigned int u32Address;
	u8	u8IfMode;
	u8	u8IfName;
};

struct tstrHostIfSetOperationMode {
	unsigned int u32Mode;
};

struct tstrHostIfSetMacAddress {
	u8 u8MacAddress[ETH_ALEN];
};

struct tstrHostIfGetMacAddress {
	u8 *u8MacAddress;
};

struct tstrHostIfBASessionInfo {
	u8 au8Bssid[ETH_ALEN];
	u8 u8Ted;
	u16 u16BufferSize;
	u16 u16SessionTimeout;
};

#ifdef WILC_P2P
struct tstrHostIfRemainOnChan {
	u16 u16Channel;
	unsigned int u32duration;
	tWILCpfRemainOnChanExpired pRemainOnChanExpired;
	tWILCpfRemainOnChanReady pRemainOnChanReady;
	void *pVoid;
	unsigned int u32ListenSessionID;
};

struct tstrHostIfRegisterFrame {
	bool bReg;
	u16 u16FrameType;
	u8 u8Regid;
};

#define   ACTION_FRM_IDX	0
#define   PROBE_REQ_IDX		1

enum p2p_listen_state {
	P2P_IDLE,
	P2P_LISTEN,
	P2P_GRP_FORMATION
};
#endif /* WILC_P2P */

struct WILC_WFIDrv {
	/* Scan user structure */
	struct tstrWILC_UsrScanReq strWILC_UsrScanReq;

	/* Connect User structure */
	struct tstrWILC_UsrConnReq strWILC_UsrConnReq;

	#ifdef WILC_P2P
	/*Remain on channel struvture*/
	struct tstrHostIfRemainOnChan strHostIfRemainOnChan;
	u8 u8RemainOnChan_pendingreq;
	unsigned long p2p_mgmt_timeout;
	u8 u8P2PConnect;
	#endif /* WILC_P2P */

	enum tenuHostIFstate enuHostIFstate;

	#ifndef CONNECT_DIRECT
	unsigned int u32SurveyResultsCount;
	struct wid_site_survey_reslts astrSurveyResults[MAX_NUM_SCANNED_NETWORKS];
	#endif /* CONNECT_DIRECT */

	u8 au8AssociatedBSSID[ETH_ALEN];
	struct tstrCfgParamVal strCfgValues;

	struct semaphore gtOsCfgValuesSem;
	struct semaphore hSemTestKeyBlock;

	struct semaphore hSemTestDisconnectBlock;
	struct semaphore hSemGetRSSI;
	struct semaphore hSemGetLINKSPEED;
	struct semaphore hSemGetCHNL;
	struct semaphore hSemInactiveTime;

	struct timer_list hScanTimer;
	struct timer_list hConnectTimer;
	#ifdef WILC_P2P
	struct timer_list hRemainOnChannel;
	#endif

	bool IFC_UP;
	int driver_handler_id;
	#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
	bool pwrsave_current_state;
	#endif
};

/*
 * Used to decode the station flag set and mask in struct WILC_AddStaParam
 */

enum tenuWILC_StaFlag {
	WILC_STA_FLAG_INVALID = 0,
	WILC_STA_FLAG_AUTHORIZED, /* station is authorized (802.1X)*/
	/*station is capable of receiving frames with short barker preamble*/
	WILC_STA_FLAG_SHORT_PREAMBLE,
	WILC_STA_FLAG_WME, /* station is WME/QoS capable*/
	WILC_STA_FLAG_MFP, /* station uses management frame protection*/
	WILC_STA_FLAG_AUTHENTICATED /* station is authenticated*/
};

struct WILC_AddStaParam {
	u8 au8BSSID[ETH_ALEN];
	u16 u16AssocID;
	u8 u8NumRates;
	u8 *pu8Rates;
	bool bIsHTSupported;
	u16 u16HTCapInfo;
	u8 u8AmpduParams;
	u8 au8SuppMCsSet[16];
	u16 u16HTExtParams;
	unsigned int u32TxBeamformingCap;
	u8 u8ASELCap;
	u16 u16FlagsMask; /* Determines which of u16FlagsSet were changed>*/
	u16 u16FlagsSet; /* Decoded according to tenuWILC_StaFlag */
};


/*
 * Sends a buffered eap to WPAS
 */
signed int host_int_send_buffered_eap(struct WFIDrvHandle *hWFIDrv,
				      tWILCpfFrmToLinux pfFrmToLinux,
				      tWILCpfFreeEAPBuffParams pfFreeEAPBuffParams,
				      u8 *pu8Buff, unsigned int u32Size,
				      unsigned int u32PktOffset,
				      void *pvUserArg);
/*
 * Removes wpa/wpa2 keys
 * only in BSS STA mode if External Supplicant support is enabled.
 * removes all WPA/WPA2 station key entries from MAC hardware.
 */
signed int host_int_remove_key(struct WFIDrvHandle *hWFIDrv,
			       const u8 *pu8StaAddress);

/*
 * Removes WEP key
 * valid only in BSS STA mode if External Supplicant support is enabled.
 * remove a WEP key entry from MAC HW.
 * The BSS Station automatically finds the index of the entry using its
 * BSS ID and removes that entry from the MAC hardware.
 */
signed int host_int_remove_wep_key(struct WFIDrvHandle *hWFIDrv, u8 u8Index);

/*
 * Sets WEP deafault key
 * Sets the index of the WEP encryption key in use in the key table
 */
signed int host_int_set_WEPDefaultKeyID(struct WFIDrvHandle *hWFIDrv,
					u8 u8Index);

/*
 * Sets WEP deafault key
 * Valid only in BSS STA mode if External Supplicant support is enabled.
 * sets WEP key entry into MAC hardware when it receives the
 * corresponding request from NDIS.
 */
signed int host_int_add_wep_key_bss_sta(struct WFIDrvHandle *hWFIDrv,
					const u8 *pu8WepKey, u8 u8WepKeylen,
					u8 u8Keyidx);
/*
 * Valid only in AP mode if External Supplicant support is enabled.
 * sets WEP key entry into MAC hardware when it receives the
 * corresponding request from NDIS.
 */
signed int host_int_add_wep_key_bss_ap(struct WFIDrvHandle *hWFIDrv,
				       const u8 *pu8WepKey, u8 u8WepKeylen,
				       u8 u8Keyidx, u8 u8mode,
				       enum AUTHTYPE tenuAuth_type);

/*
 * Adds ptk Key
 */
signed int host_int_add_ptk(struct WFIDrvHandle *hWFIDrv, u8 *pu8Ptk,
			    u8 u8PtkKeylen, const u8 *mac_addr, u8 *pu8RxMic,
			    u8 *pu8TxMic, u8 mode, u8 u8Ciphermode, u8 u8Idx);

/*
 * host_int_get_inactive_time
 */
signed int host_int_get_inactive_time(struct WFIDrvHandle *hWFIDrv, u8 *mac,
				      unsigned int *pu32InactiveTime);

/*
 * Adds Rx GTk Key
 */
signed int host_int_add_rx_gtk(struct WFIDrvHandle *hWFIDrv, u8 *pu8RxGtk,
			       u8 u8GtkKeylen, u8 u8KeyIdx,
			       unsigned int u32KeyRSClen, u8 *KeyRSC, u8 *pu8RxMic,
			       u8 *pu8TxMic, u8 mode, u8 u8Ciphermode);

/*
 * Adds Tx GTk Key
 */
signed int host_int_add_tx_gtk(struct WFIDrvHandle *hWFIDrv, u8 u8KeyLen,
			       u8 *pu8TxGtk, u8 u8KeyIdx);

/*
 * Caches the pmkid
 *
 * valid only in BSS STA mode if External Supplicant
 * support is enabled. This Function sets the PMKID in firmware
 * when host drivr receives the corresponding request from NDIS.
 * The firmware then includes theset PMKID in the appropriate
 * management frames
 */

signed int host_int_set_pmkid_info(struct WFIDrvHandle *hWFIDrv,
				   struct tstrHostIFpmkidAttr *pu8PmkidInfoArray);
/*
 * Gets the cached the pmkid info
 *
 * valid only in BSS STA mode if External Supplicant
 * support is enabled. This Function sets the PMKID in firmware
 * when host drivr receives the corresponding request from NDIS.
 * The firmware then includes theset PMKID in the appropriate
 * management frames
 */

signed int host_int_get_pmkid_info(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8PmkidInfoArray,
				   unsigned int u32PmkidInfoLen);

/*
 * Sets the pass phrase
 *
 * AP/STA mode. This function gives the pass phrase used to
 * generate the Pre-Shared Key when WPA/WPA2 is enabled
 * The length of the field can vary from 8 to 64 bytes,
 * the lower layer should get the
 */
signed int host_int_set_RSNAConfigPSKPassPhrase(struct WFIDrvHandle *hWFIDrv,
						u8 *pu8PassPhrase,
						u8 u8Psklength);
/*
 * Gets the pass phrase
 *
 * AP/STA mode. This function gets the pass phrase used to
 * generate the Pre-Shared Key when WPA/WPA2 is enabled
 * The length of the field can vary from 8 to 64 bytes,
 * the lower layer should get the
 */
signed int host_int_get_RSNAConfigPSKPassPhrase(struct WFIDrvHandle *hWFIDrv,
						u8 *pu8PassPhrase, u8 u8Psklength);

/*
 * Gets mac address
 */
signed int host_int_get_MacAddress(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8MacAddress);

/*
 * Sets mac address
 */
signed int host_int_set_MacAddress(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8MacAddress);

/*
 * wait until msg q is empty
 */
signed int host_int_wait_msg_queue_idle(void);

/*
 * gets the site survey results
 */
#ifndef CONNECT_DIRECT
signed int host_int_get_site_survey_results(struct WFIDrvHandle *hWFIDrv,
					    u8 ppu8RcvdSiteSurveyResults[][MAX_SURVEY_RESULT_FRAG_SIZE],
					    unsigned int u32MaxSiteSrvyFragLen);
#endif

/*
 *  sets a start scan request
 */

signed int host_int_set_start_scan_req(struct WFIDrvHandle *hWFIDrv,
				       u8 scanSource);

/*
 * gets scan source of the last scan
 */
signed int host_int_get_start_scan_req(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8ScanSource);

/*
 * sets a join request
 */

signed int host_int_set_join_req(struct WFIDrvHandle *hWFIDrv, u8 *pu8bssid,
				 u8 *pu8ssid, size_t ssidLen,
				 const u8 *pu8IEs, size_t IEsLen,
				 tWILCpfConnectResult pfConnectResult,
				 void *pvUserArg, u8 u8security,
				 enum AUTHTYPE tenuAuth_type, u8 u8channel,
				 void *pJoinParams);

/*
 * Flush a join request parameters to FW, but actual connection
 *
 * The function is called in situation where WILC is connected to AP and
 * required to switch to hybrid FW for P2P connection
 */

signed int host_int_flush_join_req(struct WFIDrvHandle *hWFIDrv);

/*
 * Disconnects from the currently associated network
 */
signed int host_int_disconnect(struct WFIDrvHandle *hWFIDrv, u16 u16ReasonCode);

/*
 * Disconnects a sta
 */
signed int host_int_disconnect_station(struct WFIDrvHandle *hWFIDrv,
				       u8 assoc_id);
/*
 * gets a Association request info
 */

signed int host_int_get_assoc_req_info(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8AssocReqInfo,
				       unsigned int u32AssocReqInfoLen);
/*
 * Gets a Association Response info
 */

signed int host_int_get_assoc_res_info(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8AssocRespInfo,
				       unsigned int u32MaxAssocRespInfoLen,
				       unsigned int *pu32RcvdAssocRespInfoLen);
/*
 * gets a Association Response info
 *
 * Valid only in STA mode. This function gives the RSSI
 * values observed in all the channels at the time of scanning.
 * The length of the field is 1 greater that the total number of
 * channels supported. Byte 0 contains the number of channels while
 * each of Byte N contains	the observed RSSI value for the channel index N.
 */
signed int host_int_get_rx_power_level(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8RxPowerLevel,
				       unsigned int u32RxPowerLevelLen);

/*
 * sets a channel
 */
signed int host_int_set_mac_chnl_num(struct WFIDrvHandle *hWFIDrv, u8 u8ChNum);

/*
 * gets the current channel index
 */
signed int host_int_get_host_chnl_num(struct WFIDrvHandle *hWFIDrv,
				      u8 *pu8ChNo);

/*
 * gets the sta rssi
 *
 * gets the currently maintained RSSI value for the station.
 * The received signal strength value in dB.
 * The range of valid values is -128 to 0.
 */
signed int host_int_get_rssi(struct WFIDrvHandle *hWFIDrv, s8 *ps8Rssi);

signed int host_int_get_link_speed(struct WFIDrvHandle *hWFIDrv, s8 *ps8lnkspd);

/*
 * scans a set of channels
 */
signed int host_int_scan(struct WFIDrvHandle *hWFIDrv, u8 u8ScanSource,
			 u8 u8ScanType, u8 *pu8ChnlFreqList,
			 u8 u8ChnlListLen, const u8 *pu8IEs,
			 size_t IEsLen, tWILCpfScanResult ScanResult,
			 void *pvUserArg,
			 struct tstrHiddenNetwork  *pstrHiddenNetwork);

/*
 * sets configuration wids values
 */
signed int hif_set_cfg(struct WFIDrvHandle *hWFIDrv,
		       struct tstrCfgParamVal *pstrCfgParamVal);

/*
 * gets configuration wids values
 */
signed int hif_get_cfg(struct WFIDrvHandle *hWFIDrv, u16 u16WID,
		       u16 *pu16WID_Value);

/*
 * host interface initialization function
 */
signed int host_int_init(struct WFIDrvHandle **phWFIDrv);

/*
 * host interface initialization function
 */
signed int host_int_deinit(struct WFIDrvHandle *hWFIDrv, char* pcIfName, u8 u8IfMode);

/*
 * Sends a beacon to the firmware to be transmitted over the air
 */
signed int host_int_add_beacon(struct WFIDrvHandle *hWFIDrv,
			       unsigned int u32Interval,
			       unsigned int u32DTIMPeriod,
			       unsigned int u32HeadLen, u8 *pu8Head,
			       unsigned int u32TailLen, u8 *pu8tail);

/*
 * Removes the beacon and stops transmitting it over the air
 */
signed int host_int_del_beacon(struct WFIDrvHandle *hWFIDrv);

/*
 * Notifies the firmware with a new associated stations
 */
signed int host_int_add_station(struct WFIDrvHandle *hWFIDrv,
				struct WILC_AddStaParam *pstrStaParams);

/*
 * Deauthenticates clients when group is terminating
 */
signed int host_int_del_allstation(struct WFIDrvHandle *hWFIDrv,
				   u8 pu8MacAddr[][ETH_ALEN]);

/*
 * Notifies the firmware with a new deleted station
 */
signed int host_int_del_station(struct WFIDrvHandle *hWFIDrv, u8 *pu8MacAddr);

/*
 * Notifies the firmware with new parameters of an already associated station
 */
signed int host_int_edit_station(struct WFIDrvHandle *hWFIDrv,
				 struct WILC_AddStaParam *pstrStaParams);

/*
 * Set the power management mode to enabled or disabled
 */
signed int host_int_set_power_mgmt(struct WFIDrvHandle *hWFIDrv,
				   bool bIsEnabled, unsigned int u32Timeout);

/*
 * Set the multicast filter paramters
 */
signed int host_int_setup_multicast_filter(struct WFIDrvHandle *hWFIDrv,
					   bool bIsEnabled,
					   unsigned int u32count);

/*
 * set IP address on firmware
 */
signed int host_int_setup_ipaddress(struct WFIDrvHandle *hWFIDrv,
				    u8 *pu8IPAddr, u8 idx);

/*
 * Delete single Rx BA session
 */
signed int host_int_delBASession(struct WFIDrvHandle *hWFIDrv,
				 char *pBSSID, char TID);

/*
 * get IP address on firmware
 */
signed int host_int_get_ipaddress(struct WFIDrvHandle *hWFIDrv,
				  u8 *pu8IPAddr, u8 idx);

#ifdef WILC_P2P
/*
 * host_int_remain_on_channel
 */
signed int host_int_remain_on_channel(struct WFIDrvHandle *hWFIDrv,
				      unsigned int u32SessionID,
				      unsigned int u32duration, u16 chan,
				      tWILCpfRemainOnChanExpired RemainOnChanExpired,
				      tWILCpfRemainOnChanReady RemainOnChanReady,
				      void *pvUserArg);

/*
 * host_int_ListenStateExpired
 */
signed int host_int_ListenStateExpired(struct WFIDrvHandle *hWFIDrv,
				       unsigned int u32SessionID);

/*
 * host_int_frame_register
 */
signed int host_int_frame_register(struct WFIDrvHandle *hWFIDrv,
				   u16 u16FrameType, bool bReg);
#endif

/*
 * host_int_set_wfi_drv_handler
 */
signed int host_int_set_wfi_drv_handler(unsigned int u32address, u8 u8IfMode, char* u8IfName);

signed int host_int_set_operation_mode(struct WFIDrvHandle *hWFIDrv,
				       unsigned int u32mode);

#ifdef WILC_BT_COEXISTENCE
signed int host_int_change_bt_coex_mode(struct WFIDrvHandle *hWFIDrv,
				       tenuCoexMode u8BtCoexMode);
#endif	/*WILC_BT_COEXISTENCE*/

signed int Handle_ScanDone(void *drvHandler, enum tenuScanEvent enuEvent);

static int host_int_addBASession(struct WFIDrvHandle *hWFIDrv, char *pBSSID,
				 char TID, short int BufferSize,
				 short int SessionTimeout, void *drvHandler);

void host_int_freeJoinParams(void *pJoinParams);

signed int host_int_get_statistics(struct WFIDrvHandle *hWFIDrv,
				   struct tstrStatistics *pstrStatistics);

void resolve_disconnect_aberration(void *drvHandler);

signed int host_int_set_tx_power(struct WFIDrvHandle *hWFIDrv, u8 tx_power);

signed int  host_int_get_tx_power(struct WFIDrvHandle * hWFIDrv, u8 *tx_power);
/*0 select antenna 1 , 2 select antenna mode , 2 allow the firmware to choose the best antenna*/
signed int host_int_set_antenna(struct WFIDrvHandle *hWFIDrv, u8 antenna_mode);
signed int host_int_set_wowlan_trigger(struct WFIDrvHandle *hWFIDrv, u8 wowlan_trigger);

#endif
