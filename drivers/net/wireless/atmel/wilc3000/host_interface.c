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

#include "host_interface.h"
#include "wilc_errorsupport.h"
#include "coreconfigurator.h"
#include "wilc_msgqueue.h"
#include "wilc_wlan.h"
#include "wilc_wfi_cfgoperations.h"
#include "linux_wlan.h"
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

/* Message types of the Host IF Message Queue*/
#define HOST_IF_MSG_SCAN					((u16)0)
#define HOST_IF_MSG_CONNECT					((u16)1)
#define HOST_IF_MSG_RCVD_GNRL_ASYNC_INFO	((u16)2)
#define HOST_IF_MSG_KEY						((u16)3)
#define HOST_IF_MSG_RCVD_NTWRK_INFO			((u16)4)
#define HOST_IF_MSG_RCVD_SCAN_COMPLETE		((u16)5)
#define HOST_IF_MSG_CFG_PARAMS				((u16)6)
#define HOST_IF_MSG_SET_CHANNEL				((u16)7)
#define HOST_IF_MSG_DISCONNECT				((u16)8)
#define HOST_IF_MSG_GET_RSSI				((u16)9)
#define HOST_IF_MSG_GET_CHNL				((u16)10)
#define HOST_IF_MSG_ADD_BEACON				((u16)11)
#define HOST_IF_MSG_DEL_BEACON				((u16)12)
#define HOST_IF_MSG_ADD_STATION				((u16)13)
#define HOST_IF_MSG_DEL_STATION				((u16)14)
#define HOST_IF_MSG_EDIT_STATION			((u16)15)
#define HOST_IF_MSG_SCAN_TIMER_FIRED		((u16)16)
#define HOST_IF_MSG_CONNECT_TIMER_FIRED		((u16)17)
#define HOST_IF_MSG_POWER_MGMT				((u16)18)
#define HOST_IF_MSG_GET_INACTIVETIME		((u16)19)
#define HOST_IF_MSG_REMAIN_ON_CHAN			((u16)20)
#define  HOST_IF_MSG_REGISTER_FRAME			((u16)21)
#define HOST_IF_MSG_LISTEN_TIMER_FIRED		((u16)22)
#define HOST_IF_MSG_GET_LINKSPEED			((u16)23)
#define HOST_IF_MSG_SET_WFIDRV_HANDLER		((u16)24)
#define HOST_IF_MSG_SET_MAC_ADDRESS			((u16)25)
#define HOST_IF_MSG_GET_MAC_ADDRESS			((u16)26)
#define HOST_IF_MSG_SET_OPERATION_MODE		((u16)27)
#define HOST_IF_MSG_SET_IPADDRESS			((u16)28)
#define HOST_IF_MSG_GET_IPADDRESS			((u16)29)
#define HOST_IF_MSG_FLUSH_CONNECT			((u16)30)
#define HOST_IF_MSG_GET_STATISTICS			((u16)31)
#define HOST_IF_MSG_SET_MULTICAST_FILTER	((u16)32)
#define HOST_IF_MSG_ADD_BA_SESSION			((u16)33)
#define HOST_IF_MSG_DEL_BA_SESSION			((u16)34)
#define HOST_IF_MSG_Q_IDLE					((u16)35)
#define HOST_IF_MSG_DEL_ALL_STA				((u16)36)
#define HOST_IF_MSG_DEL_ALL_RX_BA_SESSIONS	((u16)37)
#define HOST_IF_MSG_SET_TX_POWER			((u16)38)
#define HOST_IF_MSG_GET_TX_POWER			((u16)39)
#define HOST_IF_MSG_SET_ANTENNA_MODE		((u16)40)
#define HOST_IF_MSG_SEND_BUFFERED_EAP		((u16)41)
#ifdef WILC_BT_COEXISTENCE
#define HOST_IF_MSG_CHANGE_BT_COEX_MODE		((u16)42)
#endif
#define HOST_IF_MSG_SET_WOWLAN_TRIGGER 		((u16)43)

#define HOST_IF_MSG_EXIT					((u16)100)

#define HOST_IF_SCAN_TIMEOUT				4000
#define HOST_IF_CONNECT_TIMEOUT				9500

#define BA_SESSION_DEFAULT_BUFFER_SIZE		16
#define BA_SESSION_DEFAULT_TIMEOUT			1000
#define BLOCK_ACK_REQ_SIZE					0x14

static int add_handler_in_list(struct WILC_WFIDrv *handler);
static int remove_handler_in_list(struct WILC_WFIDrv *handler);
static struct WILC_WFIDrv *get_handler_from_id(int id);
/*
 * Structure to hold Host IF CFG Params Attributes
 */
struct tstrHostIFCfgParamAttr {
	struct tstrCfgParamVal pstrCfgParamVal;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
struct tstrHostIFwpaAttr {
	u8 *pu8key;
	const u8 *pu8macaddr;
	u8 *pu8seq;
	u8 u8seqlen;
	u8 u8keyidx;
	u8 u8Keylen;
	u8 u8Ciphermode;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
struct tstrHostIFwepAttr {
	u8 *pu8WepKey;
	u8 u8WepKeylen;
	u8 u8Wepidx;
	u8 u8mode;
	enum AUTHTYPE tenuAuth_type;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
union tuniHostIFkeyAttr {
	struct tstrHostIFwepAttr strHostIFwepAttr;
	struct tstrHostIFwpaAttr strHostIFwpaAttr;
	struct tstrHostIFpmkidAttr strHostIFpmkidAttr;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
struct tstrHostIFkeyAttr {
	enum tenuKeyType enuKeyType;
	u8 u8KeyAction;
	union tuniHostIFkeyAttr uniHostIFkeyAttr;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
struct tstrHostIFSendBufferedEAP {
	tWILCpfFrmToLinux pfFrmToLinux;
	tWILCpfFreeEAPBuffParams pfFreeEAPBuffParams;
	u8 *pu8Buff;
	unsigned int u32Size;
	unsigned int u32PktOffset;
	void *pvUserArg;
};

/*
 * Structure to hold Host IF Scan Attributes
 */
struct tstrHostIFscanAttr {
	u8 u8ScanSource;
	u8 u8ScanType;
	u8 *pu8ChnlFreqList;
	u8 u8ChnlListLen;
	u8 *pu8IEs;
	size_t IEsLen;
	tWILCpfScanResult pfScanResult;
	void *pvUserArg;
	struct tstrHiddenNetwork strHiddenNetwork;
};

/*
 * Structure to hold Host IF Connect Attributes
 */
struct tstrHostIFconnectAttr {
	u8 *pu8bssid;
	u8 *pu8ssid;
	size_t ssidLen;
	u8 *pu8IEs;
	size_t IEsLen;
	u8 u8security;
	tWILCpfConnectResult pfConnectResult;
	void *pvUserArg;
	enum AUTHTYPE tenuAuth_type;
	u8 u8channel;
	void *pJoinParams;
};

/*
 * Structure to hold Received General Asynchronous info
 */
struct tstrRcvdGnrlAsyncInfo {
	u8 *pu8Buffer;
	unsigned int u32Length;
};

/*
 * Set Channel  message body
 */
struct tstrHostIFSetChan {
	u8 u8SetChan;
};

/*
 * Get Channel  message body
 */
struct tstrHostIFGetChan {
	u8 u8GetChan;
};

/*
 * Set Beacon  message body
 */
struct tstrHostIFSetBeacon {
	/*
	 * Beacon Interval.
	 * Period between two successive beacons on air
	 */
	unsigned int u32Interval;
	/*
	 * DTIM Period.
	 * Indicates how many Beacon frames (including the current frame)
	 * appear before the next DTIM
	 */
	unsigned int u32DTIMPeriod;
	/*
	 * Length of the head buffer in bytes
	 */
	unsigned int u32HeadLen;
	/*
	 * Pointer to the beacon's head buffer.
	 * Beacon's head is the part from the beacon's start till the TIM
	 * element, NOT including the TIM
	 */
	u8 *pu8Head;
	/*
	 * Length of the tail buffer in bytes
	 */
	unsigned int u32TailLen;
	/*
	 * Pointer to the beacon's tail buffer.
	 * Beacon's tail starts just after the TIM
	 * inormation element
	 */
	u8 *pu8Tail;
};

/*
 * Del Beacon  message body
 */
struct tstrHostIFDelBeacon {
	u8 u8dummy;
};

/*
 * set Multicast filter Address
 */

struct tstrHostIFSetMulti {
	bool bIsEnabled;
	unsigned int u32count;
};

/*
 * Deauth station message body
 */

struct tstrHostIFDelAllSta {
	u8 au8Sta_DelAllSta[MAX_NUM_STA][ETH_ALEN];
	u8 u8Num_AssocSta;
};

/*
 * Delete station message body
 */

struct tstrHostIFDelSta {
	u8 au8MacAddr[ETH_ALEN];
};

#ifdef WILC_BT_COEXISTENCE
struct tstrHostIFBTCoexMode {
	u8 u8BTCoexMode;
};
#endif /* WILC_BT_COEXISTENCE */

/*
 * Timer callback message body
 */
struct tstrTimerCb {
	void *pvUsrArg; /* Private data passed at timer start */
};

/*
 * Power management message body
 */
struct tstrHostIfPowerMgmtParam {
	bool bIsEnabled;
	unsigned int u32Timeout;
};

/*
 * set IP Address message body
 */

struct tstrHostIFSetIPAddr {
	u8 *au8IPAddr;
	u8 idx;
};

/*
 * Get station message body
 */
struct tstrHostIfStaInactive {
	u8 mac[6];
};

struct tstrHostIFWowlanTrigger
{
	u8 u8WowlanTrigger;
};
struct tstrHostIFTxPwr
{
	u8 u8TxPwr;
};
struct tstrHostIFGetTxPwr
{
	u8* u8TxPwr;
};

struct tstrHostIFSetAnt
{
	u8 mode;
	u8 antenna1;
#ifdef ANT_SWTCH_DUAL_GPIO_CTRL
	u8 antenna2;
#endif
};

/*
 * Message body for the Host Interface message_q
 */
union tuniHostIFmsgBody {
	/* Host IF Scan Request Attributes message body */
	struct tstrHostIFscanAttr strHostIFscanAttr;
	/* Host IF Connect Request Attributes message body */
	struct tstrHostIFconnectAttr strHostIFconnectAttr;
	/* Received Asynchronous Network Info message body */
	struct tstrRcvdNetworkInfo strRcvdNetworkInfo;
	/*Received General Asynchronous Info message body */
	struct tstrRcvdGnrlAsyncInfo strRcvdGnrlAsyncInfo;
	struct tstrHostIFkeyAttr strHostIFkeyAttr;
	/*CFG Parameter message Body> */
	struct tstrHostIFCfgParamAttr strHostIFCfgParamAttr;
	struct tstrHostIFSetChan strHostIFSetChan;
	struct tstrHostIFGetChan strHostIFGetChan;
	/* Set beacon message body */
	struct tstrHostIFSetBeacon strHostIFSetBeacon;
	/* Del beacon message body */
	struct tstrHostIFDelBeacon strHostIFDelBeacon;
	/* Add station message body */
	struct WILC_AddStaParam strAddStaParam;
	/* Del Station message body */
	struct tstrHostIFDelSta strDelStaParam;
	/* Edit station message body */
	struct WILC_AddStaParam strEditStaParam;
	struct tstrTimerCb strTimerCb; /* Timer callback message body */
	/* Power Management message body */
	struct tstrHostIfPowerMgmtParam strPowerMgmtparam;
	struct tstrHostIfStaInactive strHostIfStaInactiveT;
	struct tstrHostIFSetIPAddr strHostIfSetIP;
	struct tstrHostIfSetDrvHandler strHostIfSetDrvHandler;
	struct tstrHostIFSetMulti strHostIfSetMulti;
	struct tstrHostIfSetOperationMode strHostIfSetOperationMode;
	struct tstrHostIfSetMacAddress strHostIfSetMacAddress;
	struct tstrHostIfGetMacAddress strHostIfGetMacAddress;
	struct tstrHostIfBASessionInfo strHostIfBASessionInfo;
#ifdef WILC_P2P
	struct tstrHostIfRemainOnChan strHostIfRemainOnChan;
	struct tstrHostIfRegisterFrame strHostIfRegisterFrame;
#endif /* WILC_P2P */
	char *pUserData;
	struct tstrHostIFDelAllSta strHostIFDelAllSta;
	struct tstrHostIFSendBufferedEAP strHostIFSendBufferedEAP;
	struct tstrHostIFTxPwr strHostIFTxPwr;
	struct tstrHostIFGetTxPwr strHostIFGetTxPwr;
	struct tstrHostIFWowlanTrigger strHostIFWowlanTrigger;
#ifdef WILC_BT_COEXISTENCE
	struct tstrHostIFBTCoexMode strHostIfBTMode;
#endif /* WILC_BT_COEXISTENCE */
	struct tstrHostIFSetAnt strHostIFSetAnt;
};

/*
 * Host Interface message
 */
struct tstrHostIFmsg {
	u16 u16MsgId; /* Message ID */
	union tuniHostIFmsgBody uniHostIFmsgBody; /* Message body */
	void *drvHandler;
};

#ifdef CONNECT_DIRECT
struct tstrWidJoinReqExt {
	char SSID[MAX_SSID_LEN];
	u8 u8channel;
	u8 BSSID[6];
};
#endif /* CONNECT_DIRECT */

/*Bug4218: Parsing Join Param*/
#ifdef WILC_PARSE_SCAN_IN_HOST
/* Struct containg joinParam of each AP*/
struct tstrJoinBssParam {
	enum BSSTYPE bss_type;
	u8 dtim_period;
	u16 beacon_period;
	u16 cap_info;
	u8 au8bssid[6];
	char ssid[MAX_SSID_LEN];
	u8 ssidLen;
	u8 supp_rates[MAX_RATES_SUPPORTED + 1];
	u8 ht_capable;
	u8 wmm_cap;
	u8 uapsd_cap;
	bool rsn_found;
	u8 rsn_grp_policy;
	u8 mode_802_11i;
	u8 rsn_pcip_policy[3];
	u8 rsn_auth_policy[3];
	u8 rsn_cap[2];
	struct _tstrJoinParam *nextJoinBss;
	#ifdef WILC_P2P
	unsigned int tsf;
	u8 u8NoaEnbaled;
	u8 u8OppEnable;
	u8 u8CtWindow;
	u8 u8Count;
	u8 u8Index;
	u8 au8Duration[4];
	u8 au8Interval[4];
	u8 au8StartTime[4];
	#endif /* WILC_P2P */
};

/*
 * A linked list table containing needed join parameters entries for each
 * AP found in most recent scan
 */
struct tstrBssTable {
	u8 u8noBssEntries;
	struct tstrJoinBssParam *head;
	struct tstrJoinBssParam *tail;
};
#endif /*WILC_PARSE_SCAN_IN_HOST*/

enum tenuScanConnTimer {
	SCAN_TIMER			= 0,
	CONNECT_TIMER			= 1,
	SCAN_CONNECT_TIMER_FORCE_32BIT	= 0xFFFFFFFF
};

struct WILC_WFIDrv *wfidrv_list[NUM_CONCURRENT_IFC + 1];
struct WILC_WFIDrv *terminated_handle = NULL;
struct WILC_WFIDrv *gWFiDrvHandle = NULL;

static struct task_struct *HostIFthreadHandler;
static struct MsgQueueHandle gMsgQHostIF;
static struct semaphore hSemHostIFthrdEnd;

struct semaphore hSemDeinitDrvHandle;
static struct semaphore hWaitResponse;
struct semaphore hSemHostIntDeinit;
struct timer_list g_hPeriodicRSSI;

u8 gau8MulticastMacAddrList[WILC_MULTICAST_TABLE_SIZE][ETH_ALEN] = {{0}};

#ifndef CONNECT_DIRECT
static u8 gapu8RcvdSurveyResults[2][MAX_SURVEY_RESULT_FRAG_SIZE];
#endif /* CONNECT_DIRECT */

static u8 gapu8RcvdAssocResp[MAX_ASSOC_RESP_FRAME_SIZE];

bool gbScanWhileConnected = false;

static u8 au8NullBSSID[6] = {0};
static s8 gs8Rssi = 0;
static s8 gs8lnkspd = 0;
static u8 gu8Chnl = 0;
static u8 gs8SetIP[2][4] = {{0}};
static u8 gs8GetIP[2][4] = {{0}};
#ifdef WILC_AP_EXTERNAL_MLME
static unsigned int gu32InactiveTime = 0;
static u8 gu8DelBcn = 0;
#endif /* WILC_AP_EXTERNAL_MLME */
#ifndef SIMULATION
static unsigned int gu32WidConnRstHack = 0;
#endif

/*BugID_5137*/
u8 *gu8FlushedJoinReq = NULL;
u8 *gu8FlushedInfoElemAsoc = NULL;
u8 gu8Flushed11iMode;
u8 gu8FlushedAuthType;
unsigned int gu32FlushedJoinReqSize;
unsigned int gu32FlushedInfoElemAsocSize;
unsigned int gu8FlushedJoinReqDrvHandler = 0;
#define REAL_JOIN_REQ		0
#define FLUSHED_JOIN_REQ	1
/* Position the byte indicating flushing in the flushed request */
#define FLUSHED_BYTE_POS	79

/*Bug4218: Parsing Join Param*/
#ifdef WILC_PARSE_SCAN_IN_HOST
/*Bug4218: Parsing Join Param*/
static void *host_int_ParseJoinBssParam(struct tstrNetworkInfo *ptstrNetworkInfo);
#endif /*WILC_PARSE_SCAN_IN_HOST*/

static int add_handler_in_list(struct WILC_WFIDrv *handler) {
	int i;
	for (i = 1; i < ARRAY_SIZE(wfidrv_list); i++) {
		if (!wfidrv_list[i]){ 
			wfidrv_list[i] = handler;
			handler->driver_handler_id = i ;
			return 0; 
		}

	}

	return -ENOBUFS; 
}

static int remove_handler_in_list(struct WILC_WFIDrv *handler) {
	int i;
	for (i = 1; i < ARRAY_SIZE(wfidrv_list); i++) {
		if (wfidrv_list[i] == handler){ 
			wfidrv_list[i] = NULL; 
			handler->driver_handler_id = 0;
			return 0; 
		}

	}
	return -EINVAL;
}


static struct WILC_WFIDrv *get_handler_from_id(int id){ 
	if (id <= 0 || id > ARRAY_SIZE(wfidrv_list)){
		return NULL;
	}
	return wfidrv_list[id]; 
}

/*TicketId1001*/
/*
 * Callback to frm_to_linux function to pass a buffered eapol frame
 */
static signed int Handle_SendBufferedEAP(void *drvHandler,
		   struct tstrHostIFSendBufferedEAP *pstrHostIFSendBufferedEAP)
{
	signed int s32Error = WILC_SUCCESS;

	PRINT_D(HOSTINF_DBG, "Sending bufferd eapol to WPAS\n");

	if (pstrHostIFSendBufferedEAP->pu8Buff == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	if (pstrHostIFSendBufferedEAP->pfFrmToLinux)
		pstrHostIFSendBufferedEAP->pfFrmToLinux(pstrHostIFSendBufferedEAP->pu8Buff
							, pstrHostIFSendBufferedEAP->u32Size
							, pstrHostIFSendBufferedEAP->u32PktOffset
							, PKT_STATUS_BUFFERED);

	/*Call a fucntion to free allocated eapol buffers in priv struct*/
	if (pstrHostIFSendBufferedEAP->pfFreeEAPBuffParams)
		pstrHostIFSendBufferedEAP->pfFreeEAPBuffParams(pstrHostIFSendBufferedEAP->pvUserArg);

	/*Free allocated buffer*/
	if (pstrHostIFSendBufferedEAP->pu8Buff != NULL)	{
		kfree(pstrHostIFSendBufferedEAP->pu8Buff);
		pstrHostIFSendBufferedEAP->pu8Buff = NULL;
	}

	WILC_CATCH(s32Error){
	}
	return s32Error;
}

/*
 * Sending config packet to firmware to set channel
 */
static signed int Handle_SetChannel(void *drvHandler,
				    struct tstrHostIFSetChan *pstrHostIFSetChan)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	/*prepare configuration packet*/
	strWID.u16WIDid = (u16)WID_CURRENT_CHANNEL;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (char *)&(pstrHostIFSetChan->u8SetChan);
	strWID.s32ValueSize = sizeof(char);

	PRINT_D(HOSTINF_DBG,"Setting channel\n");
	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true,
				 driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to set channel\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}
	WILC_CATCH(s32Error){
	}
	
	return s32Error;
}

/*
 * Sending config packet to firmware to set driver handler
 */
static signed int Handle_SetWfiDrvHandler(struct tstrHostIfSetDrvHandler *pstrHostIfSetDrvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	u8* pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv;
	u8* pu8Buff = kmalloc(5, GFP_ATOMIC);
	int driver_handler_id = 0;
	
	if(pu8Buff == NULL)
	{
		PRINT_ER("No buffer to send WiFi driver handler\n");
		return WILC_FAIL;
	}

	pstrWFIDrv = (struct WILC_WFIDrv *)((pstrHostIfSetDrvHandler->u32Address));

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	memset(pu8Buff, 0, 5);
	pu8CurrByte = pu8Buff;
	*pu8CurrByte = driver_handler_id & 0x000000FF;
	pu8CurrByte++;
	*pu8CurrByte = (u32)0 & 0x000000FF;
	pu8CurrByte++;
	*pu8CurrByte = (u32)0 & 0x000000FF;
	pu8CurrByte++;
	*pu8CurrByte = (u32)0 & 0x000000FF;
	pu8CurrByte++;
	*pu8CurrByte = (pstrHostIfSetDrvHandler->u8IfName | (pstrHostIfSetDrvHandler->u8IfMode << 1));	

	/*prepare configuration packet*/
	strWID.u16WIDid = (u16)WID_SET_DRV_HANDLER;
	strWID.enuWIDtype= WID_STR;
	strWID.ps8WidVal = pu8Buff;
	strWID.s32ValueSize = 5;

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if ((pstrHostIfSetDrvHandler->u32Address) == (unsigned int)NULL)
		up(&hSemDeinitDrvHandle);


	if (s32Error) {
		PRINT_ER("Failed to set driver handler\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}
	WILC_CATCH(s32Error){
	}
	kfree(pu8Buff);
	return s32Error;
}

/*
 * Sending config packet to firmware to set driver handler
 */
static signed int Handle_SetOperationMode(void *drvHandler,
					  struct tstrHostIfSetOperationMode *pstrHostIfSetOperationMode)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	strWID.u16WIDid = (u16)WID_SET_OPERATION_MODE;
	strWID.enuWIDtype = WID_INT;
	strWID.ps8WidVal = (s8 *)&(pstrHostIfSetOperationMode->u32Mode);
	strWID.s32ValueSize = sizeof(unsigned int);

	/*Sending Cfg*/
	PRINT_D(HOSTINF_DBG, "pstrWFIDrv= %x \n",driver_handler_id);
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true,driver_handler_id);

	if ((pstrHostIfSetOperationMode->u32Mode) == (unsigned int)NULL)
		up(&hSemDeinitDrvHandle);


	if (s32Error) {
		PRINT_ER("Failed to set driver handler\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}
	WILC_CATCH(s32Error){
	}
	return s32Error;
}

/*
 * Setting IP address params in message queue
 */
signed int Handle_set_IPAddress(void *drvHandler, u8 *pu8IPAddr, u8 idx)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	char firmwareIPAddress[4] = {0};
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	if (pu8IPAddr[0] < 192)
		pu8IPAddr[0] = 0;

	PRINT_D(HOSTINF_DBG,"Indx = %d, Handling set  IP = %d.%d.%d.%d\n", idx,
		 pu8IPAddr[0], pu8IPAddr[1], pu8IPAddr[2], pu8IPAddr[3]);

	memcpy(gs8SetIP[idx], pu8IPAddr, IP_ALEN);

	strWID.u16WIDid = (u16)WID_IP_ADDRESS;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = (u8 *)pu8IPAddr;
	strWID.s32ValueSize = IP_ALEN;

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	host_int_get_ipaddress((struct WFIDrvHandle *)drvHandler,
			       firmwareIPAddress, idx);

	if (s32Error) {
		PRINT_D(HOSTINF_DBG,"Failed to set IP address\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_INFO(HOSTINF_DBG,"IP address set\n");
	}

	WILC_CATCH(s32Error){
	}
	return s32Error;
}

/*
 * Setting IP address params in message queue
 */
signed int Handle_get_IPAddress(void *drvHandler, u8 *pu8IPAddr, u8 idx)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_IP_ADDRESS;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = kmalloc(IP_ALEN, GFP_ATOMIC);
	strWID.s32ValueSize = IP_ALEN;

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);

	PRINT_D(HOSTINF_DBG,"%d.%d.%d.%d\n", (u8)(strWID.ps8WidVal[0]), (u8)(strWID.ps8WidVal[1]),
				 (u8)(strWID.ps8WidVal[2]), (u8)(strWID.ps8WidVal[3]));

	memcpy(gs8GetIP[idx], strWID.ps8WidVal, IP_ALEN);

	kfree(strWID.ps8WidVal);

	if (memcmp(gs8GetIP[idx], gs8SetIP[idx], IP_ALEN) != 0)
		host_int_setup_ipaddress((struct WFIDrvHandle *)pstrWFIDrv,
					 gs8SetIP[idx], idx);

	if (s32Error != WILC_SUCCESS) {
		PRINT_ER("Failed to get IP address\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_D(HOSTINF_DBG, "IP address retrieved:: u8IfIdx = %d\n", idx);
		PRINT_D(HOSTINF_DBG,"%d.%d.%d.%d\n", gs8GetIP[idx][0], gs8GetIP[idx][1],
			 gs8GetIP[idx][2], gs8GetIP[idx][3]);

		PRINT_INFO(HOSTINF_DBG,"\n");
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Setting mac address
 */
static signed int Handle_SetMacAddress(void *drvHandler,
		      struct tstrHostIfSetMacAddress *pstrHostIfSetMacAddress)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	u8 *mac_buf = kmalloc(ETH_ALEN, GFP_ATOMIC);

	if (mac_buf == NULL)
		return WILC_FAIL;

	memcpy(mac_buf, pstrHostIfSetMacAddress->u8MacAddress, ETH_ALEN);

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_MAC_ADDR;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = mac_buf;
	strWID.s32ValueSize = ETH_ALEN;
	PRINT_D(HOSTINF_DBG,"mac addr = :%x:%x:%x:%x:%x:%x\n", strWID.ps8WidVal[0],
						    strWID.ps8WidVal[1],
						    strWID.ps8WidVal[2],
						    strWID.ps8WidVal[3],
						    strWID.ps8WidVal[4],
						    strWID.ps8WidVal[5]);
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to set mac address\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}
	kfree(mac_buf);
	return s32Error;
}

/*
 * Getting mac address
 */
static signed int Handle_GetMacAddress(void *drvHandler,
				       struct tstrHostIfGetMacAddress *pstrHostIfGetMacAddress)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_MAC_ADDR;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = pstrHostIfGetMacAddress->u8MacAddress;
	strWID.s32ValueSize = ETH_ALEN;

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to get mac address\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}
	WILC_CATCH(s32Error){

	}
	up(&hWaitResponse);

	return s32Error;
}

#ifdef WILC_BT_COEXISTENCE
static signed int Handle_BTCoexModeChange(void *drvHandler,
					  struct tstrHostIFBTCoexMode *pstrHostIFBTCoexMode)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWIDList[2];
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	unsigned int u32WidsCount = 0;
	u8 u8CoexNullFramesMode = COEX_NULL_FRAMES_OFF;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_BT_COEX_MODE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].ps8WidVal = (char *)&(pstrHostIFBTCoexMode->u8BTCoexMode);
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	u32WidsCount++;

	PRINT_D(HOSTINF_DBG,"[COEX] [DRV] Changing BT mode: %x\n",
		 pstrHostIFBTCoexMode->u8BTCoexMode);

	/*TicketId1115*/
	if(pstrHostIFBTCoexMode->u8BTCoexMode == COEX_ON)
		u8CoexNullFramesMode = COEX_NULL_FRAMES_ON;
	/*prepare configuration packet*/
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_COEX_NULL_FRAMES_MODE;
	strWIDList[u32WidsCount].enuWIDtype= WID_CHAR;
	strWIDList[u32WidsCount].ps8WidVal = (s8*)&(u8CoexNullFramesMode);
	strWIDList[u32WidsCount].s32ValueSize = sizeof(s8);
	u32WidsCount++;

	
	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, strWIDList, u32WidsCount, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("[COEX] [DRV] Changing BT mode failed\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
#endif /* WILC_BT_COEXISTENCE */

/*
 * Sending config packet to firmware to set CFG params
 */
static signed int Handle_CfgParam(void *drvHandler,
				  struct tstrHostIFCfgParamAttr *strHostIFCfgParamAttr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWIDList[32];
	int driver_handler_id = 0;
	u8 u8WidCnt = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	down(&(pstrWFIDrv->gtOsCfgValuesSem));

	PRINT_D(HOSTINF_DBG, "Setting CFG params\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & BSS_TYPE) {
			/*
			*Input Value:	INFRASTRUCTURE = 1,
			*				INDEPENDENT= 2,
			*				ANY_BSS= 3
			*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.bss_type < 6) {
			strWIDList[u8WidCnt].u16WIDid = WID_BSS_TYPE;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.bss_type;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.bss_type = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.bss_type;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}

	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & AUTH_TYPE) {
			/*
			*Input Values: OPEN_SYSTEM     = 0,
			*				SHARED_KEY      = 1,
			*				ANY             = 2
			*
			*validate Possible values
			*/
		if ((strHostIFCfgParamAttr->pstrCfgParamVal.auth_type) == 1 ||
		    (strHostIFCfgParamAttr->pstrCfgParamVal.auth_type) == 2 ||
		    (strHostIFCfgParamAttr->pstrCfgParamVal.auth_type) == 5) {
			strWIDList[u8WidCnt].u16WIDid = WID_AUTH_TYPE;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.auth_type;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.auth_type = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.auth_type;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}

	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & AUTHEN_TIMEOUT) {
		/*range is 1 to 65535*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.auth_timeout > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.auth_timeout < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_AUTH_TIMEOUT;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.auth_timeout;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.auth_timeout = strHostIFCfgParamAttr->pstrCfgParamVal.auth_timeout;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}

	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & POWER_MANAGEMENT) {
		/*
		*Input Values:	NO_POWERSAVE     = 0,
		*				MIN_FAST_PS      = 1,
		*				MAX_FAST_PS      = 2,
		*				MIN_PSPOLL_PS    = 3,
		*				MAX_PSPOLL_PS    = 4
		*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.power_mgmt_mode < 5) {
			strWIDList[u8WidCnt].u16WIDid = WID_POWER_MANAGEMENT;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.power_mgmt_mode;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.power_mgmt_mode = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.power_mgmt_mode;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}

	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & RETRY_SHORT) {
		/*range from 1 to 256*/
		if ((strHostIFCfgParamAttr->pstrCfgParamVal.short_retry_limit > 0) &&
		    (strHostIFCfgParamAttr->pstrCfgParamVal.short_retry_limit < 256)) {
			strWIDList[u8WidCnt].u16WIDid = WID_SHORT_RETRY_LIMIT;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.short_retry_limit;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.short_retry_limit = strHostIFCfgParamAttr->pstrCfgParamVal.short_retry_limit;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}

	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & RETRY_LONG) {
		/*range from 1 to 256*/
		if ((strHostIFCfgParamAttr->pstrCfgParamVal.long_retry_limit > 0) &&
		    (strHostIFCfgParamAttr->pstrCfgParamVal.long_retry_limit < 256)) {
			strWIDList[u8WidCnt].u16WIDid = WID_LONG_RETRY_LIMIT;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.long_retry_limit;

			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.long_retry_limit = strHostIFCfgParamAttr->pstrCfgParamVal.long_retry_limit;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & FRAG_THRESHOLD) {
		if (strHostIFCfgParamAttr->pstrCfgParamVal.frag_threshold > 255 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.frag_threshold < 7937) {
			strWIDList[u8WidCnt].u16WIDid = WID_FRAG_THRESHOLD;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.frag_threshold;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.frag_threshold = strHostIFCfgParamAttr->pstrCfgParamVal.frag_threshold;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & RTS_THRESHOLD) {
		 /*range 256 to 65535*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.rts_threshold > 255 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.rts_threshold < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_RTS_THRESHOLD;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.rts_threshold;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.rts_threshold = strHostIFCfgParamAttr->pstrCfgParamVal.rts_threshold;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & PREAMBLE) {
		/*
		*Input Values: Short= 0,
		*				Long= 1,
		*				Auto= 2
		*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.preamble_type < 3) {
			strWIDList[u8WidCnt].u16WIDid = WID_PREAMBLE;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.preamble_type;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.preamble_type = strHostIFCfgParamAttr->pstrCfgParamVal.preamble_type;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & SHORT_SLOT_ALLOWED) {
		if (strHostIFCfgParamAttr->pstrCfgParamVal.short_slot_allowed < 2) {
			strWIDList[u8WidCnt].u16WIDid = WID_SHORT_SLOT_ALLOWED;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.short_slot_allowed;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.short_slot_allowed = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.short_slot_allowed;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & TXOP_PROT_DISABLE) {
		/*Description:	used to Disable RTS-CTS protection for TXOP burst
		*transmission when the acknowledgement policy is No-Ack or Block-Ack
		* this information is useful for external supplicant
		*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.txop_prot_disabled < 2) {
			strWIDList[u8WidCnt].u16WIDid = WID_11N_TXOP_PROT_DISABLE;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.txop_prot_disabled;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.txop_prot_disabled = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.txop_prot_disabled;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & BEACON_INTERVAL) {
		/*range is 1 to 65535.*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.beacon_interval > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.beacon_interval < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_BEACON_INTERVAL;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.beacon_interval;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.beacon_interval = strHostIFCfgParamAttr->pstrCfgParamVal.beacon_interval;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & DTIM_PERIOD) {
		/*range is 1 to 255.*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.dtim_period > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.dtim_period < 256) {
			strWIDList[u8WidCnt].u16WIDid = WID_DTIM_PERIOD;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.dtim_period;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.dtim_period = strHostIFCfgParamAttr->pstrCfgParamVal.dtim_period;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & SITE_SURVEY) {
		/*
		*Input Values: SITE_SURVEY_1CH    = 0, i.e.: currently set channel
		*				SITE_SURVEY_ALL_CH = 1,
		*				SITE_SURVEY_OFF    = 2
		*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_enabled < 3) {
			strWIDList[u8WidCnt].u16WIDid = WID_SITE_SURVEY;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_enabled;
			strWIDList[u8WidCnt].enuWIDtype = WID_CHAR;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(char);
			pstrWFIDrv->strCfgValues.site_survey_enabled = (u8)strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_enabled;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & SITE_SURVEY_SCAN_TIME) {
		if (strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_scan_time > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_scan_time < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_SITE_SURVEY_SCAN_TIME;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_scan_time;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.site_survey_scan_time = strHostIFCfgParamAttr->pstrCfgParamVal.site_survey_scan_time;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & ACTIVE_SCANTIME) {
		/*range is 1 to 65535.*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.active_scan_time > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.active_scan_time < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_ACTIVE_SCAN_TIME;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.active_scan_time;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.active_scan_time = strHostIFCfgParamAttr->pstrCfgParamVal.active_scan_time;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & PASSIVE_SCANTIME) {
		/*range is 1 to 65535.*/
		if (strHostIFCfgParamAttr->pstrCfgParamVal.passive_scan_time > 0 &&
		    strHostIFCfgParamAttr->pstrCfgParamVal.passive_scan_time < 65536) {
			strWIDList[u8WidCnt].u16WIDid = WID_PASSIVE_SCAN_TIME;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&strHostIFCfgParamAttr->pstrCfgParamVal.passive_scan_time;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.passive_scan_time = strHostIFCfgParamAttr->pstrCfgParamVal.passive_scan_time;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	if (strHostIFCfgParamAttr->pstrCfgParamVal.u32SetCfgFlag & CURRENT_TX_RATE) {
		enum CURRENT_TX_RATE_T curr_tx_rate = strHostIFCfgParamAttr->pstrCfgParamVal.curr_tx_rate;
		/*
		 * Rates:		1   2   5.5   11   6  9  12  18  24  36  48   54  Auto
		 * InputValues:	1   2     3    4   5  6   7   8   9  10  11   12  0		*
		 */
		 /*validate rate*/
		if (curr_tx_rate == AUTORATE || curr_tx_rate == MBPS_1 ||
		    curr_tx_rate == MBPS_2 || curr_tx_rate == MBPS_5_5 ||
		    curr_tx_rate == MBPS_11 || curr_tx_rate == MBPS_6 ||
		    curr_tx_rate == MBPS_9 || curr_tx_rate == MBPS_12 ||
		    curr_tx_rate == MBPS_18 || curr_tx_rate == MBPS_24 ||
		    curr_tx_rate == MBPS_36 || curr_tx_rate == MBPS_48 ||
		    curr_tx_rate == MBPS_54) {
			strWIDList[u8WidCnt].u16WIDid = WID_CURRENT_TX_RATE;
			strWIDList[u8WidCnt].ps8WidVal = (s8 *)&curr_tx_rate;
			strWIDList[u8WidCnt].enuWIDtype = WID_SHORT;
			strWIDList[u8WidCnt].s32ValueSize = sizeof(u16);
			pstrWFIDrv->strCfgValues.curr_tx_rate = (u8)curr_tx_rate;
		} else {
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
		}
		u8WidCnt++;
	}
	s32Error = SendConfigPkt(SET_CFG, strWIDList, u8WidCnt, false, driver_handler_id);

	if (s32Error)
		PRINT_ER("Error in setting CFG params\n");


		  WILC_CATCH(s32Error)
		  {
		  }
	up(&(pstrWFIDrv->gtOsCfgValuesSem));
	return s32Error;
}

/*
 * this should be the last msg and then the msg Q becomes idle
 */
static signed int Handle_wait_msg_q_empty(void)
{
	signed int s32Error = WILC_SUCCESS;

	g_wilc_initialized = 0;
	up(&hWaitResponse);
	return s32Error;
}

/*
 * Sending config packet to firmware to set the scan params
 */
static signed int Handle_Scan(void *drvHandler,
			      struct tstrHostIFscanAttr *pstrHostIFscanAttr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWIDList[5];
	unsigned int u32WidsCount = 0;
	int driver_handler_id = 0;
	unsigned int i;
	u8 *pu8Buffer;
	u8 valuesize = 0;
	u8 *pu8HdnNtwrksWidVal = NULL;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;
	struct WILC_WFIDrv *pstrWFIDrvP2P  = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(P2P_IFC);
	struct WILC_WFIDrv *pstrWFIDrvWLAN = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(WLAN_IFC);

	PRINT_D(HOSTINF_DBG,"Setting SCAN params\n");
	PRINT_D(HOSTINF_DBG,"Scanning: In [%d] state \n", pstrWFIDrv->enuHostIFstate);

	pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult = pstrHostIFscanAttr->pfScanResult;
	pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid = pstrHostIFscanAttr->pvUserArg;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	/* If one of the two host interfaces has any state other than IDLE or CONNECTED, then abort the scan */
	if (pstrWFIDrvP2P != NULL) {
		if ((pstrWFIDrvP2P->enuHostIFstate != HOST_IF_IDLE) &&
	    (pstrWFIDrvP2P->enuHostIFstate != HOST_IF_CONNECTED)) {
			PRINT_D(GENERIC_DBG,"Don't scan. P2P_IFC is in state [%d]\n",
			 pstrWFIDrvP2P->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

	if (pstrWFIDrvWLAN != NULL) {
		if ((pstrWFIDrvWLAN->enuHostIFstate != HOST_IF_IDLE) &&
	    (pstrWFIDrvWLAN->enuHostIFstate != HOST_IF_CONNECTED)) {
			PRINT_D(GENERIC_DBG,"Don't scan. WLAN_IFC is in state [%d]\n",
			 pstrWFIDrvWLAN->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

	if(connecting) {
		PRINT_D(GENERIC_DBG, "[handle_scan]: Don't do scan in (CONNECTING) state\n");
		WILC_ERRORREPORT(s32Error, WILC_BUSY);
	}

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
	if (get_obtaining_IP_flag()) {
		PRINT_D(GENERIC_DBG, "[handle_scan]: Don't do obss scan until IP adresss is obtained\n");
		WILC_ERRORREPORT(s32Error, WILC_BUSY);
	}
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

	PRINT_D(HOSTINF_DBG,"Setting SCAN params\n");

	pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount = 0;

	strWIDList[u32WidsCount].u16WIDid = (u16)WID_SSID_PROBE_REQ;
	strWIDList[u32WidsCount].enuWIDtype = WID_STR;

	for (i = 0; i < pstrHostIFscanAttr->strHiddenNetwork.u8ssidnum; i++)
		valuesize += ((pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo[i].u8ssidlen) + 1);

	pu8HdnNtwrksWidVal = kmalloc(valuesize + 1, GFP_ATOMIC);
	strWIDList[u32WidsCount].ps8WidVal = pu8HdnNtwrksWidVal;
	if (strWIDList[u32WidsCount].ps8WidVal != NULL) {
		pu8Buffer = strWIDList[u32WidsCount].ps8WidVal;

		*pu8Buffer++ = pstrHostIFscanAttr->strHiddenNetwork.u8ssidnum;

		PRINT_D(HOSTINF_DBG,"In Handle_ProbeRequest number of ssid %d\n",
			 pstrHostIFscanAttr->strHiddenNetwork.u8ssidnum);

		for (i = 0; i < pstrHostIFscanAttr->strHiddenNetwork.u8ssidnum; i++) {
			*pu8Buffer++ = pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo[i].u8ssidlen;
			memcpy(pu8Buffer, pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo[i].pu8ssid, pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo[i].u8ssidlen);
			pu8Buffer += pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo[i].u8ssidlen;
		}

		strWIDList[u32WidsCount].s32ValueSize = (signed int)(valuesize + 1);
		u32WidsCount++;
	}

	/*filling cfg param array*/


	/* IEs to be inserted in Probe Request */
	strWIDList[u32WidsCount].u16WIDid = WID_INFO_ELEMENT_PROBE;
	strWIDList[u32WidsCount].enuWIDtype = WID_BIN_DATA;
	strWIDList[u32WidsCount].ps8WidVal = pstrHostIFscanAttr->pu8IEs;
	strWIDList[u32WidsCount].s32ValueSize = pstrHostIFscanAttr->IEsLen;
	u32WidsCount++;

	/*Scan Type*/
	strWIDList[u32WidsCount].u16WIDid = WID_SCAN_TYPE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrHostIFscanAttr->u8ScanType));
	u32WidsCount++;

	/*list of channels to be scanned*/
	strWIDList[u32WidsCount].u16WIDid = WID_SCAN_CHANNEL_LIST;
	strWIDList[u32WidsCount].enuWIDtype = WID_BIN_DATA;

	/* Bug 4648: Convert channel numbers to start from 0 not 1. */
	if (pstrHostIFscanAttr->pu8ChnlFreqList != NULL &&
	    pstrHostIFscanAttr->u8ChnlListLen > 0) {
		int i;

		for (i = 0; i < pstrHostIFscanAttr->u8ChnlListLen; i++)	{
			if (pstrHostIFscanAttr->pu8ChnlFreqList[i] > 0)
				pstrHostIFscanAttr->pu8ChnlFreqList[i] = pstrHostIFscanAttr->pu8ChnlFreqList[i] - 1;
		}
	}

	strWIDList[u32WidsCount].ps8WidVal = pstrHostIFscanAttr->pu8ChnlFreqList;
	strWIDList[u32WidsCount].s32ValueSize = pstrHostIFscanAttr->u8ChnlListLen;
	u32WidsCount++;

	/*Scan Request*/ 
	strWIDList[u32WidsCount].u16WIDid = WID_START_SCAN_REQ;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrHostIFscanAttr->u8ScanSource));
	u32WidsCount++;

	if (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED)
		gbScanWhileConnected = true;
	else if (pstrWFIDrv->enuHostIFstate == HOST_IF_IDLE)
		gbScanWhileConnected = false;

	s32Error = SendConfigPkt(SET_CFG, strWIDList, u32WidsCount, false, driver_handler_id);

	if (s32Error) {
		PRINT_ER("Failed to send scan paramters config packet\n");
		WILC_ERRORREPORT(s32Error, s32Error);
	} else {
		PRINT_D(HOSTINF_DBG,"Successfully sent SCAN params config packet\n");
		pstrWFIDrv->enuHostIFstate = HOST_IF_SCANNING;
	}
	WILC_CATCH(s32Error){
		del_timer(&(pstrWFIDrv->hScanTimer));
		/*if there is an ongoing scan request*/
		Handle_ScanDone(drvHandler, SCAN_EVENT_ABORTED);
	}

	/* Deallocate pstrHostIFscanAttr->u8ChnlListLen which was prevoisuly allocated by the sending thread */
	if (pstrHostIFscanAttr->pu8ChnlFreqList != NULL) {
		kfree(pstrHostIFscanAttr->pu8ChnlFreqList);
		pstrHostIFscanAttr->pu8ChnlFreqList = NULL;
	}

	/* Deallocate pstrHostIFscanAttr->pu8IEs which was previously allocated by the sending thread */
	if (pstrHostIFscanAttr->pu8IEs != NULL)	{
		kfree(pstrHostIFscanAttr->pu8IEs);
		pstrHostIFscanAttr->pu8IEs = NULL;
	}
	if (pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo != NULL)	{
		kfree(pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo);
		pstrHostIFscanAttr->strHiddenNetwork.pstrHiddenNetworkInfo = NULL;
	}

	/* Deallocate pstrHostIFscanAttr->u8ChnlListLen which was prevoisuly allocated by the sending thread */
	if (pstrHostIFscanAttr->pu8ChnlFreqList != NULL) {
		kfree(pstrHostIFscanAttr->pu8ChnlFreqList);
		pstrHostIFscanAttr->pu8ChnlFreqList = NULL;
	}

	if (pu8HdnNtwrksWidVal != NULL)
		kfree(pu8HdnNtwrksWidVal);

	return s32Error;
}

/*
 * Call scan notification callback function
 */
signed int Handle_ScanDone(void *drvHandler, enum tenuScanEvent enuEvent)
{
	signed int s32Error = WILC_SUCCESS;
	u8 u8abort_running_scan;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	PRINT_D(HOSTINF_DBG,"in Handle_ScanDone()\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	/*If scan is aborted then host interface state is not changed so keep it as it is.*/
	if(enuEvent == SCAN_EVENT_DONE){
		/* If Associated BSSID is NULL, then the interface state must have been IDLE before scanning */
		/* Otherwise, the interface state must have been CONNECTED before scanning */
		if (memcmp(pstrWFIDrv->au8AssociatedBSSID, au8NullBSSID, ETH_ALEN) == 0) {
			pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;
		} else {
			pstrWFIDrv->enuHostIFstate = HOST_IF_CONNECTED;
		}
	}
	
	/*BugID_4978
	*Ask FW to abort the running scan, if any
	*/
	else if (enuEvent == SCAN_EVENT_ABORTED) {
		PRINT_D(GENERIC_DBG,"Abort running scan\n");		
		u8abort_running_scan = 1;
		strWID.u16WIDid	= (u16)WID_ABORT_RUNNING_SCAN;
		strWID.enuWIDtype	= WID_CHAR;
		strWID.ps8WidVal = (s8 *)&u8abort_running_scan;
		strWID.s32ValueSize = sizeof(char);

		/*Sending Cfg*/
		s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
		if (s32Error != WILC_SUCCESS) {
			PRINT_ER("Failed to set abort running scan\n");
			WILC_ERRORREPORT(s32Error, WILC_FAIL);
		}
		WILC_CATCH(s32Error){
		}
	}

	if (pstrWFIDrv == NULL)	{
		PRINT_ER("Driver handler is NULL\n");		
		return s32Error;
	}

	/*if there is an ongoing scan request*/	
	if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
		pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult(enuEvent, NULL,
			pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid, NULL);
		/*delete current scan request*/
		pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult = NULL;
	}

	return s32Error;
}

/*
 * Sending config packet to firmware to starting connection
 */
u8 u8ConnectedSSID[6] = {0};
static signed int Handle_Connect(void *drvHandler,
				 struct tstrHostIFconnectAttr *pstrHostIFconnectAttr)
{
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;
	struct WILC_WFIDrv *pstrWFIDrvP2P  = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(P2P_IFC);
	struct WILC_WFIDrv *pstrWFIDrvWLAN = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(WLAN_IFC);
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWIDList[8];
	int driver_handler_id = 0;
	unsigned int u32WidsCount = 0, dummyval = 0;
#ifndef CONNECT_DIRECT
	signed int s32Err = WILC_SUCCESS;
	unsigned int i;
	u8 u8bssDscListIndex;
	struct wid_site_survey_reslts *pstrSurveyResults = NULL;
#else
	u8 *pu8CurrByte = NULL;
	/*Bug4218: Parsing Join Param*/
#ifdef WILC_PARSE_SCAN_IN_HOST
	struct tstrJoinBssParam *ptstrJoinBssParam;
#endif /*WILC_PARSE_SCAN_IN_HOST*/

#endif /* CONNECT_DIRECT */

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	/* If any interface is already scanning, then abort the scan */
	if (pstrWFIDrvP2P != NULL) {
		if (pstrWFIDrvP2P->enuHostIFstate == HOST_IF_SCANNING) {
			PRINT_D(GENERIC_DBG,"Don't scan. P2P_IFC is in state [%d]\n",
			 pstrWFIDrvP2P->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

	if (pstrWFIDrvWLAN != NULL) {
		if (pstrWFIDrvWLAN->enuHostIFstate == HOST_IF_SCANNING) {
			PRINT_D(GENERIC_DBG,"Don't scan. WLAN_IFC is in state [%d]\n",
			 pstrWFIDrvWLAN->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

#ifndef CONNECT_DIRECT
	memset(gapu8RcvdSurveyResults[0], 0, MAX_SURVEY_RESULT_FRAG_SIZE);
	memset(gapu8RcvdSurveyResults[1], 0, MAX_SURVEY_RESULT_FRAG_SIZE);

	PRINT_D(HOSTINF_DBG, "Getting site survey results\n");
	s32Err = host_int_get_site_survey_results((struct WFIDrvHandle *)pstrWFIDrv,
						  gapu8RcvdSurveyResults,
						  MAX_SURVEY_RESULT_FRAG_SIZE);
	if (s32Err) {
		PRINT_ER("Failed to get site survey results\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}
	s32Err = ParseSurveyResults(gapu8RcvdSurveyResults, &pstrSurveyResults,
				    &pstrWFIDrv->u32SurveyResultsCount);

	if (s32Err == WILC_SUCCESS) {
		/* use the parsed info in pstrSurveyResults, then deallocate it */
		PRINT_D(HOSTINF_DBG, "Copying site survey results in global structure, then deallocate\n");
		for (i = 0; i < pstrWFIDrv->u32SurveyResultsCount; i++)	{
			memcpy(&pstrWFIDrv->astrSurveyResults[i], &pstrSurveyResults[i],
			       sizeof(struct wid_site_survey_reslts));
		}

		DeallocateSurveyResults(pstrSurveyResults);
	} else {
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
		PRINT_ER("ParseSurveyResults, error %d\n", s32Err);
	}

	for (i = 0; i < pstrWFIDrv->u32SurveyResultsCount; i++)	{
		if (memcmp(pstrWFIDrv->astrSurveyResults[i].SSID,
			   pstrHostIFconnectAttr->pu8ssid,
			   pstrHostIFconnectAttr->ssidLen) == 0) {
			PRINT_INFO(HOSTINF_DBG,"Network with required SSID is found %s\n",
				pstrHostIFconnectAttr->pu8ssid);
			if (pstrHostIFconnectAttr->pu8bssid == NULL) {
				/* BSSID is not passed from the user, so decision of matching
				 * is done by SSID only
				 */
				PRINT_INFO(HOSTINF_DBG,"BSSID is not passed from the user\n");
				break;
			}
			if (memcmp(pstrWFIDrv->astrSurveyResults[i].BSSID,
				   pstrHostIFconnectAttr->pu8bssid,
				   6) == 0) {
					PRINT_INFO(HOSTINF_DBG,"BSSID is passed from the user and matched\n");
				break;
			}
		}
	}

	if (i < pstrWFIDrv->u32SurveyResultsCount) {
		u8bssDscListIndex = i;

		PRINT_INFO(HOSTINF_DBG,"Connecting to network of Bss Idx %d and SSID %s and channel %d\n",
			u8bssDscListIndex, pstrWFIDrv->astrSurveyResults[u8bssDscListIndex].SSID,
			pstrWFIDrv->astrSurveyResults[u8bssDscListIndex].Channel);

		PRINT_INFO(HOSTINF_DBG,"Saving connection parameters in global structure\n");

		if (pstrHostIFconnectAttr->pu8bssid != NULL) {
			pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = kmalloc(6, GFP_ATOMIC);
			memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, pstrHostIFconnectAttr->pu8bssid, 6);
		}

		pstrWFIDrv->strWILC_UsrConnReq.ssidLen = pstrHostIFconnectAttr->ssidLen;
		if (pstrHostIFconnectAttr->pu8ssid != NULL) {
			pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = kmalloc(pstrHostIFconnectAttr->ssidLen + 1, GFP_ATOMIC);
			memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid,
			       pstrHostIFconnectAttr->pu8ssid,
			       pstrHostIFconnectAttr->ssidLen);
			pstrWFIDrv->strWILC_UsrConnReq.pu8ssid[pstrHostIFconnectAttr->ssidLen] = '\0';
		}

		pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = pstrHostIFconnectAttr->IEsLen;
		if (pstrHostIFconnectAttr->pu8IEs != NULL) {
			pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = kmalloc(pstrHostIFconnectAttr->IEsLen, GFP_ATOMIC);
			memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs,
			       pstrHostIFconnectAttr->pu8IEs,
			       pstrHostIFconnectAttr->IEsLen);
		}

		pstrWFIDrv->strWILC_UsrConnReq.u8security = pstrHostIFconnectAttr->u8security;
		pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type = pstrHostIFconnectAttr->tenuAuth_type;
		pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult = pstrHostIFconnectAttr->pfConnectResult;
		pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid = pstrHostIFconnectAttr->pvUserArg;

		/* IEs to be inserted in Association Request */
		strWIDList[u32WidsCount].u16WIDid = WID_INFO_ELEMENT_ASSOCIATE;
		strWIDList[u32WidsCount].enuWIDtype = WID_BIN_DATA;
		strWIDList[u32WidsCount].ps8WidVal = pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs;
		strWIDList[u32WidsCount].s32ValueSize = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
		u32WidsCount++;
		strWIDList[u32WidsCount].u16WIDid = (u16)WID_11I_MODE;
		strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
		strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
		strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrWFIDrv->strWILC_UsrConnReq.u8security));
		u32WidsCount++;

		PRINT_INFO(HOSTINF_DBG,"Encrypt Mode = %x\n", pstrWFIDrv->strWILC_UsrConnReq.u8security);

		strWIDList[u32WidsCount].u16WIDid = (u16)WID_AUTH_TYPE;
		strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
		strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
		strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type);
		u32WidsCount++;

		PRINT_INFO(HOSTINF_DBG,"Authentication Type = %x\n",
			pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type);

		strWIDList[u32WidsCount].u16WIDid = (u16)WID_JOIN_REQ;
		strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
		strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
		strWIDList[u32WidsCount].ps8WidVal = (s8 *)&u8bssDscListIndex;
		u32WidsCount++;

		/* A temporary workaround to avoid handling the misleading MAC_DISCONNECTED raised from the 
		*  firmware at chip reset when processing the WIDs of the Connect Request.
		*  (This workaround should be removed in the future when the Chip reset of the Connect WIDs is disabled)
		*/
		gu32WidConnRstHack = 0;

		s32Error = SendConfigPkt(SET_CFG, strWIDList, u32WidsCount, false, driver_handler_id);
		if (s32Error) {
			PRINT_ER("Handle_Connect, failed to send config packet\n");
			WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
		} else {
			pstrWFIDrv->enuHostIFstate = HOST_IF_WAITING_CONN_RESP;
		}
	} else {
		PRINT_ER("Required BSSID not found\n");
		WILC_ERRORREPORT(s32Error, WILC_NOT_FOUND);
	}

#else
	/* if we try to connect to an already connected AP then discard the request*/
	if (memcmp(pstrHostIFconnectAttr->pu8bssid, u8ConnectedSSID, ETH_ALEN) == 0) {
		s32Error = WILC_SUCCESS;
		PRINT_ER("Trying to connect to an already connected AP, Discard connect request\n");
		return s32Error;
	}

	PRINT_INFO(HOSTINF_DBG, "Saving connection parameters in global structure\n");

	/*Bug4218: Parsing Join Param*/
#ifdef WILC_PARSE_SCAN_IN_HOST
	ptstrJoinBssParam = (struct tstrJoinBssParam *)pstrHostIFconnectAttr->pJoinParams;
	if (ptstrJoinBssParam == NULL) {
		PRINT_ER("Required BSSID not found\n");
		WILC_ERRORREPORT(s32Error, WILC_NOT_FOUND);
	}
#endif /*WILC_PARSE_SCAN_IN_HOST*/

	if (pstrHostIFconnectAttr->pu8bssid != NULL) {
		pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = kmalloc(6, GFP_ATOMIC);
		memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, pstrHostIFconnectAttr->pu8bssid, 6);
	}

	pstrWFIDrv->strWILC_UsrConnReq.ssidLen = pstrHostIFconnectAttr->ssidLen;
	if (pstrHostIFconnectAttr->pu8ssid != NULL) {
		pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = kmalloc(pstrHostIFconnectAttr->ssidLen + 1, GFP_ATOMIC);
		memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid, pstrHostIFconnectAttr->pu8ssid,
		       pstrHostIFconnectAttr->ssidLen);
		pstrWFIDrv->strWILC_UsrConnReq.pu8ssid[pstrHostIFconnectAttr->ssidLen] = '\0';
	}

	pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = pstrHostIFconnectAttr->IEsLen;
	if (pstrHostIFconnectAttr->pu8IEs != NULL) {
		pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = kmalloc(pstrHostIFconnectAttr->IEsLen, GFP_ATOMIC);
		memcpy(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs, pstrHostIFconnectAttr->pu8IEs,
		       pstrHostIFconnectAttr->IEsLen);
	}

	pstrWFIDrv->strWILC_UsrConnReq.u8security = pstrHostIFconnectAttr->u8security;
	pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type = pstrHostIFconnectAttr->tenuAuth_type;
	pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult = pstrHostIFconnectAttr->pfConnectResult;
	pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid = pstrHostIFconnectAttr->pvUserArg;

	strWIDList[u32WidsCount].u16WIDid = WID_SUCCESS_FRAME_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(dummyval));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_RECEIVED_FRAGMENT_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(dummyval));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_FAILED_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(dummyval));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_INFO_ELEMENT_ASSOCIATE;
	strWIDList[u32WidsCount].enuWIDtype = WID_BIN_DATA;
	strWIDList[u32WidsCount].ps8WidVal = pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs;
	strWIDList[u32WidsCount].s32ValueSize = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
	u32WidsCount++;

	if (memcmp("DIRECT-", pstrHostIFconnectAttr->pu8ssid, 7)) {
		gu32FlushedInfoElemAsocSize = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
		gu8FlushedInfoElemAsoc =  kmalloc(gu32FlushedInfoElemAsocSize, GFP_ATOMIC);
		memcpy(gu8FlushedInfoElemAsoc, pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs,
		       gu32FlushedInfoElemAsocSize);
	}
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_11I_MODE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrWFIDrv->strWILC_UsrConnReq.u8security));
	u32WidsCount++;

	if (memcmp("DIRECT-", pstrHostIFconnectAttr->pu8ssid, 7))
		gu8Flushed11iMode = pstrWFIDrv->strWILC_UsrConnReq.u8security;

	PRINT_INFO(HOSTINF_DBG, "Encrypt Mode = %x\n", pstrWFIDrv->strWILC_UsrConnReq.u8security);

	strWIDList[u32WidsCount].u16WIDid = (u16)WID_AUTH_TYPE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type);
	u32WidsCount++;

	if (memcmp("DIRECT-", pstrHostIFconnectAttr->pu8ssid, 7))
		gu8FlushedAuthType = (u8)pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type;

	PRINT_INFO(HOSTINF_DBG, "Authentication Type = %x\n", pstrWFIDrv->strWILC_UsrConnReq.tenuAuth_type);

	PRINT_D(HOSTINF_DBG, "Connecting to network of SSID %s on channel %d\n",
		 pstrWFIDrv->strWILC_UsrConnReq.pu8ssid, pstrHostIFconnectAttr->u8channel);

#ifndef WILC_PARSE_SCAN_IN_HOST
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_JOIN_REQ_EXTENDED;
	strWIDList[u32WidsCount].enuWIDtype = WID_STR;
	strWIDList[u32WidsCount].s32ValueSize = MAX_SSID_LEN + 7;
	strWIDList[u32WidsCount].ps8WidVal = kmalloc(strWIDList[u32WidsCount].s32ValueSize, GFP_ATOMIC);

	if (strWIDList[u32WidsCount].ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWIDList[u32WidsCount].ps8WidVal;

	if (pstrHostIFconnectAttr->pu8ssid != NULL) {
		memcpy(pu8CurrByte, pstrHostIFconnectAttr->pu8ssid,
		       pstrHostIFconnectAttr->ssidLen);
		pu8CurrByte[pstrHostIFconnectAttr->ssidLen] = '\0';
	}
	pu8CurrByte += MAX_SSID_LEN;
	if ((pstrHostIFconnectAttr->u8channel >= 1) && (pstrHostIFconnectAttr->u8channel <= 14)) {
		*(pu8CurrByte++) = pstrHostIFconnectAttr->u8channel;
	} else {
		PRINT_ER("Channel out of range\n");
		*(pu8CurrByte++) = 0xFF;
	}
	if (pstrHostIFconnectAttr->pu8bssid != NULL)
		memcpy(pu8CurrByte, pstrHostIFconnectAttr->pu8bssid, 6);
	pu8CurrByte += 6;

	/* keep the buffer at the start of the allocated pointer to use it with the free*/
	pu8CurrByte = strWIDList[u32WidsCount].ps8WidVal;
#else
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_JOIN_REQ_EXTENDED;
	strWIDList[u32WidsCount].enuWIDtype = WID_STR;

	/*Sending NoA attributes during connection*/
	strWIDList[u32WidsCount].s32ValueSize = 112;
	strWIDList[u32WidsCount].ps8WidVal = kmalloc(strWIDList[u32WidsCount].s32ValueSize, GFP_ATOMIC);

	/*BugID_5137*/
	if (memcmp("DIRECT-", pstrHostIFconnectAttr->pu8ssid, 7)) {
		gu32FlushedJoinReqSize = strWIDList[u32WidsCount].s32ValueSize;
		gu8FlushedJoinReq = kmalloc(gu32FlushedJoinReqSize, GFP_ATOMIC);
	}
	if (strWIDList[u32WidsCount].ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWIDList[u32WidsCount].ps8WidVal;

	if (pstrHostIFconnectAttr->pu8ssid != NULL) {
		memcpy(pu8CurrByte, pstrHostIFconnectAttr->pu8ssid,
		       pstrHostIFconnectAttr->ssidLen);
		pu8CurrByte[pstrHostIFconnectAttr->ssidLen] = '\0';
	}
	pu8CurrByte += MAX_SSID_LEN;

	/* BSS type*/
	*(pu8CurrByte++) = INFRASTRUCTURE;
	/* Channel*/
	if ((pstrHostIFconnectAttr->u8channel >= 1) && (pstrHostIFconnectAttr->u8channel <= 14)) {
		*(pu8CurrByte++) = pstrHostIFconnectAttr->u8channel;
	} else {
		PRINT_ER("Channel out of range\n");
		*(pu8CurrByte++) = 0xFF;
	}
	/* Cap Info*/
	*(pu8CurrByte++) = (ptstrJoinBssParam->cap_info) & 0xFF;
	*(pu8CurrByte++) = ((ptstrJoinBssParam->cap_info) >> 8) & 0xFF;
	PRINT_D(HOSTINF_DBG, "* Cap Info %0x*\n", (*(pu8CurrByte - 2) | ((*(pu8CurrByte - 1)) << 8)));

	/* sa*/
	if (pstrHostIFconnectAttr->pu8bssid != NULL)
		memcpy(pu8CurrByte, pstrHostIFconnectAttr->pu8bssid, 6);
	pu8CurrByte += 6;

	/* bssid*/
	if (pstrHostIFconnectAttr->pu8bssid != NULL)
		memcpy(pu8CurrByte, pstrHostIFconnectAttr->pu8bssid, 6);
	pu8CurrByte += 6;

	/* Beacon Period*/
	*(pu8CurrByte++)  = (ptstrJoinBssParam->beacon_period) & 0xFF;
	*(pu8CurrByte++)  = ((ptstrJoinBssParam->beacon_period) >> 8) & 0xFF;
	PRINT_D(HOSTINF_DBG, "* Beacon Period %d*\n", (*(pu8CurrByte - 2) | ((*(pu8CurrByte - 1)) << 8)));

	*(pu8CurrByte++)  =  ptstrJoinBssParam->dtim_period;
	PRINT_D(HOSTINF_DBG, "* DTIM Period %d*\n", (*(pu8CurrByte - 1)));

	memcpy(pu8CurrByte, ptstrJoinBssParam->supp_rates, MAX_RATES_SUPPORTED + 1);
	pu8CurrByte += (MAX_RATES_SUPPORTED + 1);

	/* wmm cap*/
	*(pu8CurrByte++)  =  ptstrJoinBssParam->wmm_cap;
	PRINT_D(HOSTINF_DBG, "* wmm cap%d*\n", (*(pu8CurrByte - 1)));
	/* uapsd cap*/
	*(pu8CurrByte++)  = ptstrJoinBssParam->uapsd_cap;

	/* ht cap*/
	*(pu8CurrByte++)  = ptstrJoinBssParam->ht_capable;
	/*copy this information to the user request*/
	pstrWFIDrv->strWILC_UsrConnReq.IsHTCapable = ptstrJoinBssParam->ht_capable;

	/* rsn found*/
	*(pu8CurrByte++)  =  ptstrJoinBssParam->rsn_found;
	PRINT_D(HOSTINF_DBG, "* rsn found %d*\n", *(pu8CurrByte - 1));
	/* rsn group policy*/
	*(pu8CurrByte++)  =  ptstrJoinBssParam->rsn_grp_policy;
	PRINT_D(HOSTINF_DBG, "* rsn group policy %0x*\n", (*(pu8CurrByte - 1)));
	/* mode_802_11i*/
	*(pu8CurrByte++) =  ptstrJoinBssParam->mode_802_11i;
	PRINT_D(HOSTINF_DBG, "* mode_802_11i %d*\n", (*(pu8CurrByte - 1)));
	/* rsn pcip policy*/
	memcpy(pu8CurrByte, ptstrJoinBssParam->rsn_pcip_policy,
	       sizeof(ptstrJoinBssParam->rsn_pcip_policy));
	pu8CurrByte += sizeof(ptstrJoinBssParam->rsn_pcip_policy);

	/* rsn auth policy*/
	memcpy(pu8CurrByte, ptstrJoinBssParam->rsn_auth_policy,
	       sizeof(ptstrJoinBssParam->rsn_auth_policy));
	pu8CurrByte += sizeof(ptstrJoinBssParam->rsn_auth_policy);

	memcpy(pu8CurrByte, ptstrJoinBssParam->rsn_cap,
	       sizeof(ptstrJoinBssParam->rsn_cap));
	pu8CurrByte += sizeof(ptstrJoinBssParam->rsn_cap);

	*(pu8CurrByte++) = REAL_JOIN_REQ;

#ifdef WILC_P2P
	*(pu8CurrByte++) = ptstrJoinBssParam->u8NoaEnbaled;
	if (ptstrJoinBssParam->u8NoaEnbaled) {
		PRINT_D(HOSTINF_DBG, "NOA present\n");

		*(pu8CurrByte++) = (ptstrJoinBssParam->tsf) & 0xFF;
		*(pu8CurrByte++) = ((ptstrJoinBssParam->tsf) >> 8) & 0xFF;
		*(pu8CurrByte++) = ((ptstrJoinBssParam->tsf) >> 16) & 0xFF;
		*(pu8CurrByte++) = ((ptstrJoinBssParam->tsf) >> 24) & 0xFF;

		*(pu8CurrByte++) = ptstrJoinBssParam->u8Index;

		*(pu8CurrByte++) = ptstrJoinBssParam->u8OppEnable;

		if (ptstrJoinBssParam->u8OppEnable)
			*(pu8CurrByte++) = ptstrJoinBssParam->u8CtWindow;

		*(pu8CurrByte++) = ptstrJoinBssParam->u8Count;

		memcpy(pu8CurrByte, ptstrJoinBssParam->au8Duration,
		       sizeof(ptstrJoinBssParam->au8Duration));

		pu8CurrByte += sizeof(ptstrJoinBssParam->au8Duration);

		memcpy(pu8CurrByte, ptstrJoinBssParam->au8Interval,
		       sizeof(ptstrJoinBssParam->au8Interval));

		pu8CurrByte += sizeof(ptstrJoinBssParam->au8Interval);

		memcpy(pu8CurrByte, ptstrJoinBssParam->au8StartTime,
		       sizeof(ptstrJoinBssParam->au8StartTime));

		pu8CurrByte += sizeof(ptstrJoinBssParam->au8StartTime);
	} else {
		PRINT_D(HOSTINF_DBG, "NOA not present\n");
	}
#endif /* WILC_P2P */

	/* keep the buffer at the start of the allocated pointer to use it with the free*/
	pu8CurrByte = strWIDList[u32WidsCount].ps8WidVal;

#endif /* WILC_PARSE_SCAN_IN_HOST*/
	u32WidsCount++;

	/* A temporary workaround to avoid handling the misleading MAC_DISCONNECTED raised from the 
	* firmware at chip reset when processing the WIDs of the Connect Request.
	*(This workaround should be removed in the future when the Chip reset of the Connect WIDs is disabled)
	*/
	gu32WidConnRstHack = 0;

	if (memcmp("DIRECT-", pstrHostIFconnectAttr->pu8ssid, 7)) {
		memcpy(gu8FlushedJoinReq, pu8CurrByte, gu32FlushedJoinReqSize);
		gu8FlushedJoinReqDrvHandler = (unsigned int)pstrWFIDrv;
	}

	PRINT_D(GENERIC_DBG,"send HOST_IF_WAITING_CONN_RESP\n");

	if (pstrHostIFconnectAttr->pu8bssid != NULL) {
		memcpy(u8ConnectedSSID, pstrHostIFconnectAttr->pu8bssid, ETH_ALEN);

		PRINT_D(HOSTINF_DBG, "save Bssid = %x:%x:%x:%x:%x:%x\n",
			 (pstrHostIFconnectAttr->pu8bssid[0]),
			 (pstrHostIFconnectAttr->pu8bssid[1]),
			 (pstrHostIFconnectAttr->pu8bssid[2]),
			 (pstrHostIFconnectAttr->pu8bssid[3]),
			 (pstrHostIFconnectAttr->pu8bssid[4]),
			 (pstrHostIFconnectAttr->pu8bssid[5]));
		PRINT_D(HOSTINF_DBG, "save bssid = %x:%x:%x:%x:%x:%x\n",
			 (u8ConnectedSSID[0]), (u8ConnectedSSID[1]),
			 (u8ConnectedSSID[2]), (u8ConnectedSSID[3]),
			 (u8ConnectedSSID[4]), (u8ConnectedSSID[5]));
	}

	s32Error = SendConfigPkt(SET_CFG, strWIDList, u32WidsCount, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Handle_Connect()] failed to send config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_D(GENERIC_DBG,"set HOST_IF_WAITING_CONN_RESP\n");
		pstrWFIDrv->enuHostIFstate = HOST_IF_WAITING_CONN_RESP;
	}
#endif /* CONNECT_DIRECT */

	WILC_CATCH(s32Error){
		struct tstrConnectInfo strConnectInfo;

		del_timer(&(pstrWFIDrv->hConnectTimer));

		PRINT_D(HOSTINF_DBG, "could not start connecting to the required network\n");

		memset(&strConnectInfo, 0, sizeof(struct tstrConnectInfo));

		if (pstrHostIFconnectAttr->pfConnectResult != NULL) {
			if (pstrHostIFconnectAttr->pu8bssid != NULL)
				memcpy(strConnectInfo.au8bssid,
				       pstrHostIFconnectAttr->pu8bssid, 6);

			if (pstrHostIFconnectAttr->pu8IEs != NULL) {
				strConnectInfo.ReqIEsLen = pstrHostIFconnectAttr->IEsLen;
				strConnectInfo.pu8ReqIEs = kmalloc(pstrHostIFconnectAttr->IEsLen, GFP_ATOMIC);
				memcpy(strConnectInfo.pu8ReqIEs,
				       pstrHostIFconnectAttr->pu8IEs,
				       pstrHostIFconnectAttr->IEsLen);
			}

			pstrHostIFconnectAttr->pfConnectResult(CONN_DISCONN_EVENT_CONN_RESP,
							       &strConnectInfo,
							       MAC_DISCONNECTED,
							       NULL,
							       pstrHostIFconnectAttr->pvUserArg);
			pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;
			if (strConnectInfo.pu8ReqIEs != NULL) {
				kfree(strConnectInfo.pu8ReqIEs);
				strConnectInfo.pu8ReqIEs = NULL;
			}
		} else {
			PRINT_ER("Connect callback function pointer is NULL\n");
		}
	}

	PRINT_D(HOSTINF_DBG, "Deallocating connection parameters\n");
	/* Deallocate pstrHostIFconnectAttr->pu8bssid which was prevoisuly allocated by the sending thread */
	if (pstrHostIFconnectAttr->pu8bssid != NULL) {
		kfree(pstrHostIFconnectAttr->pu8bssid);
		pstrHostIFconnectAttr->pu8bssid = NULL;
	}

	/* Deallocate pstrHostIFconnectAttr->pu8ssid which was prevoisuly allocated by the sending thread */
	if (pstrHostIFconnectAttr->pu8ssid != NULL) {
		kfree(pstrHostIFconnectAttr->pu8ssid);
		pstrHostIFconnectAttr->pu8ssid = NULL;
	}

	/* Deallocate pstrHostIFconnectAttr->pu8IEs which was prevoisuly allocated by the sending thread */
	if (pstrHostIFconnectAttr->pu8IEs != NULL) {
		kfree(pstrHostIFconnectAttr->pu8IEs);
		pstrHostIFconnectAttr->pu8IEs = NULL;
	}

	if (pu8CurrByte != NULL)
		kfree(pu8CurrByte);
	return s32Error;
}

/*
 * Sending config packet to firmware to flush an old connection
 * after switching FW from station one to hybrid one
 */

static signed int Handle_FlushConnect(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWIDList[5];
	unsigned int u32WidsCount = 0;
	int driver_handler_id = 0;
	u8 *pu8CurrByte = NULL;
	struct WILC_WFIDrv *pstrWFIDrv;

	/* IEs to be inserted in Association Request */
	strWIDList[u32WidsCount].u16WIDid = WID_INFO_ELEMENT_ASSOCIATE;
	strWIDList[u32WidsCount].enuWIDtype = WID_BIN_DATA;
	strWIDList[u32WidsCount].ps8WidVal = gu8FlushedInfoElemAsoc;
	strWIDList[u32WidsCount].s32ValueSize = gu32FlushedInfoElemAsocSize;
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = (u16)WID_11I_MODE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(gu8Flushed11iMode));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = (u16)WID_AUTH_TYPE;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&gu8FlushedAuthType);
	u32WidsCount++;

#ifdef WILC_PARSE_SCAN_IN_HOST
	strWIDList[u32WidsCount].u16WIDid = (u16)WID_JOIN_REQ_EXTENDED;
	strWIDList[u32WidsCount].enuWIDtype = WID_STR;
	strWIDList[u32WidsCount].s32ValueSize = gu32FlushedJoinReqSize;
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)gu8FlushedJoinReq;
	pu8CurrByte = strWIDList[u32WidsCount].ps8WidVal;

	pu8CurrByte += FLUSHED_BYTE_POS;
	*(pu8CurrByte) = FLUSHED_JOIN_REQ;

	u32WidsCount++;

#endif /* WILC_PARSE_SCAN_IN_HOST */
	pstrWFIDrv = (struct WILC_WFIDrv *)gu8FlushedJoinReqDrvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
		
	s32Error = SendConfigPkt(SET_CFG, strWIDList, u32WidsCount, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Handle_Flush_Connect()] failed to send config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Call connect notification callback function indicating connection failure
 */
static signed int Handle_ConnectTimeout(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrConnectInfo strConnectInfo;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u16 u16DummyReasonCode = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;

	if (pstrWFIDrv == NULL)	{
		PRINT_ER("Driver handler is NULL\n");
		return s32Error;
	}

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;

	gbScanWhileConnected = false;

	memset(&strConnectInfo, 0, sizeof(struct tstrConnectInfo));

	if (pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult != NULL) {
		if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL)
			memcpy(strConnectInfo.au8bssid,
			       pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, 6);

		if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
			strConnectInfo.ReqIEsLen = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
			strConnectInfo.pu8ReqIEs = kmalloc(pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen, GFP_ATOMIC);
			memcpy(strConnectInfo.pu8ReqIEs,
			       pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs,
			       pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen);
		}

		pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_CONN_RESP,
								   &strConnectInfo,
								   MAC_DISCONNECTED,
								   NULL,
								   pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);

		/* Deallocation of strConnectInfo.pu8ReqIEs */
		if (strConnectInfo.pu8ReqIEs != NULL) {
			kfree(strConnectInfo.pu8ReqIEs);
			strConnectInfo.pu8ReqIEs = NULL;
		}
	} else {
		PRINT_ER("Connect callback function pointer is NULL\n");
	}
	/* Here we will notify our firmware also with the Connection failure {through sending to it Cfg packet carrying 
	*WID_DISCONNECT}
	*/
	strWID.u16WIDid = (u16)WID_DISCONNECT;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)&u16DummyReasonCode;
	strWID.s32ValueSize = sizeof(char);

	PRINT_D(HOSTINF_DBG, "Sending disconnect request\n");

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error)
		PRINT_ER("Failed to send dissconect config packet\n");

	/* Deallocation of the Saved Connect Request in the global Handle */	
	pstrWFIDrv->strWILC_UsrConnReq.ssidLen = 0;
	if (pstrWFIDrv->strWILC_UsrConnReq.pu8ssid != NULL) {
		kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid);
		pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = NULL;
	}

	if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL) {
		kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid);
		pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = NULL;
	}

	pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = 0;
	if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
		kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs);
		pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = NULL;
	}

	memset(u8ConnectedSSID, 0, ETH_ALEN);
	/*BugID_5213*/
	/*Freeing flushed join request params on connect timeout*/
	if (gu8FlushedJoinReq != NULL &&
	    gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
		kfree(gu8FlushedJoinReq);
		gu8FlushedJoinReq = NULL;
	}
	if (gu8FlushedInfoElemAsoc != NULL &&
	    gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
		kfree(gu8FlushedInfoElemAsoc);
		gu8FlushedInfoElemAsoc = NULL;
	}

	return s32Error;
}

/*
 * Handling received network information
 */
static signed int Handle_RcvdNtwrkInfo(void *drvHandler,
				       struct tstrRcvdNetworkInfo *pstrRcvdNetworkInfo)
{
	unsigned int i;
	bool bNewNtwrkFound;

	signed int s32Error = WILC_SUCCESS;
	struct tstrNetworkInfo *pstrNetworkInfo = NULL;
	void *pJoinParams = NULL;

	struct WILC_WFIDrv *pstrWFIDrv  = (struct WILC_WFIDrv *)drvHandler;

	bNewNtwrkFound = true;
	PRINT_INFO(HOSTINF_DBG, "Handling received network info\n");

	/*if there is a an ongoing scan request*/
	if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
		PRINT_D(HOSTINF_DBG, "State: Scanning, parsing network information received\n");
		ParseNetworkInfo(pstrRcvdNetworkInfo->pu8Buffer, &pstrNetworkInfo);
		if ((pstrNetworkInfo == NULL)
		    || (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult == NULL))
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

		/* check whether this network is discovered before */
		for (i = 0; i < pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount; i++) {
			if ((pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[i].au8bssid != NULL) &&
			    (pstrNetworkInfo->au8bssid != NULL))
				if (memcmp(pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[i].au8bssid,
					   pstrNetworkInfo->au8bssid, 6) == 0) {
					if (pstrNetworkInfo->s8rssi <= pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[i].s8rssi)	{
						/*we have already found this network with better rssi, so keep the old cached one and don't 
						*send anything to the upper layer 
						*/
						PRINT_D(HOSTINF_DBG, "Network previously discovered\n");
						goto done;
					} else {
						/* here the same already found network is found again but with a better rssi, so just update 
				     	* the rssi for this cached network and send this updated network to the upper layer but 
				     	*don't add a new record for it
						*/
						pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[i].s8rssi = pstrNetworkInfo->s8rssi;
						bNewNtwrkFound = false;
						break;
					}
				}
		}

		if (bNewNtwrkFound == true) {
			/* here it is confirmed that it is a new discovered network,
			 * so add its record then call the User CallBack function
			 */
			PRINT_D(HOSTINF_DBG, "New network found\n");

			if (pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount < MAX_NUM_SCANNED_NETWORKS)	{
				pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount].s8rssi = pstrNetworkInfo->s8rssi;

				if ((pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount].au8bssid != NULL)
				    && (pstrNetworkInfo->au8bssid != NULL)) {
					memcpy(pstrWFIDrv->strWILC_UsrScanReq.astrFoundNetworkInfo[pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount].au8bssid,
					       pstrNetworkInfo->au8bssid, 6);

					pstrWFIDrv->strWILC_UsrScanReq.u32RcvdChCount++;

					pstrNetworkInfo->bNewNetwork = true;
				/*Bug4218: Parsing Join Param
				*add new BSS to JoinBssTable
				*/
#ifdef WILC_PARSE_SCAN_IN_HOST
					pJoinParams = host_int_ParseJoinBssParam(pstrNetworkInfo);
#endif /*WILC_PARSE_SCAN_IN_HOST*/

					pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult(SCAN_EVENT_NETWORK_FOUND, pstrNetworkInfo,
											  pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid,
											  pJoinParams);
				}
			} else {
				PRINT_WRN(HOSTINF_DBG, "Discovered networks exceeded max. limit\n");
			}
		} else {
			pstrNetworkInfo->bNewNetwork = false;
			/* just call the User CallBack function to send the same discovered network with its updated RSSI */
			pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult(SCAN_EVENT_NETWORK_FOUND, pstrNetworkInfo,
									  pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid, NULL);
		}
	}

	WILC_CATCH(s32Error){
	}
done:
	/* Deallocate pstrRcvdNetworkInfo->pu8Buffer which was prevoisuly allocated by the sending thread */
	if (pstrRcvdNetworkInfo->pu8Buffer != NULL) {
		kfree(pstrRcvdNetworkInfo->pu8Buffer);
		pstrRcvdNetworkInfo->pu8Buffer = NULL;
	}

	/*free structure allocated*/
	if (pstrNetworkInfo != NULL) {
		DeallocateNetworkInfo(pstrNetworkInfo);
		pstrNetworkInfo = NULL;
	}

	return s32Error;
}

/*
 * Handling received asynchrous general network information
 */
static signed int Handle_RcvdGnrlAsyncInfo(void *drvHandler,
					   struct tstrRcvdGnrlAsyncInfo *pstrRcvdGnrlAsyncInfo)
{
	/*TODO: till now, this function just handles only the received mac status msg, 
	*				 which carries only 1 WID which have WID ID = WID_STATUS
	*/
	signed int s32Error = WILC_SUCCESS;
	u8 u8MsgType = 0;
	u8 u8MsgID = 0;
	u16 u16MsgLen = 0;
	u16 u16WidID = (u16)WID_NIL;
	u8 u8WidLen  = 0;
	u8 u8MacStatus;
	u8 u8MacStatusReasonCode;
	u8 u8MacStatusAdditionalInfo;
	struct tstrConnectInfo strConnectInfo;
	struct tstrDisconnectNotifInfo strDisconnectNotifInfo;
	signed int s32Err = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;

	if (pstrWFIDrv == NULL)
		PRINT_ER("Driver handler is NULL\n");
	PRINT_D(GENERIC_DBG, "Current State = %d,Received state = %d\n",
		 pstrWFIDrv->enuHostIFstate,
		 pstrRcvdGnrlAsyncInfo->pu8Buffer[7]);

	if ((pstrWFIDrv->enuHostIFstate == HOST_IF_WAITING_CONN_RESP) ||
	    (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED) ||
	    pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
		if ((pstrRcvdGnrlAsyncInfo->pu8Buffer == NULL) ||
		    (pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult == NULL))
			WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

		u8MsgType = pstrRcvdGnrlAsyncInfo->pu8Buffer[0];

		/* Check whether the received message type is 'I' */
		if('I' != u8MsgType)
		{
			PRINT_ER("Received Message format incorrect.\n");
			WILC_ERRORREPORT(s32Error, WILC_FAIL);
		}

		/* Extract message ID */
		u8MsgID = pstrRcvdGnrlAsyncInfo->pu8Buffer[1];

		/* Extract message Length */
		u16MsgLen = MAKE_WORD16(pstrRcvdGnrlAsyncInfo->pu8Buffer[2],
					pstrRcvdGnrlAsyncInfo->pu8Buffer[3]);

		/* Extract WID ID [expected to be = WID_STATUS] */
		u16WidID = MAKE_WORD16(pstrRcvdGnrlAsyncInfo->pu8Buffer[4],
				       pstrRcvdGnrlAsyncInfo->pu8Buffer[5]);

		/* Extract WID Length [expected to be = 1] */
		u8WidLen = pstrRcvdGnrlAsyncInfo->pu8Buffer[6];

		/* get the WID value [expected to be one of two values: either MAC_CONNECTED = (1) or MAC_DISCONNECTED = (0)] */
		u8MacStatus  = pstrRcvdGnrlAsyncInfo->pu8Buffer[7];
		u8MacStatusReasonCode = pstrRcvdGnrlAsyncInfo->pu8Buffer[8];
		u8MacStatusAdditionalInfo = pstrRcvdGnrlAsyncInfo->pu8Buffer[9];
		PRINT_D(HOSTINF_DBG, "Recieved MAC status = %d with Reason = %d , Info = %d\n",
			u8MacStatus, u8MacStatusReasonCode,
			 u8MacStatusAdditionalInfo);
		if (pstrWFIDrv->enuHostIFstate == HOST_IF_WAITING_CONN_RESP) {
			/* our station had sent Association Request frame, so here it will get the Association Response frame then parse it */
			unsigned int u32RcvdAssocRespInfoLen;
			struct tstrConnectRespInfo *pstrConnectRespInfo = NULL;

			PRINT_D(HOSTINF_DBG, "Recieved MAC status = %d with Reason = %d , Code = %d\n",
				 u8MacStatus, u8MacStatusReasonCode,
				 u8MacStatusAdditionalInfo);

			memset(&strConnectInfo, 0, sizeof(struct tstrConnectInfo));

			if (u8MacStatus == MAC_CONNECTED) {
				memset(gapu8RcvdAssocResp, 0, MAX_ASSOC_RESP_FRAME_SIZE);

				host_int_get_assoc_res_info((struct WFIDrvHandle *)pstrWFIDrv,
							    gapu8RcvdAssocResp,
							    MAX_ASSOC_RESP_FRAME_SIZE,
							    &u32RcvdAssocRespInfoLen);

				PRINT_INFO(HOSTINF_DBG,"Received association response with length = %d\n", u32RcvdAssocRespInfoLen);

				if (u32RcvdAssocRespInfoLen != 0) {
					PRINT_D(HOSTINF_DBG, "Parsing association response\n");
					s32Err = ParseAssocRespInfo(gapu8RcvdAssocResp, u32RcvdAssocRespInfoLen,
								    &pstrConnectRespInfo);
					if (s32Err) {
						PRINT_ER("ParseAssocRespInfo() returned error %d\n", s32Err);
					} else {
						/* use the necessary parsed Info from the Received Association Response */
						strConnectInfo.u16ConnectStatus = pstrConnectRespInfo->u16ConnectStatus;

						if (strConnectInfo.u16ConnectStatus == SUCCESSFUL_STATUSCODE) {
							PRINT_INFO(HOSTINF_DBG,"Association response received : Successful connection status\n");
							if (pstrConnectRespInfo->pu8RespIEs != NULL) {
								strConnectInfo.u16RespIEsLen = pstrConnectRespInfo->u16RespIEsLen;

								strConnectInfo.pu8RespIEs = kmalloc(pstrConnectRespInfo->u16RespIEsLen, GFP_ATOMIC);
								memcpy(strConnectInfo.pu8RespIEs, pstrConnectRespInfo->pu8RespIEs,
								       pstrConnectRespInfo->u16RespIEsLen);
							}
						}

						/* deallocate the Assoc. Resp. parsed structure as it is not needed anymore */
						if (pstrConnectRespInfo != NULL) {
							DeallocateAssocRespInfo(pstrConnectRespInfo);
							pstrConnectRespInfo = NULL;
						}
					}
				}
			}

			/* The station has just received mac status and it also received assoc. response which 
			*it was waiting for. 
			*So check first the matching between the received mac status and the received status code in Asoc Resp
			*/
			if ((u8MacStatus == MAC_CONNECTED) &&
			    (strConnectInfo.u16ConnectStatus != SUCCESSFUL_STATUSCODE))	{
				PRINT_ER("Received MAC status is MAC_CONNECTED while the received status code in Asoc Resp is not SUCCESSFUL_STATUSCODE\n");
				memset(u8ConnectedSSID, 0, ETH_ALEN);
			} else if (u8MacStatus == MAC_DISCONNECTED) {
				PRINT_ER("Received MAC status is MAC_DISCONNECTED\n");
				memset(u8ConnectedSSID, 0, ETH_ALEN);
			}

			/*TODO:correct BSSID should be retrieved from actual BSSID received from AP
			*through a structure of type tstrConnectRespInfo
			*/
			if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL) {
				PRINT_D(HOSTINF_DBG, "Retrieving actual BSSID from AP\n");
				memcpy(strConnectInfo.au8bssid, pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, 6);

				if ((u8MacStatus == MAC_CONNECTED) &&
				    (strConnectInfo.u16ConnectStatus == SUCCESSFUL_STATUSCODE))
					memcpy(pstrWFIDrv->au8AssociatedBSSID,
					       pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, ETH_ALEN);
			}

			if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
				strConnectInfo.ReqIEsLen = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
				strConnectInfo.pu8ReqIEs = kmalloc(pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen, GFP_ATOMIC);
				memcpy(strConnectInfo.pu8ReqIEs,
				       pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs,
				       pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen);
			}

			del_timer(&(pstrWFIDrv->hConnectTimer));
			pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_CONN_RESP,
									   &strConnectInfo,
									   u8MacStatus,
									   NULL,
									   pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);

			/* if received mac status is MAC_CONNECTED and 
		    *received status code in Asoc Resp is SUCCESSFUL_STATUSCODE, change state to CONNECTED 
			* else change state to IDLE
			*/
			if ((u8MacStatus == MAC_CONNECTED) &&
			    (strConnectInfo.u16ConnectStatus == SUCCESSFUL_STATUSCODE))	{

				PRINT_D(HOSTINF_DBG, "MAC status : CONNECTED and Connect Status : Successful\n");
				pstrWFIDrv->enuHostIFstate = HOST_IF_CONNECTED;

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP

				handle_pwrsave_during_obtainingIP(pstrWFIDrv, IP_STATE_OBTAINING);
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */
			} else {
				PRINT_D(HOSTINF_DBG, "MAC status : %d and Connect Status : %d\n", u8MacStatus, strConnectInfo.u16ConnectStatus);
				pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;
				gbScanWhileConnected = false;
			}

			/* Deallocation */								
			if (strConnectInfo.pu8RespIEs != NULL) {
				kfree(strConnectInfo.pu8RespIEs);
				strConnectInfo.pu8RespIEs = NULL;
			}

			if (strConnectInfo.pu8ReqIEs != NULL) {
				kfree(strConnectInfo.pu8ReqIEs);
				strConnectInfo.pu8ReqIEs = NULL;
			}

			pstrWFIDrv->strWILC_UsrConnReq.ssidLen = 0;
			if (pstrWFIDrv->strWILC_UsrConnReq.pu8ssid != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid);
				pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = NULL;
			}

			if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid);
				pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = NULL;
			}

			pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = 0;
			if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs);
				pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = NULL;
			}
		} else if ((u8MacStatus == MAC_DISCONNECTED) &&
			   (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED)) {
			/* Disassociation or Deauthentication frame has been received */
			PRINT_D(HOSTINF_DBG, "Received MAC_DISCONNECTED from the FW\n");

			memset(&strDisconnectNotifInfo, 0, sizeof(struct tstrDisconnectNotifInfo));

			if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
				PRINT_D(HOSTINF_DBG, "\n\n<< Abort the running OBSS Scan >>\n\n");
				del_timer(&(pstrWFIDrv->hScanTimer));
				Handle_ScanDone((void *)pstrWFIDrv, SCAN_EVENT_ABORTED);
			}

			strDisconnectNotifInfo.u16reason = 0;
			strDisconnectNotifInfo.ie = NULL;
			strDisconnectNotifInfo.ie_len = 0;

			if (pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult != NULL) {
#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP

				handle_pwrsave_during_obtainingIP(pstrWFIDrv, IP_STATE_DEFAULT);
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

				pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_DISCONN_NOTIF,
										   NULL,
										   0,
										   &strDisconnectNotifInfo,
										   pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);
			} else {
				PRINT_ER("Connect result callback function is NULL\n");
			}
			memset(pstrWFIDrv->au8AssociatedBSSID, 0, ETH_ALEN);

			/* Deallocation
			* if Information Elements were retrieved from the Received deauth/disassoc frame, then they 
			should be deallocated here
			*/
			pstrWFIDrv->strWILC_UsrConnReq.ssidLen = 0;
			if (pstrWFIDrv->strWILC_UsrConnReq.pu8ssid != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid);
				pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = NULL;
			}

			if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid);
				pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = NULL;
			}

			pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = 0;
			if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
				kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs);
				pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = NULL;
			}

			/*BugID_5213
			*Freeing flushed join request params on receiving
			*MAC_DISCONNECTED while connected
			*/
			if (gu8FlushedJoinReq != NULL && gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
				kfree(gu8FlushedJoinReq);
				gu8FlushedJoinReq = NULL;
			}
			if (gu8FlushedInfoElemAsoc != NULL && gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
				kfree(gu8FlushedInfoElemAsoc);
				gu8FlushedInfoElemAsoc = NULL;
			}

			pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;
			gbScanWhileConnected = false;
		} else if ((u8MacStatus == MAC_DISCONNECTED) &&
			   (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult != NULL)) {
			PRINT_D(HOSTINF_DBG, "Received MAC_DISCONNECTED from the FW while scanning\n");
			PRINT_WRN(HOSTINF_DBG, "\n\n<< Abort the running Scan >>\n\n");
			/*Abort the running scan*/
			del_timer(&(pstrWFIDrv->hScanTimer));
			if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult)
				Handle_ScanDone((void *)pstrWFIDrv, SCAN_EVENT_ABORTED);

		}
	}

	WILC_CATCH(s32Error){
	}
	/* Deallocate pstrRcvdGnrlAsyncInfo->pu8Buffer which was prevoisuly allocated by the sending thread */
	if (pstrRcvdGnrlAsyncInfo->pu8Buffer != NULL) {
		kfree(pstrRcvdGnrlAsyncInfo->pu8Buffer);
		pstrRcvdGnrlAsyncInfo->pu8Buffer = NULL;
	}

	return s32Error;
}

/*
 * Sending config packet to firmware to set key
 */
static int Handle_Key(void *drvHandler, struct tstrHostIFkeyAttr *pstrHostIFkeyAttr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
#ifdef WILC_AP_EXTERNAL_MLME
	struct tstrWID strWIDList[5];
#endif /* WILC_AP_EXTERNAL_MLME */
	int driver_handler_id = 0;
	u8 i;
	u8 *pu8keybuf;
	s8 s8idxarray[1];
	s8 ret = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	switch (pstrHostIFkeyAttr->enuKeyType) {
	case WEP_Key:

#ifdef WILC_AP_EXTERNAL_MLME
		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY_AP)	{
			PRINT_D(HOSTINF_DBG, "Handling WEP key\n");
			PRINT_D(GENERIC_DBG, "ID Hostint is %d\n", (pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx));
			strWIDList[0].u16WIDid = (u16)WID_11I_MODE;
			strWIDList[0].enuWIDtype = WID_CHAR;
			strWIDList[0].s32ValueSize = sizeof(char);
			strWIDList[0].ps8WidVal = (s8 *)(&(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8mode));

			strWIDList[1].u16WIDid = WID_AUTH_TYPE;
			strWIDList[1].enuWIDtype = WID_CHAR;
			strWIDList[1].s32ValueSize = sizeof(char);
			strWIDList[1].ps8WidVal = (s8 *)(&(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.tenuAuth_type));

			pu8keybuf = kmalloc(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen + 2, GFP_ATOMIC);

			if (pu8keybuf == NULL){
				PRINT_ER("No buffer to send Key\n");
				return -1;
			}
			pu8keybuf[0] = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx;
			pu8keybuf[1] = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen;
			
			memcpy(&pu8keybuf[2], pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey,
			       pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen);

			kfree(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey);

			strWIDList[2].u16WIDid = (u16)WID_WEP_KEY_VALUE;
			strWIDList[2].enuWIDtype = WID_STR;
			strWIDList[2].s32ValueSize = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen + 2;
			strWIDList[2].ps8WidVal = (s8 *)pu8keybuf;

			s32Error = SendConfigPkt(SET_CFG, strWIDList, 3, true, driver_handler_id);
			kfree(pu8keybuf);
		}
#endif /* WILC_AP_EXTERNAL_MLME */

		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY) {
			PRINT_D(HOSTINF_DBG, "Handling WEP key\n");
			pu8keybuf = kmalloc(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen + 2, GFP_ATOMIC);
			if (pu8keybuf == NULL) {
				PRINT_ER("No buffer to send Key\n");
				return -1;
			}
			pu8keybuf[0] = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx;

			memcpy(pu8keybuf + 1, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen, 1);

			memcpy(pu8keybuf + 2, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey,
			       pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen);

			kfree(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey);

			strWID.u16WIDid	= (u16)WID_ADD_WEP_KEY;
			strWID.enuWIDtype = WID_STR;
			strWID.ps8WidVal = (s8 *)pu8keybuf;
			strWID.s32ValueSize = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen + 2;

			s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
			kfree(pu8keybuf);
		} else if (pstrHostIFkeyAttr->u8KeyAction & REMOVEKEY) {
			PRINT_D(HOSTINF_DBG, "Removing key\n");
			strWID.u16WIDid	= (u16)WID_REMOVE_WEP_KEY;
			strWID.enuWIDtype = WID_STR;

			s8idxarray[0] = (s8)pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx;
			strWID.ps8WidVal = s8idxarray;
			strWID.s32ValueSize = 1;

			s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
		} else if(pstrHostIFkeyAttr->u8KeyAction & DEFAULTKEY) {
			strWID.u16WIDid	= (u16)WID_KEY_ID;
			strWID.enuWIDtype = WID_CHAR;
			strWID.ps8WidVal = (s8 *)(&(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx));
			strWID.s32ValueSize = sizeof(char);

			PRINT_D(HOSTINF_DBG, "Setting default key index\n");

			s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
		}
		up(&(pstrWFIDrv->hSemTestKeyBlock));
		break;

	case WPARxGtk:
#ifdef WILC_AP_EXTERNAL_MLME
		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY_AP)	{
			pu8keybuf = kmalloc(RX_MIC_KEY_MSG_LEN, GFP_ATOMIC);
			if (pu8keybuf == NULL) {
				PRINT_ER("No buffer to send RxGTK Key\n");
				ret = -1;
				goto _WPARxGtk_end_case_;
			}

			memset(pu8keybuf, 0, RX_MIC_KEY_MSG_LEN);

				/*|----------------------------------------------------------------------------|
				* |Sta Address | Key RSC | KeyID | Key Length | Temporal Key	| Rx Michael Key |
				*  |------------|---------|-------|------------|---------------|----------------|
				*  |	6 bytes	 | 8 byte  |1 byte |  1 byte	|   16 bytes	|	  8 bytes	 |
				*/
			if (pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq != NULL)
				memcpy(pu8keybuf + 6, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq, 8);

			memcpy(pu8keybuf + 14, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8keyidx, 1);

			memcpy(pu8keybuf + 15, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen, 1);

			memcpy(pu8keybuf + 16, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
			       pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen);
			strWIDList[0].u16WIDid = (u16)WID_11I_MODE;
			strWIDList[0].enuWIDtype = WID_CHAR;
			strWIDList[0].s32ValueSize = sizeof(char);
			strWIDList[0].ps8WidVal = (s8 *)(&(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Ciphermode));

			strWIDList[1].u16WIDid = (u16)WID_ADD_RX_GTK;
			strWIDList[1].enuWIDtype = WID_STR;
			strWIDList[1].ps8WidVal	= (s8 *)pu8keybuf;
			strWIDList[1].s32ValueSize = RX_MIC_KEY_MSG_LEN;

			s32Error = SendConfigPkt(SET_CFG, strWIDList, 2, true, driver_handler_id);

			kfree(pu8keybuf);

			up(&(pstrWFIDrv->hSemTestKeyBlock));
		}

#endif /* WILC_AP_EXTERNAL_MLME */
		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY) {
			PRINT_D(HOSTINF_DBG, "Handling group key(Rx) function\n");

			pu8keybuf = kmalloc(RX_MIC_KEY_MSG_LEN, GFP_ATOMIC);
			if (pu8keybuf == NULL) {
				PRINT_ER("No buffer to send RxGTK Key\n");
				ret = -1;
				goto _WPARxGtk_end_case_;
			}

			memset(pu8keybuf, 0, RX_MIC_KEY_MSG_LEN);

				/*|----------------------------------------------------------------------------|
				* |Sta Address | Key RSC | KeyID | Key Length | Temporal Key	| Rx Michael Key |
				* |------------|---------|-------|------------|---------------|----------------|
				* |	6 bytes	 | 8 byte  |1 byte |  1 byte	|   16 bytes	|	  8 bytes	 |
				*/
			if (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED)
				memcpy(pu8keybuf, pstrWFIDrv->au8AssociatedBSSID, ETH_ALEN);
			else
				PRINT_ER("Couldn't handle WPARxGtk while enuHostIFstate is not HOST_IF_CONNECTED\n");

			memcpy(pu8keybuf + 6, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq, 8);

			memcpy(pu8keybuf + 14, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8keyidx, 1);

			memcpy(pu8keybuf + 15, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen, 1);
			memcpy(pu8keybuf + 16, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
			       pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen);

			strWID.u16WIDid	= (u16)WID_ADD_RX_GTK;
			strWID.enuWIDtype	= WID_STR;
			strWID.ps8WidVal	= (s8 *)pu8keybuf;
			strWID.s32ValueSize = RX_MIC_KEY_MSG_LEN;

			s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

			kfree(pu8keybuf);

			up(&(pstrWFIDrv->hSemTestKeyBlock));
		}
_WPARxGtk_end_case_:
		kfree(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key);
		kfree(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq);
		if (ret == -1)
			return ret;

		break;

	case WPAPtk:
#ifdef WILC_AP_EXTERNAL_MLME
		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY_AP)	{
			pu8keybuf = kmalloc(PTK_KEY_MSG_LEN + 1, GFP_ATOMIC);

			if (pu8keybuf == NULL) {
				PRINT_ER("No buffer to send PTK Key\n");
				ret = -1;
				goto _WPAPtk_end_case_;
			}
			/*|-----------------------------------------------------------------------------|
			*  |Station address |   keyidx     |Key Length    |Temporal Key  | Rx Michael Key |Tx Michael Key |
			*  |----------------|------------  |--------------|----------------|---------------|
			*  |	6 bytes    |	1 byte    |   1byte	 |   16 bytes	 |	  8 bytes	  |	   8 bytes	  |
			*  |-----------------------------------------------------------------------------|
			*/

			memcpy(pu8keybuf, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8macaddr, 6);

			memcpy(pu8keybuf + 6, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8keyidx, 1);
			memcpy(pu8keybuf + 7, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen, 1);
			memcpy(pu8keybuf + 8, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
			pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen);

			strWIDList[0].u16WIDid = (u16)WID_11I_MODE;
			strWIDList[0].enuWIDtype = WID_CHAR;
			strWIDList[0].s32ValueSize = sizeof(char);
			strWIDList[0].ps8WidVal = (s8 *)(&(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Ciphermode));

			strWIDList[1].u16WIDid = (u16)WID_ADD_PTK;
			strWIDList[1].enuWIDtype = WID_STR;
			strWIDList[1].ps8WidVal	= (s8 *)pu8keybuf;
			strWIDList[1].s32ValueSize = PTK_KEY_MSG_LEN + 1;

			s32Error = SendConfigPkt(SET_CFG, strWIDList, 2, true, driver_handler_id);
			kfree(pu8keybuf);

			up(&(pstrWFIDrv->hSemTestKeyBlock));
		}
#endif /* WILC_AP_EXTERNAL_MLME */
		if (pstrHostIFkeyAttr->u8KeyAction & ADDKEY) {
			pu8keybuf = kmalloc(PTK_KEY_MSG_LEN, GFP_ATOMIC);

			if (pu8keybuf == NULL) {
				PRINT_ER("No buffer to send PTK Key\n");
				ret = -1;
				goto _WPAPtk_end_case_;
			}
			/*|-----------------------------------------------------------------------------|
			*  |Station address | Key Length |	Temporal Key | Rx Michael Key |Tx Michael Key |
			*  |----------------|------------|--------------|----------------|---------------|
			*  |	6 bytes		 |	1byte	  |   16 bytes	 |	  8 bytes	  |	   8 bytes	  |
			*  |-----------------------------------------------------------------------------|
			*/

			memcpy(pu8keybuf, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8macaddr, 6);

			memcpy(pu8keybuf + 6, &pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen, 1);
			/*16 byte TK*/
			memcpy(pu8keybuf + 7, pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
			       pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen);

			strWID.u16WIDid	= (u16)WID_ADD_PTK;
			strWID.enuWIDtype	= WID_STR;
			strWID.ps8WidVal	= (s8 *)pu8keybuf;
			strWID.s32ValueSize = PTK_KEY_MSG_LEN;

			s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
			kfree(pu8keybuf);

			up(&(pstrWFIDrv->hSemTestKeyBlock));
		}

_WPAPtk_end_case_:
		kfree(pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFwpaAttr.pu8key);
		if (ret == -1)
			return ret;

		break;

	case PMKSA:

		PRINT_D(HOSTINF_DBG, "Handling PMKSA key\n");

		pu8keybuf = kmalloc((pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.numpmkid * PMKSA_KEY_LEN) + 1, GFP_ATOMIC);
		if (pu8keybuf == NULL){
			PRINT_ER("No buffer to send PMKSA Key\n");
			return -1;
		}		

		pu8keybuf[0] = pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.numpmkid;

		for (i = 0; i < pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.numpmkid; i++) {
			memcpy(pu8keybuf + ((PMKSA_KEY_LEN * i) + 1), pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.pmkidlist[i].bssid, ETH_ALEN);
			memcpy(pu8keybuf + ((PMKSA_KEY_LEN * i) + ETH_ALEN + 1), pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.pmkidlist[i].pmkid, PMKID_LEN);
		}

		strWID.u16WIDid	= (u16)WID_PMKID_INFO;
		strWID.enuWIDtype = WID_STR;
		strWID.ps8WidVal = (s8 *)pu8keybuf;
		strWID.s32ValueSize = (pstrHostIFkeyAttr->uniHostIFkeyAttr.strHostIFpmkidAttr.numpmkid * PMKSA_KEY_LEN) + 1;

		s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

		kfree(pu8keybuf);
		break;
	}

	if (s32Error)
		PRINT_ER("Failed to send key config packet\n");

	return s32Error;
}

/*
 * Sending config packet to firmware to disconnect
 */
static void Handle_Disconnect(void *drvHandler)
{
	struct tstrWID strWID;
	int driver_handler_id = 0;
	signed int s32Error = WILC_SUCCESS;
	u16 u16DummyReasonCode = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	struct WILC_WFIDrv *pstrWFIDrvP2P  = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(P2P_IFC);
	struct WILC_WFIDrv *pstrWFIDrvWLAN = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(WLAN_IFC);

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	/* If any interface is scanning, then abort it before proceeding with the disconnect */
	if (pstrWFIDrvWLAN != NULL)
	{
		if (pstrWFIDrvWLAN->enuHostIFstate == HOST_IF_SCANNING) 
		{
			PRINT_D(GENERIC_DBG,"Abort Scan before disconnecting. WLAN_IFC is in state [%d]\n",
				pstrWFIDrvWLAN->enuHostIFstate);
			del_timer(&(pstrWFIDrvWLAN->hScanTimer));
			Handle_ScanDone(pstrWFIDrvWLAN, SCAN_EVENT_ABORTED);
		}
	}

	if (pstrWFIDrvP2P != NULL)
	{
		if (pstrWFIDrvP2P->enuHostIFstate == HOST_IF_SCANNING)
		{
			PRINT_D(GENERIC_DBG,"Abort Scan before disconnecting. P2P_IFC is in state [%d]\n",
				 pstrWFIDrvP2P->enuHostIFstate);
			del_timer(&(pstrWFIDrvP2P->hScanTimer));
			Handle_ScanDone(pstrWFIDrvP2P, SCAN_EVENT_ABORTED);
		}
	}
	
	strWID.u16WIDid = (u16)WID_DISCONNECT;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)&u16DummyReasonCode;
	strWID.s32ValueSize = sizeof(char);

	PRINT_D(HOSTINF_DBG, "Sending disconnect request\n");

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP

	handle_pwrsave_during_obtainingIP(pstrWFIDrv, IP_STATE_DEFAULT);
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

	memset(u8ConnectedSSID, 0, ETH_ALEN);

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);

	if (s32Error) {
		PRINT_ER("Failed to send dissconect config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	} else {
		struct tstrDisconnectNotifInfo strDisconnectNotifInfo;

		memset(&strDisconnectNotifInfo, 0,
		       sizeof(struct tstrDisconnectNotifInfo));

		strDisconnectNotifInfo.u16reason = 0;
		strDisconnectNotifInfo.ie = NULL;
		strDisconnectNotifInfo.ie_len = 0;

		if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
			del_timer(&(pstrWFIDrv->hScanTimer));
			pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult(SCAN_EVENT_ABORTED, NULL,
									pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid, NULL);

			pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult = NULL;
		}

		if(pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult != NULL)
		{
			/* TicketId1002
			 * Check on host interface state, if:
			 * (1) HOST_IF_WAITING_CONN_RESP --> post CONN_DISCONN_EVENT_CONN_RESP event
			 * (2) HOST_IF_CONNECTED --> post CONN_DISCONN_EVENT_DISCONN_NOTIF event
			 */
			if (pstrWFIDrv->enuHostIFstate == HOST_IF_WAITING_CONN_RESP) {
				struct tstrConnectInfo strConnectInfo;
				PRINT_D(HOSTINF_DBG,"Upper layer requested termination of connection\n");
				memset(&strConnectInfo, 0, sizeof(struct tstrConnectInfo));

				/*Stop connect timer, if connection in progress*/
				del_timer(&(pstrWFIDrv->hConnectTimer));

				if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL)
					memcpy(strConnectInfo.au8bssid, pstrWFIDrv->strWILC_UsrConnReq.pu8bssid, 6);
				if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
					strConnectInfo.ReqIEsLen = pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen;
					strConnectInfo.pu8ReqIEs = kmalloc(pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen, GFP_ATOMIC);
					memcpy(strConnectInfo.pu8ReqIEs,
					       pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs,
					       pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen);
				}
				pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_CONN_RESP,
										     &strConnectInfo,
										     MAC_DISCONNECTED,
										     NULL,
										     pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);

				/* Deallocation */
				if (strConnectInfo.pu8ReqIEs != NULL) {
					kfree(strConnectInfo.pu8ReqIEs);
					strConnectInfo.pu8ReqIEs = NULL;
				}
			} else if (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED) {
				pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_DISCONN_NOTIF,
										     NULL,
										     0,
										     &strDisconnectNotifInfo,
										     pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);
			}
		} else {
			PRINT_ER("strWILC_UsrConnReq.pfUserConnectResult = NULL\n");
		}
		gbScanWhileConnected = false;

		pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;

		memset(pstrWFIDrv->au8AssociatedBSSID, 0, ETH_ALEN);

		/* Deallocation */
		pstrWFIDrv->strWILC_UsrConnReq.ssidLen = 0;
		if (pstrWFIDrv->strWILC_UsrConnReq.pu8ssid != NULL) {
			kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ssid);
			pstrWFIDrv->strWILC_UsrConnReq.pu8ssid = NULL;
		}

		if (pstrWFIDrv->strWILC_UsrConnReq.pu8bssid != NULL) {
			kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8bssid);
			pstrWFIDrv->strWILC_UsrConnReq.pu8bssid = NULL;
		}

		pstrWFIDrv->strWILC_UsrConnReq.ConnReqIEsLen = 0;
		if (pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs != NULL) {
			kfree(pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs);
			pstrWFIDrv->strWILC_UsrConnReq.pu8ConnReqIEs = NULL;
		}

		/*BugID_5137*/
		if (gu8FlushedJoinReq != NULL && gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
			kfree(gu8FlushedJoinReq);
			gu8FlushedJoinReq = NULL;
		}
		if (gu8FlushedInfoElemAsoc != NULL && gu8FlushedJoinReqDrvHandler == (unsigned int)drvHandler) {
			kfree(gu8FlushedInfoElemAsoc);
			gu8FlushedInfoElemAsoc = NULL;
		}
	}

	WILC_CATCH(s32Error){
	}

	up(&(pstrWFIDrv->hSemTestDisconnectBlock));
}

void resolve_disconnect_aberration(void *drvHandler)
{
	struct WILC_WFIDrv *pstrWFIDrv;

	pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	if (pstrWFIDrv  == NULL)
		return;
	if ((pstrWFIDrv->enuHostIFstate == HOST_IF_WAITING_CONN_RESP) ||
	    (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTING)) {
		PRINT_D(HOSTINF_DBG, "\n\n<< correcting Supplicant state machine >>\n\n");
		host_int_disconnect((struct WFIDrvHandle *)pstrWFIDrv, 1);
	}
}

static signed int Switch_Log_Terminal(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	static char dummy = 9;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_LOGTerminal_Switch;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = &dummy;
	strWID.s32ValueSize = sizeof(char);

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if (s32Error) {
		PRINT_D(HOSTINF_DBG, "Failed to switch log terminal\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_INFO(HOSTINF_DBG,"MAC address set ::\n");
	}
	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Sending config packet to get channel
 */
static signed int Handle_GetChnl(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_CURRENT_CHANNEL;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)&gu8Chnl;
	strWID.s32ValueSize = sizeof(char);

	PRINT_D(HOSTINF_DBG, "Getting channel value\n");

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	/*get the value by searching the local copy*/
	if (s32Error) {
		PRINT_ER("Failed to get channel number\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	up(&(pstrWFIDrv->hSemGetCHNL));

	return s32Error;
}

/*
 * Sending config packet to get RSSI
 */
static void Handle_GetRssi(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_RSSI;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = &gs8Rssi;
	strWID.s32ValueSize = sizeof(char);

	/*Sending Cfg*/
	PRINT_D(HOSTINF_DBG, "Getting RSSI value\n");

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to get RSSI value\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	up(&(pstrWFIDrv->hSemGetRSSI));
}

static void Handle_GetLinkspeed(void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	gs8lnkspd = 0;

	strWID.u16WIDid = (u16)WID_LINKSPEED;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = &gs8lnkspd;
	strWID.s32ValueSize = sizeof(char);
	/*Sending Cfg*/
	PRINT_D(HOSTINF_DBG, "Getting LINKSPEED value\n");

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to get LINKSPEED value\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	up(&(pstrWFIDrv->hSemGetLINKSPEED));
}

signed int Handle_GetStatistics(void *drvHandler,
				struct tstrStatistics *pstrStatistics)
{
	struct tstrWID strWIDList[5];
	uint32_t u32WidsCount = 0, s32Error = 0;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWIDList[u32WidsCount].u16WIDid = WID_LINKSPEED;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrStatistics->u8LinkSpeed));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_RSSI;
	strWIDList[u32WidsCount].enuWIDtype = WID_CHAR;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(char);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrStatistics->s8RSSI));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_SUCCESS_FRAME_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrStatistics->u32TxCount));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_RECEIVED_FRAGMENT_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrStatistics->u32RxCount));
	u32WidsCount++;

	strWIDList[u32WidsCount].u16WIDid = WID_FAILED_COUNT;
	strWIDList[u32WidsCount].enuWIDtype = WID_INT;
	strWIDList[u32WidsCount].s32ValueSize = sizeof(unsigned int);
	strWIDList[u32WidsCount].ps8WidVal = (s8 *)(&(pstrStatistics->u32TxFailureCount));
	u32WidsCount++;

	s32Error = SendConfigPkt(GET_CFG, strWIDList, u32WidsCount, false, driver_handler_id);

	if (s32Error)
		PRINT_ER("Failed to send scan paramters config packet\n");
	up(&hWaitResponse);

	return 0;
}

#ifdef WILC_AP_EXTERNAL_MLME
/*
 * Sending config packet to set mac adddress for station and get inactive time
 */
static signed int Handle_Get_InActiveTime(void *drvHandler,
					  struct tstrHostIfStaInactive *strHostIfStaInactiveT)
{
	signed int s32Error = WILC_SUCCESS;
	u8 *stamac;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_SET_STA_MAC_INACTIVE_TIME;
	strWID.enuWIDtype = WID_STR;
	strWID.s32ValueSize = ETH_ALEN;
	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);

	stamac = strWID.ps8WidVal;
	memcpy(stamac, strHostIfStaInactiveT->mac, ETH_ALEN);

	PRINT_D(CFG80211_DBG, "SETING STA inactive time\n");

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	/*get the value by searching the local copy*/
	if (s32Error) {
		PRINT_ER("Failed to SET incative time\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	strWID.u16WIDid = (u16)WID_GET_INACTIVE_TIME;
	strWID.enuWIDtype = WID_INT;
	strWID.ps8WidVal = (s8 *)&gu32InactiveTime;
	strWID.s32ValueSize = sizeof(unsigned int);

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	/*get the value by searching the local copy*/
	if (s32Error) {
		PRINT_ER("Failed to get incative time\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	PRINT_D(CFG80211_DBG, "Getting inactive time : %d\n", gu32InactiveTime);

	up(&(pstrWFIDrv->hSemInactiveTime));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Sending config packet to add beacon
 */
static void Handle_AddBeacon(void *drvHandler,
			     struct tstrHostIFSetBeacon *pstrSetBeaconParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	PRINT_D(HOSTINF_DBG, "Adding BEACON\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_ADD_BEACON;
	strWID.enuWIDtype = WID_BIN;
	strWID.s32ValueSize = pstrSetBeaconParam->u32HeadLen + pstrSetBeaconParam->u32TailLen + 16;
	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;
	*pu8CurrByte++ = (pstrSetBeaconParam->u32Interval & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32Interval >> 8) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32Interval >> 16) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32Interval >> 24) & 0xFF);

	*pu8CurrByte++ = (pstrSetBeaconParam->u32DTIMPeriod & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32DTIMPeriod >> 8) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32DTIMPeriod >> 16) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32DTIMPeriod >> 24) & 0xFF);

	*pu8CurrByte++ = (pstrSetBeaconParam->u32HeadLen & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32HeadLen >> 8) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32HeadLen >> 16) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32HeadLen >> 24) & 0xFF);

	memcpy(pu8CurrByte, pstrSetBeaconParam->pu8Head, pstrSetBeaconParam->u32HeadLen);
	pu8CurrByte += pstrSetBeaconParam->u32HeadLen;

	*pu8CurrByte++ = (pstrSetBeaconParam->u32TailLen & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32TailLen >> 8) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32TailLen >> 16) & 0xFF);
	*pu8CurrByte++ = ((pstrSetBeaconParam->u32TailLen >> 24) & 0xFF);

	/* Bug 4599 : if tail length = 0 skip copying */ 
	if (pstrSetBeaconParam->pu8Tail > 0)
		memcpy(pu8CurrByte, pstrSetBeaconParam->pu8Tail, pstrSetBeaconParam->u32TailLen);
	pu8CurrByte += pstrSetBeaconParam->u32TailLen;

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send add beacon config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
	if (pstrSetBeaconParam->pu8Head != NULL)
		kfree(pstrSetBeaconParam->pu8Head);
	if (pstrSetBeaconParam->pu8Tail != NULL)
		kfree(pstrSetBeaconParam->pu8Tail);
}

/*
 * Sending config packet to delete beacon
 */
static void Handle_DelBeacon(void *drvHandler,
			     struct tstrHostIFDelBeacon *pstrDelBeacon)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	strWID.u16WIDid = (u16)WID_DEL_BEACON;
	strWID.enuWIDtype = WID_CHAR;
	strWID.s32ValueSize = sizeof(char);
	strWID.ps8WidVal = &gu8DelBcn;

	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;

	PRINT_D(HOSTINF_DBG, "Deleting BEACON\n");
	/* TODO: build del beacon message*/

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send delete beacon config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}
	WILC_CATCH(s32Error){
	}
}

/*
 * Handling packing of the station params in a buffer
 */
static unsigned int WILC_HostIf_PackStaParam(u8 *pu8Buffer,
					     struct WILC_AddStaParam *pstrStationParam)
{
	u8 *pu8CurrByte;

	pu8CurrByte = pu8Buffer;

	PRINT_D(HOSTINF_DBG, "Packing STA params\n");
	memcpy(pu8CurrByte, pstrStationParam->au8BSSID, ETH_ALEN);
	pu8CurrByte +=  ETH_ALEN;

	*pu8CurrByte++ = pstrStationParam->u16AssocID & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u16AssocID >> 8) & 0xFF;

	*pu8CurrByte++ = pstrStationParam->u8NumRates;
	if (pstrStationParam->u8NumRates > 0)
		memcpy(pu8CurrByte, pstrStationParam->pu8Rates, pstrStationParam->u8NumRates);
	pu8CurrByte += pstrStationParam->u8NumRates;

	*pu8CurrByte++ = pstrStationParam->bIsHTSupported;
	*pu8CurrByte++ = pstrStationParam->u16HTCapInfo & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u16HTCapInfo >> 8) & 0xFF;

	*pu8CurrByte++ = pstrStationParam->u8AmpduParams;
	memcpy(pu8CurrByte, pstrStationParam->au8SuppMCsSet, WILC_SUPP_MCS_SET_SIZE);
	pu8CurrByte += WILC_SUPP_MCS_SET_SIZE;

	*pu8CurrByte++ = pstrStationParam->u16HTExtParams & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u16HTExtParams >> 8) & 0xFF;

	*pu8CurrByte++ = pstrStationParam->u32TxBeamformingCap & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u32TxBeamformingCap >> 8) & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u32TxBeamformingCap >> 16) & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u32TxBeamformingCap >> 24) & 0xFF;

	*pu8CurrByte++ = pstrStationParam->u8ASELCap;

	*pu8CurrByte++ = pstrStationParam->u16FlagsMask & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u16FlagsMask >> 8) & 0xFF;

	*pu8CurrByte++ = pstrStationParam->u16FlagsSet & 0xFF;
	*pu8CurrByte++ = (pstrStationParam->u16FlagsSet >> 8) & 0xFF;

	return pu8CurrByte - pu8Buffer;
}

/*
 * Sending config packet to add station
 */
static void Handle_AddStation(void *drvHandler,
			      struct WILC_AddStaParam *pstrStationParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	PRINT_D(HOSTINF_DBG, "Handling add station\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_ADD_STA;
	strWID.enuWIDtype = WID_BIN;
	strWID.s32ValueSize = WILC_ADD_STA_LENGTH + pstrStationParam->u8NumRates;

	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;
	pu8CurrByte += WILC_HostIf_PackStaParam(pu8CurrByte, pstrStationParam);

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error != WILC_SUCCESS) {
		PRINT_ER("Failed to send add station config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (pstrStationParam->pu8Rates != NULL)
		kfree(pstrStationParam->pu8Rates);
	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
}

/*
 * Sending config packet to delete station
 */
static void Handle_DelAllSta(void *drvHandler,
			     struct tstrHostIFDelAllSta *pstrDelAllStaParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	u8 i;
	u8 au8Zero_Buff[6] = {0};

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_DEL_ALL_STA;
	strWID.enuWIDtype = WID_STR;
	strWID.s32ValueSize = (pstrDelAllStaParam->u8Num_AssocSta * ETH_ALEN) + 1;

	PRINT_D(HOSTINF_DBG, "Handling delete station\n");

	strWID.ps8WidVal = kmalloc((pstrDelAllStaParam->u8Num_AssocSta * ETH_ALEN) + 1,
				   GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;

	*(pu8CurrByte++) = pstrDelAllStaParam->u8Num_AssocSta;

	for (i = 0; i < MAX_NUM_STA; i++) {
		if (memcmp(pstrDelAllStaParam->au8Sta_DelAllSta[i], au8Zero_Buff, ETH_ALEN))
			memcpy(pu8CurrByte, pstrDelAllStaParam->au8Sta_DelAllSta[i], ETH_ALEN);
		else
			continue;

		pu8CurrByte += ETH_ALEN;
	}

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send add station config packe\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
	up(&hWaitResponse);
}

/*
 * Sending config packet to delete station
 */
static void Handle_DelStation(void *drvHandler,
			      struct tstrHostIFDelSta *pstrDelStaParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	strWID.u16WIDid = (u16)WID_REMOVE_STA;
	strWID.enuWIDtype = WID_BIN;
	strWID.s32ValueSize = ETH_ALEN;

	PRINT_D(HOSTINF_DBG, "Handling delete station\n");

	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;

	memcpy(pu8CurrByte, pstrDelStaParam->au8MacAddr, ETH_ALEN);

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send add station config packe\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
}

/*
 * Sending config packet to edit station
 */
static void Handle_EditStation(void *drvHandler,
			       struct WILC_AddStaParam *pstrStationParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_EDIT_STA;
	strWID.enuWIDtype = WID_BIN;
	strWID.s32ValueSize = WILC_ADD_STA_LENGTH + pstrStationParam->u8NumRates;

	PRINT_D(HOSTINF_DBG, "Handling edit station\n");
	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;
	pu8CurrByte += WILC_HostIf_PackStaParam(pu8CurrByte, pstrStationParam);

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send edit station config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (pstrStationParam->pu8Rates != NULL)
		kfree(pstrStationParam->pu8Rates);
	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
}
#endif /*WILC_AP_EXTERNAL_MLME*/

#ifdef WILC_P2P
/*
 * Sending config packet to edit station
 */
static int Handle_RemainOnChan(void *drvHandler,
			       struct tstrHostIfRemainOnChan *pstrHostIfRemainOnChan)
{
	signed int s32Error = WILC_SUCCESS;
	u8 u8remain_on_chan_flag;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;	
	struct WILC_WFIDrv *pstrWFIDrvP2P  = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(P2P_IFC);
	struct WILC_WFIDrv *pstrWFIDrvWLAN = (struct WILC_WFIDrv *) linux_wlan_get_drv_handler_by_ifc(WLAN_IFC);

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	/*If it's a pendig remain-on-channel, don't overwrite gWFiDrvHandle values (since incoming msg is garbbage)*/
	if (!pstrWFIDrv->u8RemainOnChan_pendingreq) {
		pstrWFIDrv->strHostIfRemainOnChan.pVoid = pstrHostIfRemainOnChan->pVoid;
		pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanExpired =
				  pstrHostIfRemainOnChan->pRemainOnChanExpired;
		pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanReady =
				    pstrHostIfRemainOnChan->pRemainOnChanReady;
		pstrWFIDrv->strHostIfRemainOnChan.u16Channel =
					    pstrHostIfRemainOnChan->u16Channel;
		pstrWFIDrv->strHostIfRemainOnChan.u32ListenSessionID =
				    pstrHostIfRemainOnChan->u32ListenSessionID;
	} else {
		/*Set the channel to use it as a wid val*/
		pstrHostIfRemainOnChan->u16Channel = pstrWFIDrv->strHostIfRemainOnChan.u16Channel;
	}

	/* If any of the two interfaces is busy scanning, connecting, or listening, then report WILC_BUSY */
	if (pstrWFIDrvP2P != NULL) {
		if (pstrWFIDrvP2P->enuHostIFstate == HOST_IF_SCANNING) {
			PRINT_D(GENERIC_DBG,"Interface busy scanning. P2P_IFC is in state [%d]\n",
				pstrWFIDrvP2P->enuHostIFstate);
			pstrWFIDrv->u8RemainOnChan_pendingreq = 1;
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		} else if ((pstrWFIDrvP2P->enuHostIFstate != HOST_IF_IDLE) &&
		(pstrWFIDrvP2P->enuHostIFstate != HOST_IF_CONNECTED)) {
			PRINT_D(GENERIC_DBG,"Interface busy connecting or listening. P2P_IFC is in state [%d]\n",
			 pstrWFIDrvP2P->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

	if (pstrWFIDrvWLAN != NULL) {
		if (pstrWFIDrvWLAN->enuHostIFstate == HOST_IF_SCANNING) {
			PRINT_D(GENERIC_DBG,"Interface busy scanning. WLAN_IFC is in state [%d]\n",
				pstrWFIDrvWLAN->enuHostIFstate);
			pstrWFIDrv->u8RemainOnChan_pendingreq = 1;
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		} else if ((pstrWFIDrvWLAN->enuHostIFstate != HOST_IF_IDLE) &&
		(pstrWFIDrvWLAN->enuHostIFstate != HOST_IF_CONNECTED)) {
			PRINT_D(GENERIC_DBG,"Interface busy connecting or listening. WLAN_IFC is in state [%d]\n",
			 pstrWFIDrvWLAN->enuHostIFstate);
			WILC_ERRORREPORT(s32Error, WILC_BUSY);
		}
	}

	if(connecting) {
		PRINT_D(GENERIC_DBG, "[handle_scan]: Don't do scan in (CONNECTING) state\n");
		WILC_ERRORREPORT(s32Error, WILC_BUSY);
	}

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
	if (get_obtaining_IP_flag()) {
		PRINT_D(GENERIC_DBG, "[handle_scan]: Don't do obss scan until IP adresss is obtained\n");
		WILC_ERRORREPORT(s32Error, WILC_BUSY);
	}
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

	PRINT_D(HOSTINF_DBG, "Setting channel :%d\n", pstrHostIfRemainOnChan->u16Channel);

	u8remain_on_chan_flag = true;
	strWID.u16WIDid	= (u16)WID_REMAIN_ON_CHAN;
	strWID.enuWIDtype	= WID_STR;
	strWID.s32ValueSize = 2;
	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);

	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	strWID.ps8WidVal[0] = u8remain_on_chan_flag;
	strWID.ps8WidVal[1] = (s8)pstrHostIfRemainOnChan->u16Channel;

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error != WILC_SUCCESS)
		PRINT_ER("Failed to set remain on channel\n");

	pstrWFIDrv->enuHostIFstate = HOST_IF_P2P_LISTEN;
	pstrWFIDrv->hRemainOnChannel.data = (unsigned long)pstrWFIDrv;
	mod_timer(&(pstrWFIDrv->hRemainOnChannel),
	    (jiffies + msecs_to_jiffies(pstrHostIfRemainOnChan->u32duration)));

		/*Calling CFG ready_on_channel*/
	if (pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanReady)
		pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanReady(pstrWFIDrv->strHostIfRemainOnChan.pVoid);

	if (pstrWFIDrv->u8RemainOnChan_pendingreq)
		pstrWFIDrv->u8RemainOnChan_pendingreq = 0;

	WILC_CATCH(s32Error){
	}
	return s32Error;
}

static int Handle_RegisterFrame(void *drvHandler,
				struct tstrHostIfRegisterFrame *pstrHostIfRegisterFrame)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	PRINT_D(HOSTINF_DBG, "Handling frame register Flag : %d FrameType: %d\n",
					pstrHostIfRegisterFrame->bReg,
					pstrHostIfRegisterFrame->u16FrameType);

	/*prepare configuration packet*/
	strWID.u16WIDid = (u16)WID_REGISTER_FRAME;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = kmalloc(sizeof(u16) + 2, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;

	*pu8CurrByte++ = pstrHostIfRegisterFrame->bReg;
	*pu8CurrByte++ = pstrHostIfRegisterFrame->u8Regid;
	memcpy(pu8CurrByte, &(pstrHostIfRegisterFrame->u16FrameType), sizeof(u16));

	strWID.s32ValueSize = sizeof(u16) + 2;

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to frame register config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Handle of listen state expiration
 */
#define FALSE_FRMWR_CHANNEL 100
static unsigned int Handle_ListenStateExpired(void *drvHandler,
					      struct tstrHostIfRemainOnChan *pstrHostIfRemainOnChan)
{
	u8 u8remain_on_chan_flag;
	struct tstrWID strWID;
	signed int s32Error = WILC_SUCCESS;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *) drvHandler;

	PRINT_D(HOSTINF_DBG, "CANCEL REMAIN ON CHAN\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	/*BugID_5477*/
	/*Make sure we are already in listen state*/
	/*This is to handle duplicate expiry messages (listen timer fired and supplicant called cancel_remain_on_channel())*/
	if (pstrWFIDrv->enuHostIFstate == HOST_IF_P2P_LISTEN) {
		u8remain_on_chan_flag = false;
		strWID.u16WIDid	= (u16)WID_REMAIN_ON_CHAN;
		strWID.enuWIDtype	= WID_STR;
		strWID.s32ValueSize = 2;
		strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);

		if (strWID.ps8WidVal == NULL){
			PRINT_ER("Failed to allocate memory\n");
			return WILC_FAIL;
		}

		strWID.ps8WidVal[0] = u8remain_on_chan_flag;
		strWID.ps8WidVal[1] = FALSE_FRMWR_CHANNEL;

		/*Sending Cfg*/
		s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
		if (s32Error != WILC_SUCCESS) {
			PRINT_ER("Failed to set remain on channel\n");
			goto _done_;
		}

		if (pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanExpired)
			pstrWFIDrv->strHostIfRemainOnChan.pRemainOnChanExpired(pstrWFIDrv->strHostIfRemainOnChan.pVoid
									       , pstrHostIfRemainOnChan->u32ListenSessionID);
		
		if (memcmp(pstrWFIDrv->au8AssociatedBSSID, au8NullBSSID, ETH_ALEN) == 0) {
			pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;
		} else {
			pstrWFIDrv->enuHostIFstate = HOST_IF_CONNECTED;
		}
	} else {
		PRINT_D(GENERIC_DBG, "Not in listen state\n");
		s32Error = WILC_FAIL;
	}

_done_:
	return s32Error;
}

/**
 *  @brief                      ListenTimerCB
 *  @details            Callback function of remain-on-channel timer
 *  @param[in]          NONE
 *  @return             Error code.
 *  @author
 *  @date
 *  @version		1.0
 */
static void ListenTimerCB(unsigned long function_context)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)function_context;
	/*Stopping remain-on-channel timer*/
	del_timer(&(pstrWFIDrv->hRemainOnChannel));

	/* prepare the Timer Callback message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_LISTEN_TIMER_FIRED;
	strHostIFmsg.drvHandler = pstrWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.u32ListenSessionID =
			  pstrWFIDrv->strHostIfRemainOnChan.u32ListenSessionID;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);
	WILC_CATCH(s32Error){
	}

}
#endif

/*
 * Sending config packet to edit station
 */
static void Handle_PowerManagement(void *drvHandler,
				   struct tstrHostIfPowerMgmtParam *strPowerMgmtParam)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	s8 s8PowerMode;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_POWER_MANAGEMENT;

	if (strPowerMgmtParam->bIsEnabled == true)
		s8PowerMode = MIN_FAST_PS;
	else
		s8PowerMode = NO_POWERSAVE;
	PRINT_D(HOSTINF_DBG, "Handling power mgmt to %d\n", s8PowerMode);
	strWID.ps8WidVal = &s8PowerMode;
	strWID.s32ValueSize = sizeof(char);

	PRINT_D(HOSTINF_DBG, "Handling Power Management\n");

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send power management config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}

	/* Save the current status of the PS */
	store_power_save_current_state(pstrWFIDrv, s8PowerMode);

	WILC_CATCH(s32Error){
	}

}

/*
 * Set Multicast filter in firmware
 */
static void Handle_SetMulticastFilter(void *drvHandler,
				      struct tstrHostIFSetMulti *strHostIfSetMulti)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	u8 *pu8CurrByte;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	PRINT_D(HOSTINF_DBG, "Setup Multicast Filter\n");

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_SETUP_MULTICAST_FILTER;
	strWID.enuWIDtype = WID_BIN;
	strWID.s32ValueSize = sizeof(struct tstrHostIFSetMulti) +
			      ((strHostIfSetMulti->u32count) * ETH_ALEN);
	strWID.ps8WidVal = kmalloc(strWID.s32ValueSize, GFP_ATOMIC);
	if (strWID.ps8WidVal == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);

	pu8CurrByte = strWID.ps8WidVal;
	*pu8CurrByte++ = (strHostIfSetMulti->bIsEnabled & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->bIsEnabled >> 8) & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->bIsEnabled >> 16) & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->bIsEnabled >> 24) & 0xFF);

	*pu8CurrByte++ = (strHostIfSetMulti->u32count & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->u32count >> 8) & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->u32count >> 16) & 0xFF);
	*pu8CurrByte++ = ((strHostIfSetMulti->u32count >> 24) & 0xFF);

	if ((strHostIfSetMulti->u32count) > 0)
		memcpy(pu8CurrByte, gau8MulticastMacAddrList,
		       ((strHostIfSetMulti->u32count) * ETH_ALEN));

	/*Sending Cfg*/
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, false, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send setup multicast config packet\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);
}

/*
 * Add block ack session
 */
static signed int Handle_AddBASession(void *drvHandler,
				      struct tstrHostIfBASessionInfo *strHostIfBASessionInfo)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	int AddbaTimeout = 100;
	char *ptr = NULL;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	PRINT_D(HOSTINF_DBG, "Opening Block Ack session with\nBSSID = %.2x:%.2x:%.2x\n"
		 "TID=%d\nBufferSize == %d\nSessionTimeOut = %d\n",
		strHostIfBASessionInfo->au8Bssid[0],
		strHostIfBASessionInfo->au8Bssid[1],
		strHostIfBASessionInfo->au8Bssid[2],
		strHostIfBASessionInfo->u16BufferSize,
		strHostIfBASessionInfo->u16SessionTimeout,
		strHostIfBASessionInfo->u8Ted);

	strWID.u16WIDid = (u16)WID_11E_P_ACTION_REQ;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = kmalloc(BLOCK_ACK_REQ_SIZE, GFP_ATOMIC);
	strWID.s32ValueSize = BLOCK_ACK_REQ_SIZE;
	ptr = strWID.ps8WidVal;
	memset(ptr, 0, strWID.s32ValueSize);
	*ptr++ = 0x14;
	*ptr++ = 0x3;
	*ptr++ = 0x0;
	memcpy(ptr, strHostIfBASessionInfo->au8Bssid, ETH_ALEN);
	ptr += ETH_ALEN;
	*ptr++ = strHostIfBASessionInfo->u8Ted;
	/* BA Policy*/
	*ptr++ = 1;
	/* Buffer size*/
	*ptr++ = (strHostIfBASessionInfo->u16BufferSize & 0xFF);
	*ptr++ = ((strHostIfBASessionInfo->u16BufferSize >> 16) & 0xFF);
	/* BA timeout*/
	*ptr++ = (strHostIfBASessionInfo->u16SessionTimeout & 0xFF);
	*ptr++ = ((strHostIfBASessionInfo->u16SessionTimeout >> 16) & 0xFF);
	/* ADDBA timeout*/
	*ptr++ = (AddbaTimeout & 0xFF);
	*ptr++ = ((AddbaTimeout >> 16) & 0xFF);
	/* Group Buffer Max Frames*/
	*ptr++ = 8;
	/* Group Buffer Timeout */
	*ptr++ = 0;

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error)
		PRINT_D(HOSTINF_DBG, "Couldn't open BA Session\n");

	strWID.u16WIDid = (u16)WID_11E_P_ACTION_REQ;
	strWID.enuWIDtype = WID_STR;
	strWID.s32ValueSize = 15;
	ptr = strWID.ps8WidVal;
	memset(ptr, 0, strWID.s32ValueSize);
	*ptr++ = 15;
	*ptr++ = 7;
	*ptr++ = 0x2;
	memcpy(ptr, strHostIfBASessionInfo->au8Bssid, ETH_ALEN);
	ptr += ETH_ALEN;
	/* TID*/
	*ptr++ = strHostIfBASessionInfo->u8Ted;
	/* Max Num MSDU */
	*ptr++ = 8;
	/* BA timeout*/
	*ptr++ = (strHostIfBASessionInfo->u16BufferSize & 0xFF);
	*ptr++ = ((strHostIfBASessionInfo->u16SessionTimeout >> 16) & 0xFF);
	/*Ack-Policy */
	*ptr++ = 3;
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);

	return s32Error;
}

/*
 * Delete block ack session
 */
static signed int Handle_DelBASession(void *drvHandler,
				      struct tstrHostIfBASessionInfo *strHostIfBASessionInfo)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	char *ptr = NULL;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	PRINT_D(GENERIC_DBG, "Delete Block Ack session with\nBSSID = %.2x:%.2x:%.2x\nTID=%d\n",
		strHostIfBASessionInfo->au8Bssid[0],
		strHostIfBASessionInfo->au8Bssid[1],
		strHostIfBASessionInfo->au8Bssid[2],
		strHostIfBASessionInfo->u8Ted);

	strWID.u16WIDid = (u16)WID_11E_P_ACTION_REQ;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = kmalloc(BLOCK_ACK_REQ_SIZE, GFP_ATOMIC);
	strWID.s32ValueSize = BLOCK_ACK_REQ_SIZE;
	ptr = strWID.ps8WidVal;
	*ptr++ = 0x14;
	*ptr++ = 0x3;
	*ptr++ = 0x2;
	memcpy(ptr, strHostIfBASessionInfo->au8Bssid, ETH_ALEN);
	ptr += ETH_ALEN;
	*ptr++ = strHostIfBASessionInfo->u8Ted;
	/* BA direction = recipent*/
	*ptr++ = 0;
	/* Delba Reason */
	*ptr++ = 32; /* Unspecific QOS reason */

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error)
		PRINT_D(HOSTINF_DBG, "Couldn't delete BA Session\n");

	strWID.u16WIDid = (u16)WID_11E_P_ACTION_REQ;
	strWID.enuWIDtype = WID_STR;
	strWID.s32ValueSize = 15;
	ptr = strWID.ps8WidVal;
	*ptr++ = 15;
	*ptr++ = 7;
	*ptr++ = 0x3;
	memcpy(ptr, strHostIfBASessionInfo->au8Bssid, ETH_ALEN);
	ptr += ETH_ALEN;
	/* TID*/
	*ptr++ = strHostIfBASessionInfo->u8Ted;

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if (strWID.ps8WidVal != NULL)
		kfree(strWID.ps8WidVal);

	up(&hWaitResponse);

	return s32Error;
}

static signed int Handle_SetWowlanTrigger(void * drvHandler, u8 u8WowlanTrigger)
{	
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_WOWLAN_TRIGGER;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8*)&u8WowlanTrigger;
	strWID.s32ValueSize = sizeof(s8);	

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if(s32Error)
	{
		PRINT_D(HOSTINF_DBG,"Failed to send wowlan trigger config packet\n");
		WILC_ERRORREPORT(s32Error,WILC_FAIL);
	}

	WILC_CATCH(s32Error)
	{

	}

	return s32Error;
}

static signed int Handle_SetTxPwr(void * drvHandler, u8 u8TxPwr)
{	
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_TX_POWER;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8*)&u8TxPwr;
	strWID.s32ValueSize = sizeof(s8);	

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);

	if(s32Error)
	{
		PRINT_D(HOSTINF_DBG,"Failed to switch log terminal\n");
		WILC_ERRORREPORT(s32Error,WILC_INVALID_STATE);
	}

	WILC_CATCH(s32Error)
	{

	}

	return s32Error;
}

static signed int Handle_GetTxPwr(void * drvHandler, u8* pu8TxPwr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = WID_TX_POWER;
	strWID.enuWIDtype= WID_CHAR;
	strWID.s32ValueSize = sizeof(s8);
	strWID.ps8WidVal = (s8*)(pu8TxPwr);

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
		
	if(s32Error)
	{
		PRINT_ER("Failed to send scan paramters config packet\n");
		//WILC_ERRORREPORT(s32Error, s32Error);
	}
	up(&hWaitResponse);
	return s32Error; 
}

static signed int Handle_SetAntennaMode(void * drvHandler,struct tstrHostIFSetAnt* strPtrSetAnt)
{
	int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)drvHandler;
	
	strWID.u16WIDid 	= (u16)WID_ANTENNA_SELECTION;
	strWID.enuWIDtype	= WID_BIN;
	strWID.s32ValueSize = sizeof(struct tstrHostIFSetAnt);
	strWID.ps8WidVal 	= (u8*)strPtrSetAnt;

#ifdef ANT_SWTCH_SNGL_GPIO_CTRL
	PRINT_D(CFG80211_DBG, "set antenna %d on GPIO %d\n",strPtrSetAnt->mode,strPtrSetAnt->antenna1);
#elif defined(ANT_SWTCH_DUAL_GPIO_CTRL)
	PRINT_D(CFG80211_DBG, "set antenna %d on GPIOs %d and %d\n",strPtrSetAnt->mode,strPtrSetAnt->antenna1,strPtrSetAnt->antenna2);
#endif
	
	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true,(int)pstrWFIDrv);
		
	if(s32Error)
	{
		PRINT_ER("Failed to send scan paramters config packet\n"); 
	} 
	return s32Error; 
}


/*
 * Main thread to handle message queue requests
 */
static int hostIFthread(void *pvArg)
{
	unsigned int u32Ret;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_WFIDrv *pstrWFIDrv;

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	while (1) {
		WILC_MsgQueueRecv(&gMsgQHostIF, &strHostIFmsg,
				 sizeof(struct tstrHostIFmsg), &u32Ret);
		pstrWFIDrv = (struct WILC_WFIDrv *)strHostIFmsg.drvHandler;
		if (strHostIFmsg.u16MsgId == HOST_IF_MSG_EXIT) {
			PRINT_D(GENERIC_DBG, "THREAD: Exiting HostIfThread\n");
			break;
		}

		/*Re-Queue HIF message*/
		if ((!g_wilc_initialized)) {
			PRINT_D(GENERIC_DBG, "--WAIT--");
			msleep(200);
			WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					 sizeof(struct tstrHostIFmsg));
			continue;
		}

		if (strHostIFmsg.u16MsgId == HOST_IF_MSG_CONNECT &&
		    pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult != NULL) {
			PRINT_D(HOSTINF_DBG, "Requeue connect request till scan done received\n");
			WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					 sizeof(struct tstrHostIFmsg));
			usleep_range(2000, 2100);
			continue;
		}

		switch (strHostIFmsg.u16MsgId) {
			case HOST_IF_MSG_Q_IDLE:
			{
				Handle_wait_msg_q_empty();
				break;
			}

			case HOST_IF_MSG_SCAN:
			{
				Handle_Scan(strHostIFmsg.drvHandler,
					    &strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr);
				break;
			}

			case HOST_IF_MSG_CONNECT:
			{
				Handle_Connect(strHostIFmsg.drvHandler,
					       &strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr);
				break;
			}

				/*BugID_5137*/
			case HOST_IF_MSG_FLUSH_CONNECT:
			{
				Handle_FlushConnect(strHostIFmsg.drvHandler);
				break;
			}

			case HOST_IF_MSG_RCVD_NTWRK_INFO:
			{
				Handle_RcvdNtwrkInfo(strHostIFmsg.drvHandler,
						     &strHostIFmsg.uniHostIFmsgBody.strRcvdNetworkInfo);
				break;
			}

			case HOST_IF_MSG_RCVD_GNRL_ASYNC_INFO:
			{
				Handle_RcvdGnrlAsyncInfo(strHostIFmsg.drvHandler,
							 &strHostIFmsg.uniHostIFmsgBody.strRcvdGnrlAsyncInfo);
				break;
			}

			case HOST_IF_MSG_KEY:
			{
				Handle_Key(strHostIFmsg.drvHandler,
					   &strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr);
				break;
			}

			case HOST_IF_MSG_CFG_PARAMS:
			{
				Handle_CfgParam(strHostIFmsg.drvHandler,
						&strHostIFmsg.uniHostIFmsgBody.strHostIFCfgParamAttr);
				break;
			}

			case HOST_IF_MSG_SET_CHANNEL:
			{
				Handle_SetChannel(strHostIFmsg.drvHandler,
						  &strHostIFmsg.uniHostIFmsgBody.strHostIFSetChan);
				break;
			}

	#ifdef WILC_BT_COEXISTENCE
			case HOST_IF_MSG_CHANGE_BT_COEX_MODE:
			{
				Handle_BTCoexModeChange(strHostIFmsg.drvHandler,
							&strHostIFmsg.uniHostIFmsgBody.strHostIfBTMode);
				break;
			}

	#endif
			case HOST_IF_MSG_DISCONNECT:
			{
				Handle_Disconnect(strHostIFmsg.drvHandler);
				break;
			}

			case HOST_IF_MSG_RCVD_SCAN_COMPLETE:
			{
				del_timer(&(pstrWFIDrv->hScanTimer));
				PRINT_D(HOSTINF_DBG, "scan completed successfully\n");

				/*BugID_5213
				*Allow chip sleep, only if both interfaces are not connected
				*/
				if (!linux_wlan_get_num_conn_ifcs())
					chip_sleep_manually(INFINITE_SLEEP_TIME,
							    PWR_DEV_SRC_WIFI);

				Handle_ScanDone(strHostIFmsg.drvHandler, SCAN_EVENT_DONE);

	#ifdef WILC_P2P
				if (pstrWFIDrv->u8RemainOnChan_pendingreq)
					Handle_RemainOnChan(strHostIFmsg.drvHandler,
							    &strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan);
	#endif /* WILC_P2P */

				break;
			}

			case HOST_IF_MSG_GET_RSSI:
			{
				Handle_GetRssi(strHostIFmsg.drvHandler);
				break;
			}

			case HOST_IF_MSG_GET_LINKSPEED:
			{
				Handle_GetLinkspeed(strHostIFmsg.drvHandler);
				break;
			}

			case HOST_IF_MSG_GET_STATISTICS:
			{
				Handle_GetStatistics(strHostIFmsg.drvHandler,
						     (struct tstrStatistics *)strHostIFmsg.uniHostIFmsgBody.pUserData);
				break;
			}

			case HOST_IF_MSG_GET_CHNL:
			{
				Handle_GetChnl(strHostIFmsg.drvHandler);
				break;
			}

	#ifdef WILC_AP_EXTERNAL_MLME
			case HOST_IF_MSG_ADD_BEACON:
			{
				Handle_AddBeacon(strHostIFmsg.drvHandler,
						 &strHostIFmsg.uniHostIFmsgBody.strHostIFSetBeacon);
				break;
			}
			break;

			case HOST_IF_MSG_DEL_BEACON:
			{
				Handle_DelBeacon(strHostIFmsg.drvHandler,
						 &strHostIFmsg.uniHostIFmsgBody.strHostIFDelBeacon);
				break;
			}
			break;

			case HOST_IF_MSG_ADD_STATION:
			{
				Handle_AddStation(strHostIFmsg.drvHandler,
						  &strHostIFmsg.uniHostIFmsgBody.strAddStaParam);
				break;
			}

			case HOST_IF_MSG_DEL_STATION:
			{
				Handle_DelStation(strHostIFmsg.drvHandler,
						  &strHostIFmsg.uniHostIFmsgBody.strDelStaParam);
				break;
			}

			case HOST_IF_MSG_EDIT_STATION:
			{
				Handle_EditStation(strHostIFmsg.drvHandler,
						   &strHostIFmsg.uniHostIFmsgBody.strEditStaParam);
				break;
			}

			case HOST_IF_MSG_GET_INACTIVETIME:
			{
				Handle_Get_InActiveTime(strHostIFmsg.drvHandler,
							&strHostIFmsg.uniHostIFmsgBody.strHostIfStaInactiveT);
				break;
			}

	#endif /*WILC_AP_EXTERNAL_MLME*/
			case HOST_IF_MSG_SCAN_TIMER_FIRED:
			{
				PRINT_INFO(HOSTINF_DBG, "Scan Timeout\n");
				Handle_ScanDone(strHostIFmsg.drvHandler,
						SCAN_EVENT_ABORTED);

				break;
			}

			case HOST_IF_MSG_CONNECT_TIMER_FIRED:
			{
				PRINT_INFO(HOSTINF_DBG, "Connect Timeout\n");
				Handle_ConnectTimeout(strHostIFmsg.drvHandler);
				break;
			}

			case HOST_IF_MSG_POWER_MGMT:
			{
				Handle_PowerManagement(strHostIFmsg.drvHandler,
						       &strHostIFmsg.uniHostIFmsgBody.strPowerMgmtparam);
				break;
			}

			case HOST_IF_MSG_SET_WFIDRV_HANDLER:
			{
				Handle_SetWfiDrvHandler(&strHostIFmsg.uniHostIFmsgBody.strHostIfSetDrvHandler);

				break;
			}

			case HOST_IF_MSG_SET_OPERATION_MODE:
			{
				Handle_SetOperationMode(strHostIFmsg.drvHandler,
							&strHostIFmsg.uniHostIFmsgBody.strHostIfSetOperationMode);

				break;
			}

			case HOST_IF_MSG_SET_IPADDRESS:
			{
				PRINT_D(HOSTINF_DBG, "HOST_IF_MSG_SET_IPADDRESS\n");
				Handle_set_IPAddress(strHostIFmsg.drvHandler,
						     strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.au8IPAddr,
						     strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.idx);
				break;
			}

			case HOST_IF_MSG_GET_IPADDRESS:
			{
				PRINT_D(HOSTINF_DBG, "HOST_IF_MSG_SET_IPADDRESS\n");
				Handle_get_IPAddress(strHostIFmsg.drvHandler,
						     strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.au8IPAddr,
						     strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.idx);
				break;
			}

			/*BugID_5077*/
			case HOST_IF_MSG_SET_MAC_ADDRESS:
			{
				Handle_SetMacAddress(strHostIFmsg.drvHandler,
						     &strHostIFmsg.uniHostIFmsgBody.strHostIfSetMacAddress);
				break;
			}

			/*BugID_5213*/
			case HOST_IF_MSG_GET_MAC_ADDRESS:
			{
				Handle_GetMacAddress(strHostIFmsg.drvHandler,
						     &strHostIFmsg.uniHostIFmsgBody.strHostIfGetMacAddress);
				break;
			}

	#ifdef WILC_P2P
			case HOST_IF_MSG_REMAIN_ON_CHAN:
			{
				PRINT_D(HOSTINF_DBG, "HOST_IF_MSG_REMAIN_ON_CHAN\n");
				Handle_RemainOnChan(strHostIFmsg.drvHandler,
						    &strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan);
				break;
			}

			case HOST_IF_MSG_REGISTER_FRAME:
			{
				PRINT_D(HOSTINF_DBG, "HOST_IF_MSG_REGISTER_FRAME\n");
				Handle_RegisterFrame(strHostIFmsg.drvHandler,
						     &strHostIFmsg.uniHostIFmsgBody.strHostIfRegisterFrame);
				break;
			}

			case HOST_IF_MSG_LISTEN_TIMER_FIRED:
			{
				Handle_ListenStateExpired(strHostIFmsg.drvHandler,
							  &strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan);
				break;
			}

	#endif /* WILC_P2P */
			case HOST_IF_MSG_SET_MULTICAST_FILTER:
			{
				PRINT_D(HOSTINF_DBG, "HOST_IF_MSG_SET_MULTICAST_FILTER\n");
				Handle_SetMulticastFilter(strHostIFmsg.drvHandler,
							  &strHostIFmsg.uniHostIFmsgBody.strHostIfSetMulti);
				break;
			}

			/*BugID_5222*/
			case HOST_IF_MSG_ADD_BA_SESSION:
			{
				Handle_AddBASession(strHostIFmsg.drvHandler,
						    &strHostIFmsg.uniHostIFmsgBody.strHostIfBASessionInfo);
				break;
			}

			case HOST_IF_MSG_DEL_ALL_STA:
			{
				Handle_DelAllSta(strHostIFmsg.drvHandler,
						 &strHostIFmsg.uniHostIFmsgBody.strHostIFDelAllSta);
				break;
			}

			case HOST_IF_MSG_SEND_BUFFERED_EAP:
			{
				Handle_SendBufferedEAP(strHostIFmsg.drvHandler,
						       &strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP);
				break;
			}
			case HOST_IF_MSG_SET_TX_POWER:
			{
				Handle_SetTxPwr(strHostIFmsg.drvHandler,strHostIFmsg.uniHostIFmsgBody.strHostIFTxPwr.u8TxPwr);
				break;
			}

			case HOST_IF_MSG_GET_TX_POWER:
			{
				Handle_GetTxPwr(strHostIFmsg.drvHandler,strHostIFmsg.uniHostIFmsgBody.strHostIFGetTxPwr.u8TxPwr);
				break;
			}
			case HOST_IF_MSG_SET_ANTENNA_MODE:
			{
				Handle_SetAntennaMode(strHostIFmsg.drvHandler,&strHostIFmsg.uniHostIFmsgBody.strHostIFSetAnt);
				break;				
			}
				case HOST_IF_MSG_SET_WOWLAN_TRIGGER:
			{
				Handle_SetWowlanTrigger(strHostIFmsg.drvHandler,strHostIFmsg.uniHostIFmsgBody.strHostIFWowlanTrigger.u8WowlanTrigger);
				break;
			}
				
			default:
			{
				PRINT_ER("[Host Interface] undefined Received Msg ID\n");
				break;
			}
		}
	}

	PRINT_D(HOSTINF_DBG, "Releasing thread exit semaphore\n");
	up(&hSemHostIFthrdEnd);

	while (!kthread_should_stop())
				schedule();
	return 0;
}

static void TimerCB_Scan(unsigned long function_context)
{
	struct tstrHostIFmsg strHostIFmsg;

	/* prepare the Timer Callback message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.drvHandler = (void *)function_context;
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SCAN_TIMER_FIRED;

	/* send the message */
	WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
			 sizeof(struct tstrHostIFmsg));
}

static void TimerCB_Connect(unsigned long function_context)
{
	struct tstrHostIFmsg strHostIFmsg;

	/*prepare the Timer Callback message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.drvHandler = (void *)function_context;
	strHostIFmsg.u16MsgId = HOST_IF_MSG_CONNECT_TIMER_FIRED;

	/* send the message */
	WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
			 sizeof(struct tstrHostIFmsg));
}

/*
 * Sends a buffered eap to WPAS
 */
signed int host_int_send_buffered_eap(struct WFIDrvHandle *hWFIDrv,
				      tWILCpfFrmToLinux pfFrmToLinux,
				      tWILCpfFreeEAPBuffParams pfFreeEAPBuffParams,
				      u8 *pu8Buff, unsigned int u32Size,
				      unsigned int u32PktOffset,
				      void *pvUserArg)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL || pfFrmToLinux == NULL || pfFreeEAPBuffParams == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Scan Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_SEND_BUFFERED_EAP;
	strHostIFmsg.drvHandler = hWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pfFrmToLinux = pfFrmToLinux;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pfFreeEAPBuffParams = pfFreeEAPBuffParams;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.u32Size = u32Size;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.u32PktOffset = u32PktOffset;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pu8Buff = kmalloc(u32Size + u32PktOffset, GFP_ATOMIC);
	if(strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pu8Buff != NULL)
	{
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pu8Buff, pu8Buff, u32Size + u32PktOffset);
	}
	else
	{
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);
	}
	
	strHostIFmsg.uniHostIFmsgBody.strHostIFSendBufferedEAP.pvUserArg = pvUserArg;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send message queue buffered eapol\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * only in BSS STA mode if External Supplicant support is enabled.
 * removes all WPA/WPA2 station key entries from MAC hardware.
 */
signed int host_int_remove_key(struct WFIDrvHandle *hWFIDrv, const u8 *pu8StaAddress)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid	= (u16)WID_REMOVE_KEY;
	strWID.enuWIDtype	= WID_STR;
	strWID.ps8WidVal	= (s8 *)pu8StaAddress;
	strWID.s32ValueSize = 6;

	return s32Error;
}

/*
 * valid only in BSS STA mode if External Supplicant support is enabled.
 * remove a WEP key entry from MAC HW.
 * The BSS Station automatically finds the index of the entry using its
 * BSS ID and removes that entry from the MAC hardware.
 */
signed int host_int_remove_wep_key(struct WFIDrvHandle *hWFIDrv, u8 u8keyIdx)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Remove Wep Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WEP_Key;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = REMOVEKEY;
	strHostIFmsg.drvHandler = hWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx = u8keyIdx;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if(s32Error)
		PRINT_ER("Error in sending message queue : Request to remove WEP key\n");
	else
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Sets the index of the WEP encryption key in use in the key table
 */
signed int host_int_set_WEPDefaultKeyID(struct WFIDrvHandle *hWFIDrv, u8 u8Index)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WEP_Key;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = DEFAULTKEY;
	strHostIFmsg.drvHandler = hWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx = u8Index;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Error in sending message queue : Default key index\n");
	else
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * valid only in BSS STA mode if External Supplicant support is enabled.
 * sets WEP key entry into MAC hardware when it receives the
 * corresponding request from NDIS.
 * @hWFIDrv handle to the wifi driver
 * @pu8WepKey message containing WEP Key in the following format
				|---------------------------------------|
				|Key ID Value | Key Length |	Key		|
				|-------------|------------|------------|
				|	1byte	  |		1byte  | Key Length	|
				|---------------------------------------|

 */
signed int host_int_add_wep_key_bss_sta(struct WFIDrvHandle *hWFIDrv,
					const u8 *pu8WepKey, u8 u8WepKeylen,
					u8 u8Keyidx)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WEP_Key;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY;
	strHostIFmsg.drvHandler = hWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey = kmalloc(u8WepKeylen, GFP_ATOMIC);

	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey,
	       pu8WepKey, u8WepKeylen);

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen = (u8WepKeylen);

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx = u8Keyidx;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Error in sending message queue :WEP Key\n");
	else
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

#ifdef WILC_AP_EXTERNAL_MLME
/*
 * valid only in BSS AP mode if External Supplicant support is enabled.
 * sets WEP key entry into MAC hardware when it receives the
 * corresponding request from NDIS.
 */
signed int host_int_add_wep_key_bss_ap(struct WFIDrvHandle *hWFIDrv,
				       const u8 *pu8WepKey, u8 u8WepKeylen,
				       u8 u8Keyidx, u8 u8mode,
				       enum AUTHTYPE tenuAuth_type)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	u8 i;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	if(INFO)
	{
		for (i = 0; i < u8WepKeylen; i++)
			PRINT_INFO(HOSTAPD_DBG, "KEY is %x\n", pu8WepKey[i]);
	}
	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WEP_Key;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY_AP;
	strHostIFmsg.drvHandler = hWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey = kmalloc((u8WepKeylen), GFP_ATOMIC);

	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwepAttr.pu8WepKey,
	       pu8WepKey, (u8WepKeylen));

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8WepKeylen = (u8WepKeylen);

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8Wepidx = u8Keyidx;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.u8mode = u8mode;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwepAttr.tenuAuth_type = tenuAuth_type;
	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));

	if (s32Error)
		PRINT_ER("Error in sending message queue :WEP Key\n");
	else	
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
#endif

/*
 * adds ptk Key
*  PTK Key has the following format
*|-----------------------------------------------------------------------------|
*|Station address | Key Length |	Temporal Key | Rx Michael Key |Tx Michael Key |
*|----------------|------------|--------------|----------------|---------------|
*|	6 bytes		 |	1byte	  |   16 bytes	 |	  8 bytes	  |	   8 bytes	  |
*|-----------------------------------------------------------------------------|
 */
signed int host_int_add_ptk(struct WFIDrvHandle *hWFIDrv, u8 *pu8Ptk,
			    u8 u8PtkKeylen, const u8 *mac_addr, u8 *pu8RxMic,
			    u8 *pu8TxMic, u8 mode, u8 u8Ciphermode, u8 u8Idx)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	u8 u8KeyLen = u8PtkKeylen;
	unsigned int i;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	if (pu8RxMic != NULL)
		u8KeyLen += RX_MIC_KEY_LEN;
	if (pu8TxMic != NULL)
		u8KeyLen += TX_MIC_KEY_LEN;

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WPAPtk;
#ifdef WILC_AP_EXTERNAL_MLME
	if (mode == AP_MODE) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY_AP;
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
		uniHostIFkeyAttr.strHostIFwpaAttr.u8keyidx = u8Idx;
	}
#endif
	if (mode == STATION_MODE)
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.pu8key = kmalloc(u8PtkKeylen, GFP_ATOMIC);

	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
	       pu8Ptk, u8PtkKeylen);

	if (pu8RxMic != NULL) {
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key + 16,
		       pu8RxMic, RX_MIC_KEY_LEN);
		for (i = 0; i < RX_MIC_KEY_LEN; i++)
			PRINT_INFO(CFG80211_DBG, "PairwiseRx[%d] = %x\n", i, pu8RxMic[i]);
	}
	if (pu8TxMic != NULL) {
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key + 24,
		       pu8TxMic, TX_MIC_KEY_LEN);
	   if(INFO)
	   {
			for (i = 0; i < TX_MIC_KEY_LEN; i++)
				PRINT_INFO(CFG80211_DBG, "PairwiseTx[%d] = %x\n", i, pu8TxMic[i]);
		}
	}

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen = u8KeyLen;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.u8Ciphermode = u8Ciphermode;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.pu8macaddr = mac_addr;
	strHostIFmsg.drvHandler = hWFIDrv;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));

	if (s32Error)
		PRINT_ER("Error in sending message queue:  PTK Key\n");
    else
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * adds Rx GTk Key
 * @pu8RxGtk : contains temporal key | Rx Mic | Tx Mic
 * @u8GtkKeylen :The total key length
 */
signed int host_int_add_rx_gtk(struct WFIDrvHandle *hWFIDrv, u8 *pu8RxGtk,
			       u8 u8GtkKeylen, u8 u8KeyIdx,
			       unsigned int u32KeyRSClen, u8 *KeyRSC,
			       u8 *pu8RxMic, u8 *pu8TxMic, u8 mode,
			       u8 u8Ciphermode)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	u8 u8KeyLen = u8GtkKeylen;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	if (pu8RxMic != NULL)
		u8KeyLen += RX_MIC_KEY_LEN;
	if (pu8TxMic != NULL)
		u8KeyLen += TX_MIC_KEY_LEN;
	if (KeyRSC != NULL) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
		uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq = kmalloc(u32KeyRSClen, GFP_ATOMIC);

		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8seq,
		       KeyRSC, u32KeyRSClen);
	}

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = WPARxGtk;
	strHostIFmsg.drvHandler = hWFIDrv;

#ifdef WILC_AP_EXTERNAL_MLME
	if (mode == AP_MODE) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY_AP;
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.u8Ciphermode = u8Ciphermode;
	}
#endif /* WILC_AP_EXTERNAL_MLME */
	if (mode == STATION_MODE)
		strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.pu8key = kmalloc(u8KeyLen, GFP_ATOMIC);

	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key,
	       pu8RxGtk, u8GtkKeylen);

	if (pu8RxMic != NULL)
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key + 16,
		       pu8RxMic, RX_MIC_KEY_LEN);

	if (pu8TxMic != NULL)
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFwpaAttr.pu8key + 24,
		       pu8TxMic, TX_MIC_KEY_LEN);

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.u8keyidx = u8KeyIdx;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.u8Keylen = u8KeyLen;

	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.
	uniHostIFkeyAttr.strHostIFwpaAttr.u8seqlen = u32KeyRSClen;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Error in sending message queue:  RX GTK\n");
	else
		down(&(pstrWFIDrv->hSemTestKeyBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * caches the pmkid valid only in BSS STA mode if External Supplicant
 * support is enabled. This Function sets the PMKID in firmware
 * when host drivr receives the corresponding request from NDIS.
 * The firmware then includes theset PMKID in the appropriate
 * management frames
* PMKID Info has the following format
* |-----------------------------------------------------------------|
* |NumEntries |	BSSID[1] | PMKID[1] |  ...	| BSSID[K] | PMKID[K] |
* |-----------|------------|----------|-------|----------|----------|
* |	   1	|		6	 |   16		|  ...	|	 6	   |	16	  |
* |-----------------------------------------------------------------|
 */
signed int host_int_set_pmkid_info(struct WFIDrvHandle *hWFIDrv,
				   struct tstrHostIFpmkidAttr *pu8PmkidInfoArray)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	unsigned int i;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_KEY;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.enuKeyType = PMKSA;
	strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.u8KeyAction = ADDKEY;
	strHostIFmsg.drvHandler = hWFIDrv;

	for (i = 0; i < pu8PmkidInfoArray->numpmkid; i++) {
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFpmkidAttr.pmkidlist[i].bssid, &pu8PmkidInfoArray->pmkidlist[i].bssid,
		       ETH_ALEN);

		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFkeyAttr.uniHostIFkeyAttr.strHostIFpmkidAttr.pmkidlist[i].pmkid, &pu8PmkidInfoArray->pmkidlist[i].pmkid,
		       PMKID_LEN);
	}

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER(" Error in sending messagequeue: PMKID Info\n");

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * valid only in BSS STA mode if External Supplicant
 * support is enabled. This Function sets the PMKID in firmware
 * when host drivr receives the corresponding request from NDIS.
 * The firmware then includes theset PMKID in the appropriate
 * management frames
* PMKID Info in the following format
* |-----------------------------------------------------------------|
* |NumEntries |	BSSID[1] | PMKID[1] |  ...	| BSSID[K] | PMKID[K] |
* |-----------|------------|----------|-------|----------|----------|
* |	   1	|		6	 |   16		|  ...	|	 6	   |	16	  |
* |-----------------------------------------------------------------|
 */
signed int host_int_get_pmkid_info(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8PmkidInfoArray,
				   unsigned int u32PmkidInfoLen)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid	= (u16)WID_PMKID_INFO;
	strWID.enuWIDtype	= WID_STR;
	strWID.s32ValueSize = u32PmkidInfoLen;
	strWID.ps8WidVal = pu8PmkidInfoArray;

	return s32Error;
}

/*
 * AP/STA mode. This function gives the pass phrase used to
 * generate the Pre-Shared Key when WPA/WPA2 is enabled
 * The length of the field can vary from 8 to 64 bytes,
 * the lower layer should get the
 */
signed int host_int_set_RSNAConfigPSKPassPhrase(struct WFIDrvHandle *hWFIDrv,
						u8 *pu8PassPhrase,
						u8 u8Psklength)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	/*validating psk length*/
	if ((u8Psklength > 7) && (u8Psklength < 65)) {
		strWID.u16WIDid	= (u16)WID_11I_PSK;
		strWID.enuWIDtype	= WID_STR;
		strWID.ps8WidVal	= pu8PassPhrase;
		strWID.s32ValueSize = u8Psklength;
	}

	return s32Error;
}
/*
 * gets mac address
 */
signed int host_int_get_MacAddress(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8MacAddress)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_MAC_ADDRESS;
	strHostIFmsg.uniHostIFmsgBody.strHostIfGetMacAddress.u8MacAddress = pu8MacAddress;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send get mac address\n");
		return WILC_FAIL;
	}

	down(&hWaitResponse);
	return s32Error;
}

/*
 * sets mac address
 */
signed int host_int_set_MacAddress(struct WFIDrvHandle *hWFIDrv,
				   u8 *pu8MacAddress)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	PRINT_D(HOSTINF_DBG, "mac addr = %x:%x:%x\n", pu8MacAddress[0], pu8MacAddress[1],
		 pu8MacAddress[2]);

	/* prepare setting mac address message */	
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_MAC_ADDRESS;
	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIfSetMacAddress.u8MacAddress,
	       pu8MacAddress, ETH_ALEN);
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send message queue: Set mac address\n");
		WILC_ERRORREPORT(s32Error, s32Error);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * gets the pass phrase:AP/STA mode. This function gets the pass phrase used to
 * generate the Pre-Shared Key when WPA/WPA2 is enabled
 * The length of the field can vary from 8 to 64 bytes,
 * the lower layer should get the
 */
signed int host_int_get_RSNAConfigPSKPassPhrase(struct WFIDrvHandle *hWFIDrv,
						u8 *pu8PassPhrase, u8 u8Psklength)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid	= (u16)WID_11I_PSK;
	strWID.enuWIDtype	= WID_STR;
	strWID.s32ValueSize = u8Psklength;
	strWID.ps8WidVal	= pu8PassPhrase;

	return s32Error;
}

/*
 * gets the site survey results
* site survey results in the 
* 				  following format 
* |---------------------------------------------------|
* | MsgLength | fragNo.	| MsgBodyLength	| MsgBody	|					
* |-----------|-----------|---------------|-----------|
* |	 1		|	  1		|		1		|	 1		|					
* -----------------------------------------	 |  ----------------
* 										     |   						
* 						|---------------------------------------|
* 						| Network1 | Netweork2 | ... | Network5 |
* 					|---------------------------------------|
* 						|	44	   |	44	   | ... |	 44		|
* -------------------------- | ---------------------------------------
* 							 |
* |---------------------------------------------------------------------|
* | SSID | BSS Type | Channel | Security Status| BSSID | RSSI |Reserved |
* 
* 
* |------|----------|---------|----------------|-------|------|---------|
* |  33  |	 1	  |	  1		|		1		 |	  6	 |	 1	|	 1	  |
* |---------------------------------------------------------------------|
 */
#ifndef CONNECT_DIRECT
signed int host_int_get_site_survey_results(struct WFIDrvHandle *hWFIDrv,
					    u8 ppu8RcvdSiteSurveyResults[][MAX_SURVEY_RESULT_FRAG_SIZE],
					    unsigned int u32MaxSiteSrvyFragLen)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID astrWIDList[2];
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}

	astrWIDList[0].u16WIDid = (u16)WID_SITE_SURVEY_RESULTS;
	astrWIDList[0].enuWIDtype = WID_STR;
	astrWIDList[0].ps8WidVal = ppu8RcvdSiteSurveyResults[0];
	astrWIDList[0].s32ValueSize = u32MaxSiteSrvyFragLen;

	astrWIDList[1].u16WIDid = (u16)WID_SITE_SURVEY_RESULTS;
	astrWIDList[1].enuWIDtype = WID_STR;
	astrWIDList[1].ps8WidVal = ppu8RcvdSiteSurveyResults[1];
	astrWIDList[1].s32ValueSize = u32MaxSiteSrvyFragLen;

	s32Error = SendConfigPkt(GET_CFG, astrWIDList, 2, true, driver_handler_id);

	/*get the value by searching the local copy*/
	if (s32Error) {
		PRINT_ER("Failed to send config packet to get survey results\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
#endif /* CONNECT_DIRECT */

/*
 * sets a start scan request
 */
signed int host_int_set_start_scan_req(struct WFIDrvHandle *hWFIDrv,
				       u8 scanSource)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid = (u16)WID_START_SCAN_REQ;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)&scanSource;
	strWID.s32ValueSize = sizeof(char);

	return s32Error;
}

/*
 * gets a start scan request
 */

signed int host_int_get_start_scan_req(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8ScanSource)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid = (u16)WID_START_SCAN_REQ;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)pu8ScanSource;
	strWID.s32ValueSize = sizeof(char);

	return s32Error;
}

/*
 * sets a join request
 */
signed int host_int_set_join_req(struct WFIDrvHandle *hWFIDrv, u8 *pu8bssid,
				 u8 *pu8ssid, size_t ssidLen,
				 const u8 *pu8IEs, size_t IEsLen,
				 tWILCpfConnectResult pfConnectResult, void *pvUserArg,
				 u8 u8security, enum AUTHTYPE tenuAuth_type,
				 u8 u8channel,
				 void *pJoinParams)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	enum tenuScanConnTimer enuScanConnTimer;

	if (pstrWFIDrv == NULL || pfConnectResult == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	if (hWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: gWFiDrvHandle = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	if (pJoinParams == NULL) {
		PRINT_ER("Unable to Join - JoinParams is NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	/* prepare the Connect Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_CONNECT;

	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.u8security = u8security;
	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.tenuAuth_type = tenuAuth_type;
	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.u8channel = u8channel;
	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pfConnectResult = pfConnectResult;
	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pvUserArg = pvUserArg;
	strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pJoinParams = pJoinParams;
	strHostIFmsg.drvHandler = hWFIDrv;

	if (pu8bssid != NULL) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8bssid = kmalloc(6, GFP_ATOMIC);
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8bssid,
		       pu8bssid, 6);
	}

	if (pu8ssid != NULL) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.ssidLen = ssidLen;
		strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8ssid = kmalloc(ssidLen, GFP_ATOMIC);
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8ssid,

		       pu8ssid, ssidLen);
	}

	if (pu8IEs != NULL) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.IEsLen = IEsLen;
		strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8IEs = kmalloc(IEsLen, GFP_ATOMIC);
		memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFconnectAttr.pu8IEs,
		       pu8IEs, IEsLen);
	}
	if (pstrWFIDrv->enuHostIFstate < HOST_IF_CONNECTING)
		pstrWFIDrv->enuHostIFstate = HOST_IF_CONNECTING;
	else
		PRINT_D(GENERIC_DBG, "Don't set state to 'connecting' as state is %d\n", pstrWFIDrv->enuHostIFstate);

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send message queue: Set join request\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	enuScanConnTimer = CONNECT_TIMER;
	pstrWFIDrv->hConnectTimer.data = (unsigned long)hWFIDrv;
	mod_timer(&(pstrWFIDrv->hConnectTimer), (jiffies + msecs_to_jiffies(HOST_IF_CONNECT_TIMEOUT)));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Flush a join request parameters to FW, but actual connection
 * The function is called in situation where WILC is connected to AP and
 * required to switch to hybrid FW for P2P connection
 */

signed int host_int_flush_join_req(struct WFIDrvHandle *hWFIDrv)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	if (!gu8FlushedJoinReq)	{
		s32Error = WILC_FAIL;
		return s32Error;
	}

	if (hWFIDrv  == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);


	strHostIFmsg.u16MsgId = HOST_IF_MSG_FLUSH_CONNECT;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send message queue: Flush join request\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * host_int_disconnect
 * disconnects from the currently associated network
 */
signed int host_int_disconnect(struct WFIDrvHandle *hWFIDrv, u16 u16ReasonCode)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	if (pstrWFIDrv == NULL)	{
		PRINT_ER("gWFiDrvHandle = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	/* prepare the Disconnect Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_DISCONNECT;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Failed to send message queue: disconnect\n");
	else
		down(&(pstrWFIDrv->hSemTestDisconnectBlock));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * disconnects a sta
 */
signed int host_int_disconnect_station(struct WFIDrvHandle *hWFIDrv, u8 assoc_id)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid = (u16)WID_DISCONNECT;
	strWID.enuWIDtype = WID_CHAR;
	strWID.ps8WidVal = (s8 *)&assoc_id;
	strWID.s32ValueSize = sizeof(char);

	return s32Error;
}

/*
 * gets a Association request info
 * assoc. req info in the following format
 * ------------------------------------------------------------------------
 * |                        Management Frame Format                    |
 * |-------------------------------------------------------------------| 
 * |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS |
 * |-------------|--------|--|--|-----|----------------|----------|----|
 * | 2           |2       |6 |6 |6    |		2       |0 - 2312  | 4  |
 * |-------------------------------------------------------------------|
 * |                                                                   |
 * |             Association Request Frame - Frame Body                |
 * |-------------------------------------------------------------------|
 * | Capability Information | Listen Interval | SSID | Supported Rates |
 * |------------------------|-----------------|------|-----------------|
 * |			2            |		 2         | 2-34 |		3-10        |
 * | ---------------------------------------------------------------------
 */
signed int host_int_get_assoc_req_info(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8AssocReqInfo,
				       unsigned int u32AssocReqInfoLen)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid = (u16)WID_ASSOC_REQ_INFO;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = pu8AssocReqInfo;
	strWID.s32ValueSize = u32AssocReqInfoLen;

	return s32Error;
}

/*
 * gets a Association Response info
 */
signed int host_int_get_assoc_res_info(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8AssocRespInfo,
				       unsigned int u32MaxAssocRespInfoLen,
				       unsigned int *pu32RcvdAssocRespInfoLen)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_ASSOC_RES_INFO;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = pu8AssocRespInfo;
	strWID.s32ValueSize = u32MaxAssocRespInfoLen;

	/* Sending Configuration packet */
	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Failed to send association response config packet\n");
		*pu32RcvdAssocRespInfoLen = 0;
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		*pu32RcvdAssocRespInfoLen = strWID.s32ValueSize;
	}
	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * gets a Association Response info
 *
 * Valid only in STA mode. This function gives the RSSI
 * values observed in all the channels at the time of scanning.
 * The length of the field is 1 greater that the total number of
 * channels supported. Byte 0 contains the number of channels while
 * each of Byte N contains the observed RSSI value for the channel index N.
 */
signed int host_int_get_rx_power_level(struct WFIDrvHandle *hWFIDrv,
				       u8 *pu8RxPowerLevel,
				       unsigned int u32RxPowerLevelLen)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;

	strWID.u16WIDid = (u16)WID_RX_POWER_LEVEL;
	strWID.enuWIDtype = WID_STR;
	strWID.ps8WidVal = pu8RxPowerLevel;
	strWID.s32ValueSize = u32RxPowerLevelLen;

	return s32Error;
}

/*
 * sets a channel
 * |-------------------------------------------------------------------| 
 * |          CHANNEL1      CHANNEL2 ....		             CHANNEL14	|
 * |  Input:         1             2					            14	|
 * |-------------------------------------------------------------------|
 */
signed int host_int_set_mac_chnl_num(struct WFIDrvHandle *hWFIDrv, u8 u8ChNum)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the set channel message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_CHANNEL;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSetChan.u8SetChan = u8ChNum;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

#ifdef WILC_BT_COEXISTENCE
signed int host_int_change_bt_coex_mode(struct WFIDrvHandle *hWFIDrv,
					tenuCoexMode u8BtCoexMode)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the set channel message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_CHANGE_BT_COEX_MODE;
	strHostIFmsg.uniHostIFmsgBody.strHostIfBTMode.u8BTCoexMode = u8BtCoexMode;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
#endif /* WILC_BT_COEXISTENCE */

signed int host_int_wait_msg_queue_idle(void)
{
	signed int s32Error = WILC_SUCCESS;

	struct tstrHostIFmsg strHostIFmsg;

	/* prepare the set driver handler message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_Q_IDLE;
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);
	
	/* wait untill MSG Q is empty*/
	down(&hWaitResponse);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_set_wfi_drv_handler(unsigned int u32address, u8 u8IfMode, char* pcIfName)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	/* prepare the set driver handler message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_WFIDRV_HANDLER;
	strHostIFmsg.uniHostIFmsgBody.strHostIfSetDrvHandler.u32Address = u32address;
	strHostIFmsg.uniHostIFmsgBody.strHostIfSetDrvHandler.u8IfMode = u8IfMode;

	if(!(memcmp(pcIfName, IFC_0, 5)))
		strHostIFmsg.uniHostIFmsgBody.strHostIfSetDrvHandler.u8IfName = WLAN_IFC;
	else if(!(memcmp(pcIfName, IFC_1, 4)))
		strHostIFmsg.uniHostIFmsgBody.strHostIfSetDrvHandler.u8IfName = P2P_IFC;
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_set_operation_mode(struct WFIDrvHandle *hWFIDrv,
				       unsigned int u32mode)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	/* prepare the set driver handler message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_OPERATION_MODE;
	strHostIFmsg.uniHostIFmsgBody.strHostIfSetOperationMode.u32Mode = u32mode;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
		}

	return s32Error;
}

/*
 * gets the current channel index
 * current channel index
 * |-----------------------------------------------------------------------| 
 * |          CHANNEL1      CHANNEL2 ....                     CHANNEL14	|
 * |  Input:         1             2                                 14	|
 * |-----------------------------------------------------------------------|
 */
signed int host_int_get_host_chnl_num(struct WFIDrvHandle *hWFIDrv, u8 *pu8ChNo)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	/* prepare the Get Channel Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_CHNL;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Failed to send get host channel param's message queue\n");
	else
		down(&(pstrWFIDrv->hSemGetCHNL));

	*pu8ChNo = gu8Chnl;

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Test function for setting wids
 */
signed int host_int_test_set_int_wid(struct WFIDrvHandle *hWFIDrv,
				     unsigned int u32TestMemAddr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	/*prepare configuration packet*/
	strWID.u16WIDid = (u16)WID_MEMORY_ADDRESS;
	strWID.enuWIDtype = WID_INT;
	strWID.ps8WidVal = (char *)&u32TestMemAddr;
	strWID.s32ValueSize = sizeof(unsigned int);

	s32Error = SendConfigPkt(SET_CFG, &strWID, 1, true, driver_handler_id);
	if (s32Error) {
		PRINT_ER("Test Function: Failed to set wid value\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_D(HOSTINF_DBG, "Successfully set wid value\n");
	}
	WILC_CATCH(s32Error){
	}

	return s32Error;
}

#ifdef WILC_AP_EXTERNAL_MLME
/*
 * host_int_get_inactive_time
 */
signed int host_int_get_inactive_time(struct WFIDrvHandle *hWFIDrv, u8 *mac,
				      unsigned int *pu32InactiveTime)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIfStaInactiveT.mac,
	       mac, ETH_ALEN);

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_INACTIVETIME;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Failed to send get host channel param's message queue");
	else
		down(&(pstrWFIDrv->hSemInactiveTime));

	*pu32InactiveTime = gu32InactiveTime;

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
#endif

/*
 * Test function for getting wids
 */
signed int host_int_test_get_int_wid(struct WFIDrvHandle *hWFIDrv,
				     unsigned int *pu32TestMemAddr)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrWID strWID;
	int driver_handler_id = 0;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}

	if(pstrWFIDrv != NULL)
	{
		driver_handler_id = pstrWFIDrv->driver_handler_id;
	}
	else
	{
		driver_handler_id = 0;
	}
	
	strWID.u16WIDid = (u16)WID_MEMORY_ADDRESS;
	strWID.enuWIDtype = WID_INT;
	strWID.ps8WidVal = (s8 *)pu32TestMemAddr;
	strWID.s32ValueSize = sizeof(unsigned int);

	s32Error = SendConfigPkt(GET_CFG, &strWID, 1, true, driver_handler_id);
	/*get the value by searching the local copy*/
	if (s32Error) {
		PRINT_ER("Test Function: Failed to get wid value\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_STATE);
	} else {
		PRINT_D(HOSTINF_DBG, "Successfully got wid value\n");
	}
	WILC_CATCH(s32Error){
	}
	return s32Error;
}

/*
 * gets the currently maintained RSSI value for the station.
 * The received signal strength value in dB.
 * The range of valid values is -128 to 0.
 */
signed int host_int_get_rssi(struct WFIDrvHandle *hWFIDrv, s8 *ps8Rssi)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	/* prepare the Get RSSI Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_RSSI;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send get host channel param's message queue\n");
		return WILC_FAIL;
	}

	down(&(pstrWFIDrv->hSemGetRSSI));

	if (ps8Rssi == NULL) {
		PRINT_ER("RSS pointer value is null");
		return WILC_FAIL;
	}

	*ps8Rssi = gs8Rssi;

	return s32Error;
}

signed int host_int_get_link_speed(struct WFIDrvHandle *hWFIDrv, s8 *ps8lnkspd)
{
	struct tstrHostIFmsg strHostIFmsg;
	signed int s32Error = WILC_SUCCESS;

	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	/* prepare the Get LINKSPEED Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_LINKSPEED;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send GET_LINKSPEED to message queue ");
		return WILC_FAIL;
	}

	down(&(pstrWFIDrv->hSemGetLINKSPEED));

	if (ps8lnkspd == NULL) {
		PRINT_ER("LINKSPEED pointer value is null");
		return WILC_FAIL;
	}

	*ps8lnkspd = gs8lnkspd;

	return s32Error;
}

signed int host_int_get_statistics(struct WFIDrvHandle *hWFIDrv,
				   struct tstrStatistics *pstrStatistics)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;

	/* prepare the Get RSSI Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_STATISTICS;
	strHostIFmsg.uniHostIFmsgBody.pUserData = (char *)pstrStatistics;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Failed to send get host channel param's message queue\n");
		return WILC_FAIL;
	}

	down(&hWaitResponse);
	return s32Error;
}

/*
 * scans a set of channels
 */
signed int host_int_scan(struct WFIDrvHandle *hWFIDrv, u8 u8ScanSource,
			 u8 u8ScanType, u8 *pu8ChnlFreqList,
			 u8 u8ChnlListLen, const u8 *pu8IEs,
			 size_t IEsLen, tWILCpfScanResult ScanResult,
			 void *pvUserArg,
			 struct tstrHiddenNetwork  *pstrHiddenNetwork)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	enum tenuScanConnTimer enuScanConnTimer;

	if (pstrWFIDrv == NULL || ScanResult == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

		/* prepare the Scan Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_SCAN;

	if (pstrHiddenNetwork != NULL) {
		strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.strHiddenNetwork.pstrHiddenNetworkInfo = pstrHiddenNetwork->pstrHiddenNetworkInfo;
		strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.strHiddenNetwork.u8ssidnum = pstrHiddenNetwork->u8ssidnum;
	} else {
		PRINT_WRN(HOSTINF_DBG, "pstrHiddenNetwork IS EQUAL TO NULL\n");
	}

	strHostIFmsg.drvHandler = hWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.u8ScanSource = u8ScanSource;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.u8ScanType = u8ScanType;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pfScanResult = ScanResult;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pvUserArg = pvUserArg;

	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.u8ChnlListLen = u8ChnlListLen;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pu8ChnlFreqList = kmalloc(u8ChnlListLen, GFP_ATOMIC);
	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pu8ChnlFreqList,
	       pu8ChnlFreqList, u8ChnlListLen);

	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.IEsLen = IEsLen;
	strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pu8IEs = kmalloc(IEsLen, GFP_ATOMIC);
	memcpy(strHostIFmsg.uniHostIFmsgBody.strHostIFscanAttr.pu8IEs,
	       pu8IEs, IEsLen);

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error) {
		PRINT_ER("Error in sending message queue scanning parameters: Error(%d)\n",
		       s32Error);
		WILC_ERRORREPORT(s32Error, WILC_FAIL);
	}

	enuScanConnTimer = SCAN_TIMER;
	PRINT_D(HOSTINF_DBG, ">> Starting the SCAN timer\n");
	pstrWFIDrv->hScanTimer.data = (unsigned long)hWFIDrv;
	mod_timer(&(pstrWFIDrv->hScanTimer),
		  (jiffies + msecs_to_jiffies(HOST_IF_SCAN_TIMEOUT)));

	WILC_CATCH(s32Error){
		}

	return s32Error;
}

/*
 * sets configuration wids values
 */
signed int hif_set_cfg(struct WFIDrvHandle *hWFIDrv,
		       struct tstrCfgParamVal *pstrCfgParamVal)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the WiphyParams Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_CFG_PARAMS;
	strHostIFmsg.uniHostIFmsgBody.strHostIFCfgParamAttr.pstrCfgParamVal = *pstrCfgParamVal;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * gets configuration wids values
 */
signed int hif_get_cfg(struct WFIDrvHandle *hWFIDrv, u16 u16WID, u16 *pu16WID_Value)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;

	down(&(pstrWFIDrv->gtOsCfgValuesSem));

	if (pstrWFIDrv == NULL) {
		PRINT_ER("Driver not initialized: pstrWFIDrv = NULL\n");
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);
	}
	PRINT_D(HOSTINF_DBG, "Getting configuration parameters\n");
	switch (u16WID)	{
	case WID_BSS_TYPE:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.bss_type;
	}
	break;

	case WID_AUTH_TYPE:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.auth_type;
	}
	break;

	case WID_AUTH_TIMEOUT:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.auth_timeout;
	}
	break;

	case WID_POWER_MANAGEMENT:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.power_mgmt_mode;
	}
	break;

	case WID_SHORT_RETRY_LIMIT:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.short_retry_limit;
	}
	break;

	case WID_LONG_RETRY_LIMIT:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.long_retry_limit;
	}
	break;

	case WID_FRAG_THRESHOLD:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.frag_threshold;
	}
	break;

	case WID_RTS_THRESHOLD:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.rts_threshold;
	}
	break;

	case WID_PREAMBLE:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.preamble_type;
	}
	break;

	case WID_SHORT_SLOT_ALLOWED:
	{
		*pu16WID_Value = (u16) pstrWFIDrv->strCfgValues.short_slot_allowed;
	}
	break;

	case WID_11N_TXOP_PROT_DISABLE:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.txop_prot_disabled;
	}
	break;

	case WID_BEACON_INTERVAL:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.beacon_interval;
	}
	break;

	case WID_DTIM_PERIOD:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.dtim_period;
	}
	break;

	case WID_SITE_SURVEY:
	{
		*pu16WID_Value = (u16)pstrWFIDrv->strCfgValues.site_survey_enabled;
	}
	break;

	case WID_SITE_SURVEY_SCAN_TIME:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.site_survey_scan_time;
	}
	break;

	case WID_ACTIVE_SCAN_TIME:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.active_scan_time;
	}
	break;

	case WID_PASSIVE_SCAN_TIME:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.passive_scan_time;
	}
	break;

	case WID_CURRENT_TX_RATE:
	{
		*pu16WID_Value = pstrWFIDrv->strCfgValues.curr_tx_rate;
	}
	break;

	default:
		break;
	}

	up(&(pstrWFIDrv->gtOsCfgValuesSem));

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Notifies host with stations found in scan
 * sends the beacon/probe response from scan
 */

void GetPeriodicRSSI(unsigned long pvArg)
{
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)pvArg;

	if (pstrWFIDrv == NULL)	{
		PRINT_ER("Driver handler is NULL\n");
		return;
	}

	if (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED) {
		signed int s32Error = WILC_SUCCESS;
		struct tstrHostIFmsg strHostIFmsg;

		/* prepare the Get RSSI Message */
		memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

		strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_RSSI;
		strHostIFmsg.drvHandler = pstrWFIDrv;

		s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					    sizeof(struct tstrHostIFmsg));
		if (s32Error) {
			PRINT_ER("Failed to send get host channel param's message queue ");
			return;
		}
	}
	g_hPeriodicRSSI.data = (unsigned long)pstrWFIDrv;
	mod_timer(&(g_hPeriodicRSSI), (jiffies + msecs_to_jiffies(5000)));
}

/*
 * host interface initialization function
 */
static unsigned int u32Intialized;
static unsigned int msgQ_created;
static unsigned int clients_count;

signed int host_int_init(struct WFIDrvHandle **phWFIDrv)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv;
	int err;
	
	PRINT_D(HOSTINF_DBG, "Initializing host interface for client %d\n",
		 clients_count + 1);

	gbScanWhileConnected = false;

		/*Allocate host interface private structure*/
	pstrWFIDrv  = kzalloc(sizeof(struct WILC_WFIDrv), GFP_KERNEL);
	if (!pstrWFIDrv)
		return -ENOMEM;

	memset(pstrWFIDrv,0,sizeof(struct WILC_WFIDrv));
	/*return driver handle to user*/
	*phWFIDrv = (struct WFIDrvHandle *)pstrWFIDrv;
	err = add_handler_in_list(pstrWFIDrv);
	if (err){ 
		s32Error = s32Error; 
		goto _fail_mem_; 
	}	
	
#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP

	set_obtaining_IP_flag(false);
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

	if (clients_count == 0)	{
		sema_init(&hSemHostIFthrdEnd, 0);
		sema_init(&hSemDeinitDrvHandle, 0);
		/*BugID_5348*/
		sema_init(&hSemHostIntDeinit, 1);
	}

	sema_init(&hWaitResponse, 0);
	sema_init(&(pstrWFIDrv->hSemTestKeyBlock), 0);
	sema_init(&(pstrWFIDrv->hSemTestDisconnectBlock), 0);
	sema_init(&(pstrWFIDrv->hSemGetRSSI), 0);
	sema_init(&(pstrWFIDrv->hSemGetLINKSPEED), 0);
	sema_init(&(pstrWFIDrv->hSemGetCHNL), 0);
	sema_init(&(pstrWFIDrv->hSemInactiveTime), 0);
	sema_init(&(pstrWFIDrv->gtOsCfgValuesSem), 1);

	PRINT_D(HOSTINF_DBG, "INIT: CLIENT COUNT %d\n", clients_count);

	if (clients_count == 0)	{
		WILC_MsgQueueCreate(&gMsgQHostIF);
		msgQ_created = 1;

		HostIFthreadHandler = kthread_run(hostIFthread, NULL,
						  "WILC_kthread");

		if (IS_ERR(HostIFthreadHandler)) {
			PRINT_ER("Failed to creat Thread\n");
			goto _fail_mq_;
		}
		setup_timer(&(g_hPeriodicRSSI), GetPeriodicRSSI, 0);
		g_hPeriodicRSSI.data = (unsigned long)pstrWFIDrv;
		mod_timer(&(g_hPeriodicRSSI), (jiffies + msecs_to_jiffies(5000)));
	}

	setup_timer(&(pstrWFIDrv->hScanTimer), TimerCB_Scan, 0);
	setup_timer(&(pstrWFIDrv->hConnectTimer), TimerCB_Connect, 0);

#ifdef WILC_P2P
	/*Remain on channel timer*/
	setup_timer(&(pstrWFIDrv->hRemainOnChannel), ListenTimerCB, 0);
#endif

	down(&(pstrWFIDrv->gtOsCfgValuesSem));

	pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;

	/*Initialize CFG WIDS Defualt Values*/

	pstrWFIDrv->strCfgValues.site_survey_enabled = SITE_SURVEY_OFF;
	pstrWFIDrv->strCfgValues.scan_source = DEFAULT_SCAN;
	pstrWFIDrv->strCfgValues.active_scan_time = ACTIVE_SCAN_TIME;
	pstrWFIDrv->strCfgValues.passive_scan_time = PASSIVE_SCAN_TIME;
	pstrWFIDrv->strCfgValues.curr_tx_rate = AUTORATE;

#ifdef WILC_P2P
	pstrWFIDrv->p2p_mgmt_timeout = 0;
#endif

	PRINT_INFO(HOSTINF_DBG,"Initialization values, Site survey value: %d\nScan source: %d\nActive scan time: %d\nPassive scan time: %d\nCurrent tx Rate = %d\n",
		pstrWFIDrv->strCfgValues.site_survey_enabled,
		pstrWFIDrv->strCfgValues.scan_source,
		pstrWFIDrv->strCfgValues.active_scan_time,
		pstrWFIDrv->strCfgValues.passive_scan_time,
		pstrWFIDrv->strCfgValues.curr_tx_rate);

	up(&(pstrWFIDrv->gtOsCfgValuesSem));

	s32Error = CoreConfiguratorInit();
	if (s32Error < 0) {
		PRINT_ER("Failed to initialize core configurator\n");
		goto _fail_mem_;
	}

	u32Intialized = 1;
	clients_count++;

	return s32Error;

_fail_mem_:
#ifdef WILC_P2P
	del_timer_sync(&(pstrWFIDrv->hRemainOnChannel));
#endif
	up(&(pstrWFIDrv->gtOsCfgValuesSem));
	del_timer_sync(&(pstrWFIDrv->hConnectTimer));
	del_timer_sync(&(pstrWFIDrv->hScanTimer));
	kthread_stop(HostIFthreadHandler);
_fail_mq_:
	WILC_MsgQueueDestroy(&gMsgQHostIF);
	kfree(pstrWFIDrv);

	return s32Error;
}

/*
 * host interface initialization function
 */

signed int host_int_deinit(struct WFIDrvHandle *hWFIDrv, char* pcIfName, u8 u8IfMode)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	int ret;
	
	ret = remove_handler_in_list(pstrWFIDrv);
	if (ret)
	s32Error = s32Error;
	
	if (pstrWFIDrv == NULL)	{
		PRINT_ER("pstrWFIDrv = NULL\n");
		return 0;
	}

	down(&hSemHostIntDeinit);

	terminated_handle = pstrWFIDrv;
	PRINT_D(HOSTINF_DBG, "De-initializing host interface for client %d\n",
		 clients_count);

	/*BugID_5348
	 *Destroy all timers before acquiring hSemDeinitDrvHandle
	 *to guarantee handling all messages befor proceeding
	 */
	if (del_timer_sync(&(pstrWFIDrv->hScanTimer)))
		PRINT_D(HOSTINF_DBG, ">> Scan timer is active\n");

	if (del_timer_sync(&(pstrWFIDrv->hConnectTimer)))
		PRINT_D(HOSTINF_DBG, ">> Connect timer is active\n");


	if (del_timer_sync(&(g_hPeriodicRSSI)))
		PRINT_D(HOSTINF_DBG, ">> Connect timer is active\n");

#ifdef WILC_P2P
	del_timer_sync(&(pstrWFIDrv->hRemainOnChannel));
#endif

	host_int_set_wfi_drv_handler((unsigned int)NULL, u8IfMode, pcIfName);
	down(&hSemDeinitDrvHandle);

	/*Calling the CFG80211 scan done function with the abort flag set to true*/
	if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
		pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult(SCAN_EVENT_ABORTED, NULL,
								pstrWFIDrv->strWILC_UsrScanReq.u32UserScanPvoid, NULL);

		pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult = NULL;
	}
	CoreConfiguratorDeInit();

	pstrWFIDrv->enuHostIFstate = HOST_IF_IDLE;

	gbScanWhileConnected = false;

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	if (clients_count == 1)	{
		if (del_timer_sync(&g_hPeriodicRSSI))
			PRINT_D(HOSTINF_DBG, ">> Connect timer is active\n");

		strHostIFmsg.u16MsgId = HOST_IF_MSG_EXIT;
		strHostIFmsg.drvHandler = hWFIDrv;

		s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					    sizeof(struct tstrHostIFmsg));
		if (s32Error != WILC_SUCCESS)
			PRINT_ER("Error in sending deinit's message queue message function: Error(%d)\n", s32Error);
		else			
			down(&hSemHostIFthrdEnd);

		kthread_stop(HostIFthreadHandler);
		HostIFthreadHandler = NULL;
		
		WILC_MsgQueueDestroy(&gMsgQHostIF);
		msgQ_created = 0;
	}

	down(&(pstrWFIDrv->gtOsCfgValuesSem));

	u32Intialized = 0;
	if (pstrWFIDrv != NULL)
		kfree(pstrWFIDrv);

	clients_count--;
	terminated_handle = NULL;
	up(&hSemHostIntDeinit);
	return s32Error;
}

/*
 * function to to be called when network info packet is received
 */
void NetworkInfoReceived(u8 *pu8Buffer, u32 u32Length)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	unsigned int drvHandler;
	struct WILC_WFIDrv *pstrWFIDrv = NULL;

	drvHandler = ((pu8Buffer[u32Length - 4]) | (pu8Buffer[u32Length - 3] << 8) |
		     (pu8Buffer[u32Length - 2] << 16) | (pu8Buffer[u32Length - 1] << 24));
	pstrWFIDrv = get_handler_from_id(drvHandler);

	if (pstrWFIDrv == NULL || pstrWFIDrv == terminated_handle)
		return;

	/* prepare the Asynchronous Network Info message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_RCVD_NTWRK_INFO;
	strHostIFmsg.drvHandler = pstrWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strRcvdNetworkInfo.u32Length = u32Length;
	strHostIFmsg.uniHostIFmsgBody.strRcvdNetworkInfo.pu8Buffer = kmalloc(u32Length, GFP_ATOMIC);
	memcpy(strHostIFmsg.uniHostIFmsgBody.strRcvdNetworkInfo.pu8Buffer,
	       pu8Buffer, u32Length);

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Error in sending network info message queue message parameters: Error(%d)\n", s32Error);
}

/*
 * function to be called when general Asynchronous info packet is received
 */
void GnrlAsyncInfoReceived(u8 *pu8Buffer, u32 u32Length)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	unsigned int drvHandler;
	struct WILC_WFIDrv *pstrWFIDrv = NULL;

	down(&hSemHostIntDeinit);

	drvHandler = ((pu8Buffer[u32Length - 4]) | (pu8Buffer[u32Length - 3] << 8) |
		     (pu8Buffer[u32Length - 2] << 16) | (pu8Buffer[u32Length - 1] << 24));
	pstrWFIDrv = get_handler_from_id(drvHandler);
	PRINT_D(HOSTINF_DBG, "General asynchronous info packet received\n");

	if (pstrWFIDrv == NULL || pstrWFIDrv == terminated_handle) {
		PRINT_ER("Wifi driver handler is equal to NULL\n");
		/*BugID_5348*/
		up(&hSemHostIntDeinit);
		return;
	}

	if (pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult == NULL) {
		/* received mac status is not needed when there is no current Connect Request */
		PRINT_ER("Received mac status is not needed when there is no current Connect Reques\n");
		/*BugID_5348*/
		up(&hSemHostIntDeinit);
		return;
	}

	/* prepare the General Asynchronous Info message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_RCVD_GNRL_ASYNC_INFO;
	strHostIFmsg.drvHandler = pstrWFIDrv;

	strHostIFmsg.uniHostIFmsgBody.strRcvdGnrlAsyncInfo.u32Length = u32Length;
	strHostIFmsg.uniHostIFmsgBody.strRcvdGnrlAsyncInfo.pu8Buffer = kmalloc(u32Length, GFP_ATOMIC);
	memcpy(strHostIFmsg.uniHostIFmsgBody.strRcvdGnrlAsyncInfo.pu8Buffer,
	       pu8Buffer, u32Length);

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		PRINT_ER("Error in sending message queue asynchronous message info: Error(%d)\n", s32Error);

	/*BugID_5348*/
	up(&hSemHostIntDeinit);
}

/*
 * Setting scan complete received notifcation in message queue
 */
void host_int_ScanCompleteReceived(u8 *pu8Buffer, u32 u32Length)
{
	signed int s32Error = WILC_SUCCESS;
	struct tstrHostIFmsg strHostIFmsg;
	unsigned int drvHandler;
	struct WILC_WFIDrv *pstrWFIDrv = NULL;

	drvHandler = ((pu8Buffer[u32Length - 4]) | (pu8Buffer[u32Length - 3] << 8) |
		     (pu8Buffer[u32Length - 2] << 16) | (pu8Buffer[u32Length - 1] << 24));
	pstrWFIDrv = get_handler_from_id(drvHandler);

	PRINT_D(GENERIC_DBG, "Scan notification received\n");

	if (pstrWFIDrv == NULL || pstrWFIDrv == terminated_handle)
		return;

	/*if there is an ongoing scan request*/	
	if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
		/* prepare theScan Done message */
		memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

		strHostIFmsg.u16MsgId = HOST_IF_MSG_RCVD_SCAN_COMPLETE;
		strHostIFmsg.drvHandler = pstrWFIDrv;

		s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					    sizeof(struct tstrHostIFmsg));
		if (s32Error)
			PRINT_ER("Error in sending message queue scan complete parameters: Error(%d)\n", s32Error);
	}
}

#ifdef WILC_P2P
signed int host_int_remain_on_channel(struct WFIDrvHandle *hWFIDrv,
				      unsigned int u32SessionID,
				      unsigned int u32duration, u16 chan,
				      tWILCpfRemainOnChanExpired RemainOnChanExpired,
				      tWILCpfRemainOnChanReady RemainOnChanReady,
				      void *pvUserArg)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the remainonchan Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_REMAIN_ON_CHAN;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.u16Channel = chan;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.pRemainOnChanExpired = RemainOnChanExpired;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.pRemainOnChanReady = RemainOnChanReady;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.pVoid = pvUserArg;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.u32duration = u32duration;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.u32ListenSessionID = u32SessionID;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_ListenStateExpired(struct WFIDrvHandle *hWFIDrv,
				       unsigned int u32SessionID)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/*Stopping remain-on-channel timer*/
	del_timer(&(pstrWFIDrv->hRemainOnChannel));

	/* prepare the timer fire Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));
	strHostIFmsg.u16MsgId = HOST_IF_MSG_LISTEN_TIMER_FIRED;
	strHostIFmsg.drvHandler = hWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRemainOnChan.u32ListenSessionID = u32SessionID;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_frame_register(struct WFIDrvHandle *hWFIDrv, u16 u16FrameType,
				   bool bReg)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_REGISTER_FRAME;
	switch (u16FrameType) {
	case ACTION:
		PRINT_D(HOSTINF_DBG, "ACTION\n");
		strHostIFmsg.uniHostIFmsgBody.strHostIfRegisterFrame.u8Regid = ACTION_FRM_IDX;
		break;

	case PROBE_REQ:
		PRINT_D(HOSTINF_DBG, "PROBE REQ\n");
		strHostIFmsg.uniHostIFmsgBody.strHostIfRegisterFrame.u8Regid = PROBE_REQ_IDX;
		break;

	default:
		PRINT_D(HOSTINF_DBG, "Not valid frame type\n");
		break;
	}
	strHostIFmsg.uniHostIFmsgBody.strHostIfRegisterFrame.u16FrameType = u16FrameType;
	strHostIFmsg.uniHostIFmsgBody.strHostIfRegisterFrame.bReg = bReg;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}
	return s32Error;
}
#endif

#ifdef WILC_AP_EXTERNAL_MLME
/*
 * Setting add beacon params in message queue
 */
signed int host_int_add_beacon(struct WFIDrvHandle *hWFIDrv,
			       unsigned int u32Interval,
			       unsigned int u32DTIMPeriod,
			       unsigned int u32HeadLen, u8 *pu8Head,
			       unsigned int u32TailLen, u8 *pu8Tail)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIFSetBeacon *pstrSetBeaconParam = &strHostIFmsg.uniHostIFmsgBody.strHostIFSetBeacon;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	PRINT_D(HOSTINF_DBG, "Setting adding beacon message queue params\n");

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_ADD_BEACON;
	strHostIFmsg.drvHandler = hWFIDrv;
	pstrSetBeaconParam->u32Interval = u32Interval;
	pstrSetBeaconParam->u32DTIMPeriod = u32DTIMPeriod;
	pstrSetBeaconParam->u32HeadLen = u32HeadLen;
	pstrSetBeaconParam->pu8Head = kmalloc(u32HeadLen, GFP_ATOMIC);
	if (pstrSetBeaconParam->pu8Head == NULL)
		WILC_ERRORREPORT(s32Error, WILC_NO_MEM);
	memcpy(pstrSetBeaconParam->pu8Head, pu8Head, u32HeadLen);
	pstrSetBeaconParam->u32TailLen = u32TailLen;

	/* Bug 4599 : if tail length = 0 skip allocating & copying */ 
	if (u32TailLen > 0) {
		pstrSetBeaconParam->pu8Tail = kmalloc(u32TailLen, GFP_ATOMIC);
		if (pstrSetBeaconParam->pu8Tail == NULL)
			WILC_ERRORREPORT(s32Error, WILC_NO_MEM);
		memcpy(pstrSetBeaconParam->pu8Tail, pu8Tail, u32TailLen);
	} else {
		pstrSetBeaconParam->pu8Tail = NULL;
	}
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);


	WILC_CATCH(s32Error){
		if (pstrSetBeaconParam->pu8Head != NULL)
			kfree(pstrSetBeaconParam->pu8Head);

		if (pstrSetBeaconParam->pu8Tail != NULL)
			kfree(pstrSetBeaconParam->pu8Tail);
	}

	return s32Error;
}

/*
 * Setting add beacon params in message queue
 */
signed int host_int_del_beacon(struct WFIDrvHandle *hWFIDrv)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_DEL_BEACON;
	strHostIFmsg.drvHandler = hWFIDrv;
	PRINT_D(HOSTINF_DBG, "Setting deleting beacon message queue params\n");

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	WILC_ERRORCHECK(s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Setting add station params in message queue
 */
signed int host_int_add_station(struct WFIDrvHandle *hWFIDrv,
				struct WILC_AddStaParam *pstrStaParams)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_AddStaParam *pstrAddStationMsg = &strHostIFmsg.uniHostIFmsgBody.strAddStaParam;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	PRINT_D(HOSTINF_DBG, "Setting adding station message queue params\n");

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_ADD_STATION;
	strHostIFmsg.drvHandler = hWFIDrv;

	memcpy(pstrAddStationMsg, pstrStaParams, sizeof(struct WILC_AddStaParam));
	if (pstrAddStationMsg->u8NumRates > 0) {
		pstrAddStationMsg->pu8Rates = kmalloc(pstrAddStationMsg->u8NumRates, GFP_ATOMIC);
		WILC_NULLCHECK(s32Error, pstrAddStationMsg->pu8Rates);

		memcpy(pstrAddStationMsg->pu8Rates, pstrStaParams->pu8Rates,
		       pstrAddStationMsg->u8NumRates);
	}

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Setting delete station params in message queue
 */
signed int host_int_del_station(struct WFIDrvHandle *hWFIDrv, u8 *pu8MacAddr)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIFDelSta *pstrDelStationMsg = &strHostIFmsg.uniHostIFmsgBody.strDelStaParam;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	PRINT_D(HOSTINF_DBG, "Setting deleting station message queue params\n");

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_DEL_STATION;
	strHostIFmsg.drvHandler = hWFIDrv;

	/*BugID_4795: Handling situation of deleting all stations*/
	if (pu8MacAddr == NULL)
		memset(pstrDelStationMsg->au8MacAddr, 255, ETH_ALEN);
	else
		memcpy(pstrDelStationMsg->au8MacAddr, pu8MacAddr, ETH_ALEN);

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}
/*
 * Setting del station params in message queue
 */
signed int host_int_del_allstation(struct WFIDrvHandle *hWFIDrv,
				   u8 pu8MacAddr[][ETH_ALEN])
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIFDelAllSta *pstrDelAllStationMsg = &strHostIFmsg.uniHostIFmsgBody.strHostIFDelAllSta;
	u8 au8Zero_Buff[ETH_ALEN] = {0};
	unsigned int i;
	u8 u8AssocNumb = 0;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	PRINT_D(HOSTINF_DBG, "Setting deauthenticating station message queue params\n");

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_DEL_ALL_STA;
	strHostIFmsg.drvHandler = hWFIDrv;

	/* Handling situation of deauthenticing all associated stations*/
	for (i = 0; i < MAX_NUM_STA; i++) {
		if (memcmp(pu8MacAddr[i], au8Zero_Buff, ETH_ALEN)) {
			memcpy(pstrDelAllStationMsg->au8Sta_DelAllSta[i],
			       pu8MacAddr[i], ETH_ALEN);
			PRINT_D(CFG80211_DBG, "BSSID = %x%x%x%x%x%x\n",
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][0],
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][1],
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][2],
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][3],
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][4],
				 pstrDelAllStationMsg->au8Sta_DelAllSta[i][5]);
			u8AssocNumb++;
		}
	}
	if (!u8AssocNumb) {
		PRINT_D(CFG80211_DBG, "NO ASSOCIATED STAS\n");
		return s32Error;
	}

	pstrDelAllStationMsg->u8Num_AssocSta = u8AssocNumb;
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));

	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	down(&hWaitResponse);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * Setting edit station params in message queue
 */
signed int host_int_edit_station(struct WFIDrvHandle *hWFIDrv,
				 struct WILC_AddStaParam *pstrStaParams)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct WILC_AddStaParam *pstrAddStationMsg = &strHostIFmsg.uniHostIFmsgBody.strAddStaParam;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	PRINT_D(HOSTINF_DBG, "Setting editing station message queue params\n");

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_EDIT_STATION;
	strHostIFmsg.drvHandler = hWFIDrv;

	memcpy(pstrAddStationMsg, pstrStaParams, sizeof(struct WILC_AddStaParam));
	if (pstrAddStationMsg->u8NumRates > 0) {
		pstrAddStationMsg->pu8Rates = kmalloc(pstrAddStationMsg->u8NumRates, GFP_ATOMIC);
		memcpy(pstrAddStationMsg->pu8Rates, pstrStaParams->pu8Rates,
		       pstrAddStationMsg->u8NumRates);
		WILC_NULLCHECK(s32Error, pstrAddStationMsg->pu8Rates);
	}

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
		}

	return s32Error;
}
#endif /*WILC_AP_EXTERNAL_MLME*/

signed int host_int_set_power_mgmt(struct WFIDrvHandle *hWFIDrv,
				   bool bIsEnabled, unsigned int u32Timeout)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIfPowerMgmtParam *pstrPowerMgmtParam = &strHostIFmsg.uniHostIFmsgBody.strPowerMgmtparam;
	/*if the two interface are connected and it is required to enable PS , neglect the request*/
	if(linux_wlan_get_num_conn_ifcs() == 2 && bIsEnabled)
	{
		return 0;
	}

	PRINT_D(HOSTINF_DBG, "\n\n>> Setting PS to %d <<\n\n", bIsEnabled);

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	PRINT_D(HOSTINF_DBG, "Setting Power management message queue params\n");

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_POWER_MGMT;
	strHostIFmsg.drvHandler = hWFIDrv;

	pstrPowerMgmtParam->bIsEnabled = bIsEnabled;
	pstrPowerMgmtParam->u32Timeout = u32Timeout;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_setup_multicast_filter(struct WFIDrvHandle *hWFIDrv,
					   bool bIsEnabled,
					   unsigned int u32count)
{
	signed int s32Error = WILC_SUCCESS;

	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIFSetMulti *pstrMulticastFilterParam = &strHostIFmsg.uniHostIFmsgBody.strHostIfSetMulti;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	PRINT_D(HOSTINF_DBG, "Setting Multicast Filter params\n");

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_MULTICAST_FILTER;
	strHostIFmsg.drvHandler = hWFIDrv;

	pstrMulticastFilterParam->bIsEnabled = bIsEnabled;
	pstrMulticastFilterParam->u32count = u32count;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

#ifdef WILC_PARSE_SCAN_IN_HOST
/*
 * Parse Needed Join Parameters and save it in a new JoinBssParam entry
 */
static void *host_int_ParseJoinBssParam(struct tstrNetworkInfo *ptstrNetworkInfo)
{
	struct tstrJoinBssParam *pNewJoinBssParam = NULL;
	u8 *pu8IEs;
	u16 u16IEsLen;
	u16 index = 0;
	u8 suppRatesNo = 0;
	u8 extSuppRatesNo;
	u16 jumpOffset;
	u8 pcipherCount;
	u8 authCount;
	u8 pcipherTotalCount = 0;
	u8 authTotalCount = 0;
	u8 i, j;

	pu8IEs = ptstrNetworkInfo->pu8IEs;
	u16IEsLen = ptstrNetworkInfo->u16IEsLen;

	pNewJoinBssParam = kmalloc(sizeof(struct tstrJoinBssParam), GFP_ATOMIC);
	if (pNewJoinBssParam != NULL) {
		memset(pNewJoinBssParam, 0, sizeof(struct tstrJoinBssParam));
		pNewJoinBssParam->dtim_period = ptstrNetworkInfo->u8DtimPeriod;
		pNewJoinBssParam->beacon_period = ptstrNetworkInfo->u16BeaconPeriod;
		pNewJoinBssParam->cap_info = ptstrNetworkInfo->u16CapInfo;
		memcpy(pNewJoinBssParam->au8bssid, ptstrNetworkInfo->au8bssid, 6);
		memcpy((u8 *)pNewJoinBssParam->ssid, ptstrNetworkInfo->au8ssid,
		       ptstrNetworkInfo->u8SsidLen + 1);
		pNewJoinBssParam->ssidLen = ptstrNetworkInfo->u8SsidLen;
		memset(pNewJoinBssParam->rsn_pcip_policy, 0xFF, 3);
		memset(pNewJoinBssParam->rsn_auth_policy, 0xFF, 3);

		/*parse supported rates:*/
		while (index < u16IEsLen) {
			/*supportedRates IE*/
			if (pu8IEs[index] == SUPP_RATES_IE) {
				suppRatesNo = pu8IEs[index + 1];
				pNewJoinBssParam->supp_rates[0] = suppRatesNo;
				index += 2;

				for (i = 0; i < suppRatesNo; i++)
					pNewJoinBssParam->supp_rates[i + 1] = pu8IEs[index + i];

				index += suppRatesNo;
				continue;
			/*Ext SupportedRates IE*/
			} else if (pu8IEs[index] == EXT_SUPP_RATES_IE) {
				/*checking if no of ext. supp and supp rates < max limit*/
				extSuppRatesNo = pu8IEs[index + 1];
				if (extSuppRatesNo > (MAX_RATES_SUPPORTED - suppRatesNo))
					pNewJoinBssParam->supp_rates[0] = MAX_RATES_SUPPORTED;
				else
					pNewJoinBssParam->supp_rates[0] += extSuppRatesNo;
				index += 2;
				for (i = 0; i < (pNewJoinBssParam->supp_rates[0] - suppRatesNo); i++)
					pNewJoinBssParam->supp_rates[suppRatesNo + i + 1] = pu8IEs[index + i];

				index += extSuppRatesNo;
				continue;
			/*HT Cap. IE*/
			} else if (pu8IEs[index] == HT_CAPABILITY_IE) {
				pNewJoinBssParam->ht_capable = 1;
				index += pu8IEs[index + 1] + 2;
				continue;
			} else if ((pu8IEs[index] == WMM_IE) && /* WMM Element ID */
				   (pu8IEs[index + 2] == 0x00) && (pu8IEs[index + 3] == 0x50) &&
				   (pu8IEs[index + 4] == 0xF2) && /* OUI */
				   (pu8IEs[index + 5] == 0x02) && /* OUI Type     */
				   ((pu8IEs[index + 6] == 0x00) || (pu8IEs[index + 6] == 0x01)) && /* OUI Sub Type */
				   (pu8IEs[index + 7] == 0x01)) {
				/* Presence of WMM Info/Param element indicates WMM capability */
				pNewJoinBssParam->wmm_cap = 1;

				/* Check if Bit 7 is set indicating U-APSD capability */
				if (pu8IEs[index + 8] & (1 << 7))
					pNewJoinBssParam->uapsd_cap = 1;
				index += pu8IEs[index + 1] + 2;
				continue;
			}
#ifdef WILC_P2P
			else if ((pu8IEs[index] == P2P_IE) && /* P2P Element ID */
				 (pu8IEs[index + 2] == 0x50) && (pu8IEs[index + 3] == 0x6f) &&
				 (pu8IEs[index + 4] == 0x9a) && /* OUI */
				 (pu8IEs[index + 5] == 0x09) && (pu8IEs[index + 6] == 0x0c)) { /* OUI Type     */
				u16 u16P2P_count;

				pNewJoinBssParam->tsf = ptstrNetworkInfo->u32Tsf;
				pNewJoinBssParam->u8NoaEnbaled = 1;
				pNewJoinBssParam->u8Index = pu8IEs[index + 9];

				/* Check if Bit 7 is set indicating Opss capability */
				if (pu8IEs[index + 10] & (1 << 7)) {
					pNewJoinBssParam->u8OppEnable = 1;
					pNewJoinBssParam->u8CtWindow = pu8IEs[index + 10];
				} else {
					pNewJoinBssParam->u8OppEnable = 0;
				}
				PRINT_D(GENERIC_DBG, "P2P Dump\n");
				for (i = 0; i < pu8IEs[index + 7]; i++)
					PRINT_D(GENERIC_DBG, " %x\n", pu8IEs[index + 9 + i]);

				pNewJoinBssParam->u8Count = pu8IEs[index + 11];
				u16P2P_count = index + 12;

				memcpy(pNewJoinBssParam->au8Duration, pu8IEs + u16P2P_count, 4);
				u16P2P_count += 4;

				memcpy(pNewJoinBssParam->au8Interval, pu8IEs + u16P2P_count, 4);
				u16P2P_count += 4;

				memcpy(pNewJoinBssParam->au8StartTime, pu8IEs + u16P2P_count, 4);

				index += pu8IEs[index + 1] + 2;
				continue;
			}
#endif /* WILC_P2P */
			else if ((pu8IEs[index] == RSN_IE) ||
				 ((pu8IEs[index] == WPA_IE) && (pu8IEs[index + 2] == 0x00) &&
				  (pu8IEs[index + 3] == 0x50) && (pu8IEs[index + 4] == 0xF2) &&
				  (pu8IEs[index + 5] == 0x01)))	{
				u16 rsnIndex = index;

				if (pu8IEs[rsnIndex] == RSN_IE)	{
					pNewJoinBssParam->mode_802_11i = 2;
				} else {
					if (pNewJoinBssParam->mode_802_11i == 0)
						pNewJoinBssParam->mode_802_11i = 1;
					rsnIndex += 4;
				}
				/*//skipping id, length, version(2B) and first 3 bytes of gcipher*/
				rsnIndex += 7;
				pNewJoinBssParam->rsn_grp_policy = pu8IEs[rsnIndex];
				rsnIndex++;
				/*initialize policies with invalid values*/

				jumpOffset = pu8IEs[rsnIndex] * 4;

				/*parsing pairwise cipher
				 *saving 3 pcipher max.
				 */
				pcipherCount = (pu8IEs[rsnIndex] > 3) ? 3 : pu8IEs[rsnIndex];
				/* jump 2 bytes of pcipher count*/
				rsnIndex += 2;

				for (i = pcipherTotalCount, j = 0; i < pcipherCount + pcipherTotalCount && i < 3; i++, j++)
					/*each count corresponds to 4 bytes, only last byte is saved*/
					pNewJoinBssParam->rsn_pcip_policy[i] = pu8IEs[rsnIndex + ((j + 1) * 4) - 1];
				pcipherTotalCount += pcipherCount;
				rsnIndex += jumpOffset;

				jumpOffset = pu8IEs[rsnIndex] * 4;

				/* parsing AKM suite (auth_policy)
				 * saving 3 auth policies max.
				 */
				authCount = (pu8IEs[rsnIndex] > 3) ? 3 : pu8IEs[rsnIndex];
				rsnIndex += 2;

				for (i = authTotalCount, j = 0; i < authTotalCount + authCount; i++, j++)
					pNewJoinBssParam->rsn_auth_policy[i] = pu8IEs[rsnIndex + ((j + 1) * 4) - 1];
				authTotalCount += authCount;
				rsnIndex += jumpOffset;
				/*pasring rsn cap. only if rsn IE*/
				if (pu8IEs[index] == RSN_IE) {
					pNewJoinBssParam->rsn_cap[0] = pu8IEs[rsnIndex];
					pNewJoinBssParam->rsn_cap[1] = pu8IEs[rsnIndex + 1];
					rsnIndex += 2;
				}
				pNewJoinBssParam->rsn_found = true;
				/* Skip ID,Length bytes and IE body*/
				index += pu8IEs[index + 1] + 2;
				continue;
			} else {
				/* Skip ID,Length bytes and IE body*/
				index += pu8IEs[index + 1] + 2;
			}
		}
	}

	return (void *)pNewJoinBssParam;
}

void host_int_freeJoinParams(void *pJoinParams)
{
	if ((struct tstrJoinBssParam *)pJoinParams != NULL)
		kfree((struct tstrJoinBssParam *)pJoinParams);
	else
		PRINT_ER("Unable to FREE null pointer\n");
}
#endif  /*WILC_PARSE_SCAN_IN_HOST*/

/*
 * Open a block Ack session with the given parameters
 */
static int host_int_addBASession(struct WFIDrvHandle *hWFIDrv, char *pBSSID,
				 char TID, short int BufferSize,
				 short int SessionTimeout, void *drvHandler)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIfBASessionInfo *pBASessionInfo = &strHostIFmsg.uniHostIFmsgBody.strHostIfBASessionInfo;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_ADD_BA_SESSION;

	memcpy(pBASessionInfo->au8Bssid, pBSSID, ETH_ALEN);
	pBASessionInfo->u8Ted = TID;
	pBASessionInfo->u16BufferSize = BufferSize;
	pBASessionInfo->u16SessionTimeout = SessionTimeout;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}

signed int host_int_delBASession(struct WFIDrvHandle *hWFIDrv, char *pBSSID,
				 char TID)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;
	struct tstrHostIfBASessionInfo *pBASessionInfo = &strHostIFmsg.uniHostIFmsgBody.strHostIfBASessionInfo;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_DEL_BA_SESSION;

	memcpy(pBASessionInfo->au8Bssid, pBSSID, ETH_ALEN);
	pBASessionInfo->u8Ted = TID;
	strHostIFmsg.drvHandler = hWFIDrv;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	down(&hWaitResponse);
	WILC_CATCH(s32Error){
	}

	return s32Error;
}

/*
 * setup IP in firmware
 */
signed int host_int_setup_ipaddress(struct WFIDrvHandle *hWFIDrv, u8 *u16ipadd,
				    u8 idx)
{
	return 0;
}

/*
 * Get IP from firmware
 */
signed int host_int_get_ipaddress(struct WFIDrvHandle *hWFIDrv, u8 *u16ipadd,
				  u8 idx)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv *pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if (pstrWFIDrv == NULL)
		WILC_ERRORREPORT(s32Error, WILC_INVALID_ARGUMENT);

	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	/* prepare the WiphyParams Message */
	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_IPADDRESS;

	strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.au8IPAddr = u16ipadd;
	strHostIFmsg.drvHandler = hWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIfSetIP.idx = idx;

	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
				    sizeof(struct tstrHostIFmsg));
	if (s32Error)
		WILC_ERRORREPORT(s32Error, s32Error);

	WILC_CATCH(s32Error){
	}

	return s32Error;
}



signed int host_int_set_tx_power(struct WFIDrvHandle *hWFIDrv, u8 tx_power)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if(pstrWFIDrv == NULL)
	{
		WILC_ERRORREPORT(s32Error,WILC_INVALID_ARGUMENT);
	}

	/* prepare the Key Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_TX_POWER;
	strHostIFmsg.uniHostIFmsgBody.strHostIFTxPwr.u8TxPwr = tx_power;
	strHostIFmsg.drvHandler=hWFIDrv;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, 
					sizeof(struct tstrHostIFmsg));
	if(s32Error)
		PRINT_ER(" Error in sending messagequeue: PMKID Info\n");

	WILC_CATCH(s32Error)
	{

	}

	return s32Error;
}

signed int  host_int_get_tx_power(struct WFIDrvHandle * hWFIDrv, u8 *tx_power)
{
	signed int s32Error = WILC_SUCCESS;	
	struct tstrHostIFmsg strHostIFmsg;

	
	/* prepare the Get RSSI Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_GET_TX_POWER;
	strHostIFmsg.drvHandler=hWFIDrv;
	strHostIFmsg.uniHostIFmsgBody.strHostIFGetTxPwr.u8TxPwr=tx_power;
	/* send the message */
	s32Error = 	WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					sizeof(struct tstrHostIFmsg));
	if(s32Error){
		PRINT_ER("Failed to send get host channel param's message queue ");
		return WILC_FAIL;
		}

	down(&hWaitResponse);	

	return s32Error;
}

s32 host_int_set_antenna(struct WFIDrvHandle * hWFIDrv, u8 antenna_mode)
{
	signed int s32Error = WILC_SUCCESS;	
	struct tstrHostIFmsg strHostIFmsg;
	
	/* prepare the Get RSSI Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId 	= HOST_IF_MSG_SET_ANTENNA_MODE;
	strHostIFmsg.uniHostIFmsgBody.strHostIFSetAnt.mode= antenna_mode;
#ifdef ANT_SWTCH_SNGL_GPIO_CTRL
	#if(((ANT_1_GPIO_NUM >= 17) && (ANT_1_GPIO_NUM <= 21)) ||(ANT_1_GPIO_NUM == 3) || (ANT_1_GPIO_NUM == 4))
			strHostIFmsg.uniHostIFmsgBody.strHostIFSetAnt.antenna1 = ANT_1_GPIO_NUM;
	#else
			return WILC_FAIL;
	#endif
#elif defined(ANT_SWTCH_DUAL_GPIO_CTRL)
	#if((((ANT_1_GPIO_NUM >= 17) && (ANT_1_GPIO_NUM <= 21)) ||(ANT_1_GPIO_NUM == 3) || (ANT_1_GPIO_NUM == 4))\
		&& (((ANT_2_GPIO_NUM >= 17) && (ANT_2_GPIO_NUM <= 21)) ||(ANT_2_GPIO_NUM == 3) || (ANT_2_GPIO_NUM == 4)))
			strHostIFmsg.uniHostIFmsgBody.strHostIFSetAnt.antenna1 = ANT_1_GPIO_NUM;
			strHostIFmsg.uniHostIFmsgBody.strHostIFSetAnt.antenna2 = ANT_2_GPIO_NUM;
	#else
			return WILC_FAIL;
	#endif
#endif
	strHostIFmsg.drvHandler	= hWFIDrv;
	/* send the message */
	s32Error = 	WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg, 
					sizeof(struct tstrHostIFmsg));
	if(s32Error){
		PRINT_ER("Failed to send get host channel param's message queue ");
		return WILC_FAIL;
	}	
	return s32Error;
}

signed int host_int_set_wowlan_trigger(struct WFIDrvHandle *hWFIDrv, u8 wowlan_trigger)
{
	signed int s32Error = WILC_SUCCESS;
	struct WILC_WFIDrv * pstrWFIDrv = (struct WILC_WFIDrv *)hWFIDrv;
	struct tstrHostIFmsg strHostIFmsg;

	if(pstrWFIDrv == NULL)
	{
		WILC_ERRORREPORT(s32Error,WILC_INVALID_ARGUMENT);
	}

	/* prepare the trigger Message */
	memset(&strHostIFmsg, 0, sizeof(struct tstrHostIFmsg));

	strHostIFmsg.u16MsgId = HOST_IF_MSG_SET_WOWLAN_TRIGGER;
	strHostIFmsg.uniHostIFmsgBody.strHostIFWowlanTrigger.u8WowlanTrigger = wowlan_trigger;
	strHostIFmsg.drvHandler=hWFIDrv;

	/* send the message */
	s32Error = WILC_MsgQueueSend(&gMsgQHostIF, &strHostIFmsg,
					sizeof(struct tstrHostIFmsg));
	if(s32Error)
		PRINT_ER(" Error in sending message queue: wowlan trigger\n");

	WILC_CATCH(s32Error)
	{

	}

	return s32Error;
}	

