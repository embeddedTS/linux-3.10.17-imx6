
/*!  
*  @file	coreconfigurator.h
*  @brief	
*  @author	
*  @sa		coreconfigurator.c 
*  @date	1 Mar 2012
*  @version	1.0
*/


#ifndef CORECONFIGURATOR_H
#define CORECONFIGURATOR_H

#include "wilc_oswrapper.h"
#include "wilc_wlan_if.h"
/*****************************************************************************/
/* Constants                                                                 */
/*****************************************************************************/
/* Number of WID Options Supported */
#define NUM_BASIC_SWITCHES      45
#define NUM_FHSS_SWITCHES        0

#define NUM_RSSI	5

#ifdef MAC_802_11N
#define NUM_11N_BASIC_SWITCHES  25
#define NUM_11N_HUT_SWITCHES    47
#else /* MAC_802_11N */
#define NUM_11N_BASIC_SWITCHES  0
#define NUM_11N_HUT_SWITCHES    0
#endif /* MAC_802_11N */

extern WILC_Uint16 g_num_total_switches;

#define MAC_HDR_LEN             24          /* No Address4 - non-ESS         */
#define MAX_SSID_LEN            33	
#define FCS_LEN                 4
#define TIME_STAMP_LEN          8
#define BEACON_INTERVAL_LEN     2
#define CAP_INFO_LEN            2
#define STATUS_CODE_LEN         2
#define AID_LEN                 2
#define IE_HDR_LEN       		2


/* Operating Mode: SET */
#define SET_CFG              0
/* Operating Mode: GET */
#define GET_CFG              1

#define MAX_PACKET_BUFF_SIZE 1596

#define MAX_STRING_LEN					256
#define MAX_SURVEY_RESULT_FRAG_SIZE MAX_STRING_LEN
#define SURVEY_RESULT_LENGTH		44
#define MAX_ASSOC_RESP_FRAME_SIZE MAX_STRING_LEN

#define STATUS_MSG_LEN            	12
#define MAC_CONNECTED			1
#define MAC_DISCONNECTED   		0



/*****************************************************************************/
/* Function Macros                                                           */
/*****************************************************************************/
#define MAKE_WORD16(lsb, msb) (((WILC_Uint16)(msb) << 8) & 0xFF00) | (lsb)
#define MAKE_WORD32(lsw, msw) (((WILC_Uint32)(msw) << 16) & 0xFFFF0000) | (lsw)


/*****************************************************************************/
/* Type Definitions                                                      								  */
/*****************************************************************************/

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
typedef enum
{
		SUCCESSFUL_STATUSCODE  	= 0,
              UNSPEC_FAIL            		   	= 1,
              UNSUP_CAP              			= 10,
              REASOC_NO_ASOC    	     		= 11,
              FAIL_OTHER             			= 12,
              UNSUPT_ALG             			= 13,
              AUTH_SEQ_FAIL          		= 14,
              CHLNG_FAIL             			= 15,
              AUTH_TIMEOUT           		= 16,
              AP_FULL                			= 17,
              UNSUP_RATE             			= 18,
              SHORT_PREAMBLE_UNSUP   	= 19,
              PBCC_UNSUP             			= 20,
              CHANNEL_AGIL_UNSUP     	= 21,
              SHORT_SLOT_UNSUP       		= 25,
              OFDM_DSSS_UNSUP        		= 26,
              CONNECT_STS_FORCE_16_BIT = 0xFFFF
} tenuConnectSts;

struct tstrWID
{    
    WILC_Uint16     u16WIDid;
    tenuWIDtype  enuWIDtype;
	WILC_Sint32    s32ValueSize;
    WILC_Sint8      *ps8WidVal;
    
};

typedef struct
{
	WILC_Uint8 u8Full;
	WILC_Uint8 u8Index;
	WILC_Sint8 as8RSSI[NUM_RSSI];
}tstrRSSI;
/* This structure is used to support parsing of the received 'N' message */
struct tstrNetworkInfo
{
	WILC_Sint8 s8rssi;
	WILC_Uint16 u16CapInfo;
	WILC_Uint8 au8ssid[MAX_SSID_LEN];
	WILC_Uint8 u8SsidLen;
	WILC_Uint8 au8bssid[6];
	WILC_Uint16 u16BeaconPeriod;
	WILC_Uint8 u8DtimPeriod;
	WILC_Uint8 u8channel;
	unsigned long u32TimeRcvdInScanCached; /* of type unsigned long to be accepted by the linux kernel macro time_after() */
	unsigned long u32TimeRcvdInScan;
	WILC_Bool bNewNetwork;
#ifdef AGING_ALG
	WILC_Uint8 u8Found;
#endif
#ifdef WILC_P2P
	WILC_Uint32 u32Tsf; /* time-stamp [Low only 32 bit] */
#endif
    	WILC_Uint8 *pu8IEs;
	WILC_Uint16 u16IEsLen;
	void* pJoinParams;
	tstrRSSI strRssi;
	WILC_Uint64 u64Tsf; /* time-stamp [Low and High 64 bit] */
};

/* This structure is used to support parsing of the received Association Response frame */
struct tstrConnectRespInfo
{	
	WILC_Uint16 u16capability;
	WILC_Uint16 u16ConnectStatus;
	WILC_Uint16 u16AssocID;
	WILC_Uint8 *pu8RespIEs;
	WILC_Uint16 u16RespIEsLen;
};


struct tstrConnectInfo
{
	WILC_Uint8 au8bssid[6];
	WILC_Uint8* pu8ReqIEs;
	size_t ReqIEsLen;
    	WILC_Uint8 *pu8RespIEs;
	WILC_Uint16 u16RespIEsLen;
	WILC_Uint16 u16ConnectStatus;
};



struct tstrDisconnectNotifInfo
{
	WILC_Uint16 u16reason;
	WILC_Uint8 * ie;
	size_t ie_len;
};

#ifndef CONNECT_DIRECT
typedef struct wid_site_survey_reslts
{
	WILC_Char	SSID[MAX_SSID_LEN];
	WILC_Uint8	BssType;
	WILC_Uint8   Channel;
	WILC_Uint8   SecurityStatus;
	WILC_Uint8   BSSID[6];
	WILC_Char	RxPower;
	WILC_Uint8   Reserved;

}wid_site_survey_reslts_s;
#endif

extern WILC_Sint32 CoreConfiguratorInit(void);
extern WILC_Sint32 CoreConfiguratorDeInit(void);

extern WILC_Sint32 SendConfigPkt(WILC_Uint8 u8Mode, struct tstrWID* pstrWIDs,
       WILC_Uint32 u32WIDsCount,WILC_Bool bRespRequired,WILC_Uint32 drvHandler);
extern WILC_Sint32 ParseNetworkInfo(WILC_Uint8* pu8MsgBuffer, struct tstrNetworkInfo** ppstrNetworkInfo);
extern WILC_Sint32 DeallocateNetworkInfo(struct tstrNetworkInfo* pstrNetworkInfo);

extern WILC_Sint32 ParseAssocRespInfo(WILC_Uint8* pu8Buffer, WILC_Uint32 u32BufferLen, 
									      struct tstrConnectRespInfo** ppstrConnectRespInfo);
extern WILC_Sint32 DeallocateAssocRespInfo(struct tstrConnectRespInfo* pstrConnectRespInfo);

#ifndef CONNECT_DIRECT
extern WILC_Sint32 ParseSurveyResults(WILC_Uint8 ppu8RcvdSiteSurveyResults[][MAX_SURVEY_RESULT_FRAG_SIZE],
									 wid_site_survey_reslts_s** ppstrSurveyResults,
									 WILC_Uint32* pu32SurveyResultsCount);
extern WILC_Sint32 DeallocateSurveyResults(wid_site_survey_reslts_s* pstrSurveyResults);
#endif

extern WILC_Sint32 SendRawPacket(WILC_Sint8* pspacket, WILC_Sint32 s32PacketLen);
extern void NetworkInfoReceived(WILC_Uint8* pu8Buffer,WILC_Uint32 u32Length);
void GnrlAsyncInfoReceived(WILC_Uint8* pu8Buffer, WILC_Uint32 u32Length);
void host_int_ScanCompleteReceived(WILC_Uint8 * pu8Buffer, WILC_Uint32 u32Length);

#endif
