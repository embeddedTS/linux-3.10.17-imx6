////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) Atmel Corporation.  All rights reserved.
//
// Module Name:  wilc_wlan.c
//
//
//////////////////////////////////////////////////////////////////////////////

#include "wilc_wlan_if.h"
#include "wilc_wlan.h"
#include "linux_wlan.h"
#define INLINE static __inline

/********************************************

	Global

********************************************/
extern unsigned int int_clrd;
extern wilc_hif_func_t hif_sdio;
extern wilc_hif_func_t hif_spi;
extern wilc_cfg_func_t mac_cfg;
extern void WILC_WFI_mgmt_rx(uint8_t *buff, uint32_t size);
int sdio_xfer_cnt(void);
uint32_t wilc_get_chipid(uint8_t update);
WILC_Uint16 Set_machw_change_vir_if(WILC_Bool bValue);

//static uint32_t vmm_table[WILC_VMM_TBL_SIZE];
//static uint32_t vmm_table_rbk[WILC_VMM_TBL_SIZE];

//static uint32_t vmm_table_rbk[WILC_VMM_TBL_SIZE];

#define AC_LINUX_PKTS_BUFFER_SIZE 1000
#define PRINTARRAY(X,Y)   /*do {int l;for(l=0;l<NQUEUES;l++) {printk("%s[%d]=%d ",X,l,Y[l]);}printk("\n"); }while(0);*/
#define PRINTVAR(X,Y)   /* do {printk("%s = %d\n",X,Y); }while(0); */


typedef struct{
	struct txq_entry_t *txq_head;
	struct txq_entry_t *txq_tail;
	uint16_t	count;
	uint8_t acm;
} txq_handle;
typedef enum {AC_VO_Q = 0, /* Mapped to AC_VO_Q */
              AC_VI_Q = 1, /* Mapped to AC_VI_Q */
              AC_BE_Q = 2, /* Mapped to AC_BE_Q */
              AC_BK_Q = 3  /* Mapped to AC_BK_Q */
} IP_PKT_PRIORITY_T;
typedef struct {
	int quit;

	/**
		input interface functions
	**/
	wilc_wlan_os_func_t os_func;
	wilc_wlan_io_func_t io_func;
	wilc_wlan_net_func_t net_func;
	wilc_wlan_indicate_func_t indicate_func;

	/**
		host interface functions
	**/
	wilc_hif_func_t hif_func;
	void *hif_lock;

	/**
		configuration interface functions
	**/
	wilc_cfg_func_t cif_func;
	int cfg_frame_in_use;
	wilc_cfg_frame_t cfg_frame;
	uint32_t cfg_frame_offset;
	int cfg_seq_no;
	void *cfg_wait;

	/**
		RX buffer
	**/
	#ifdef MEMORY_STATIC
	uint32_t rx_buffer_size;
	uint8_t *rx_buffer;
	uint32_t rx_buffer_offset;
	#endif
	/**
		TX buffer
	**/
	uint32_t tx_buffer_size;
	uint8_t *tx_buffer;
	uint32_t tx_buffer_offset;

	/**
		TX queue
	**/
	void *txq_lock;

	/*Added by Amr - BugID_4720*/
	void *txq_add_to_head_lock;
	void *txq_spinlock;
	unsigned long txq_spinlock_flags;

	txq_handle txq[NQUEUES];
	
	int txq_entries;
	void *txq_wait;
	int txq_exit;

	/**
		RX queue
	**/
	void *rxq_lock;
	struct rxq_entry_t *rxq_head;
	struct rxq_entry_t *rxq_tail;
	int rxq_entries;
	void *rxq_wait;
	int rxq_exit;


} wilc_wlan_dev_t;

static wilc_wlan_dev_t g_wlan;

void chip_allow_sleep(void);
#ifdef WILC_OPTIMIZE_SLEEP_INT
void chip_wakeup(void);
#else
INLINE void chip_wakeup(void);

#endif
/********************************************

	Debug

********************************************/

static uint32_t dbgflag = N_INIT|N_ERR|N_INTR|N_TXQ|N_RXQ;

static void wilc_debug(uint32_t flag, char *fmt, ...)
{
	char buf[256];
	va_list args;
	int len;

	if (flag & dbgflag) {
		va_start(args, fmt);
		len = vsprintf(buf, fmt, args);
		va_end(args);

		if (g_wlan.os_func.os_debug)
			g_wlan.os_func.os_debug(buf);
	}

	return;
}

static CHIP_PS_STATE_T genuChipPSstate = CHIP_WAKEDUP;

/*BugID_5213*/
/*acquire_bus() and release_bus() are made INLINE functions*/
/*as a temporary workaround to fix a problem of receiving*/
/*unknown interrupt from FW*/
INLINE void acquire_bus(BUS_ACQUIRE_T acquire)
{

	g_wlan.os_func.os_enter_cs(g_wlan.hif_lock);
	#ifndef WILC_OPTIMIZE_SLEEP_INT
		if(genuChipPSstate != CHIP_WAKEDUP)
	#endif
		{
			if(acquire == ACQUIRE_AND_WAKEUP)
				chip_wakeup();
		}

}
INLINE void release_bus(BUS_RELEASE_T release)
{
	#ifdef WILC_OPTIMIZE_SLEEP_INT
		if(release == RELEASE_ALLOW_SLEEP)
			chip_allow_sleep();
	#endif
	g_wlan.os_func.os_leave_cs(g_wlan.hif_lock);
}
/********************************************

	Queue

********************************************/

static void wilc_wlan_txq_remove(uint8_t q_num, struct txq_entry_t *tqe)
{

	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	//unsigned long flags;
	//p->os_func.os_spin_lock(p->txq_spinlock, &flags);
	if (tqe==p->txq[q_num].txq_head) 
	{

		p->txq[q_num].txq_head = tqe->next;
		if(p->txq[q_num].txq_head)
		{
			p->txq[q_num].txq_head->prev=NULL;
		}


	}
	else if(tqe==p->txq[q_num].txq_tail)
	{
		p->txq[q_num].txq_tail=(tqe->prev);
		if(p->txq[q_num].txq_tail)
		{
			p->txq[q_num].txq_tail->next=NULL;
		}
	}else
	{
		tqe->prev->next=tqe->next;
		tqe->next->prev=tqe->prev;

	}
	p->txq_entries-=1;
	p->txq[q_num].count--;
	//p->os_func.os_spin_unlock(p->txq_spinlock, &flags);

}

static struct txq_entry_t *wilc_wlan_txq_remove_from_head(uint8_t q_num)
{
	struct txq_entry_t * tqe;
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);
	if (p->txq[q_num].txq_head) 
	{
		//p->os_func.os_enter_cs(p->txq_lock);
		tqe = p->txq[q_num].txq_head;
		p->txq[q_num].txq_head = tqe->next;
		if(p->txq[q_num].txq_head)
		{
			p->txq[q_num].txq_head->prev=NULL;
		}
		p->txq_entries-=1;
		p->txq[q_num].count--;
		/*Added by Amr - BugID_4720*/


		//p->os_func.os_leave_cs(p->txq_lock);

	}
	else
	{
		tqe = NULL;
	}
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);
	return tqe;
}

static void wilc_wlan_txq_add_to_tail(uint8_t q_num, struct txq_entry_t *tqe)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
		unsigned long flags;
	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);

//	p->os_func.os_enter_cs(p->txq_lock);
	if (p->txq[q_num].txq_head == NULL) 
	{
		tqe->next = NULL;
		tqe->prev= NULL;
		p->txq[q_num].txq_head = tqe;
		p->txq[q_num].txq_tail = tqe;
		//p->os_func.os_signal(p->txq_wait);
	} else {
		tqe->next = NULL;
		tqe->prev=p->txq[q_num].txq_tail;
		p->txq[q_num].txq_tail->next = tqe;
		p->txq[q_num].txq_tail = tqe;
	}
	p->txq_entries+=1;
	p->txq[q_num].count++;
	PRINT_D(TX_DBG,"Number of entries in TxQ = %d\n",p->txq_entries);
//	p->os_func.os_leave_cs(p->txq_lock);

	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);

	/**
		wake up TX queue
	**/
	PRINT_D(TX_DBG,"Wake the txq_handling\n");

	p->os_func.os_signal(p->txq_wait);


}

static int wilc_wlan_txq_add_to_head(uint8_t q_num, struct txq_entry_t *tqe)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	/*Added by Amr - BugID_4720*/
	if(p->os_func.os_wait(p->txq_add_to_head_lock, CFG_PKTS_TIMEOUT))
		return -1;

	p->os_func.os_spin_lock(p->txq_spinlock, &flags);

	//p->os_func.os_enter_cs(p->txq_lock);
	if (p->txq[q_num].txq_head == NULL) {
		tqe->next = NULL;
		tqe->prev= NULL;
		p->txq[q_num].txq_head=tqe;
		p->txq[q_num].txq_tail = tqe;
	} else {
		tqe->next = p->txq[q_num].txq_head;
		tqe->prev= NULL;
		p->txq[q_num].txq_head->prev=tqe;
		p->txq[q_num].txq_head = tqe;
	}
	p->txq_entries+=1;
	p->txq[q_num].count++;
	PRINT_D(TX_DBG,"Number of entries in TxQ = %d\n",p->txq_entries);
	//p->os_func.os_leave_cs(p->txq_lock);

	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);
	p->os_func.os_signal(p->txq_add_to_head_lock);


	/**
		wake up TX queue
	**/
	p->os_func.os_signal(p->txq_wait);
	PRINT_D(TX_DBG,"Wake up the txq_handler\n");
//	complete(p->txq_wait);

	/*Added by Amr - BugID_4720*/
	return 0;

}

uint32_t Statisitcs_totalAcks=0,Statisitcs_DroppedAcks=0;
static uint8_t inline ac_classify(struct txq_entry_t * tqe);
static inline uint8_t change_ac_if_needed(uint8_t* ac);
#ifdef	TCP_ACK_FILTER
struct Ack_session_info;
typedef struct Ack_session_info
{
	uint32_t Ack_seq_num;
	uint32_t Bigger_Ack_num;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t status;
	//struct Ack_session_info * next;
	//struct Ack_session_info * prev;
} Ack_session_info_t;

typedef struct {
	uint32_t ack_num;
	//uint32_t seq_num;
	//uint16_t src_port;
	//uint16_t dst_port;
	//uint32_t dst_ip_addr;
	uint32_t Session_index;
	struct txq_entry_t  * txqe;
	//Ack_session_info * Ack_session;
} Pending_Acks_info_t/*Ack_info_t*/;




struct Ack_session_info * Free_head=NULL;
struct Ack_session_info * Alloc_head=NULL;

#define TCP_FIN_MASK 		(1<<0)
#define TCP_SYN_MASK 		(1<<1)
#define TCP_Ack_MASK 		(1<<4)
#define NOT_TCP_ACK			(-1)

#define MAX_TCP_SESSION		25
#define MAX_PENDING_ACKS	256
Ack_session_info_t 	Acks_keep_track_info[2*MAX_TCP_SESSION];
Pending_Acks_info_t 	Pending_Acks_info[MAX_PENDING_ACKS];

uint32_t PendingAcks_arrBase=0;
uint32_t Opened_TCP_session=0;
uint32_t Pending_Acks=0;



static int inline Init_TCP_tracking(void)
{

	/*uint32_t i;
	Free_head=&Acks_keep_track_info[0];
	 i=1;
	 Acks_keep_track_info[0].next=&Acks_keep_track_info[1];
	for(i=1<;i<MAX_TCP_SESSION-1;i++)
	{
		Acks_keep_track_info[i].next=&Acks_keep_track_info[i+1];
		Acks_keep_track_info[i].prev=&Acks_keep_track_info[i-1];
	}
	Acks_keep_track_info[49].prev=&Acks_keep_track_info[48];
	*/
	return 0;

}
static int inline add_TCP_track_session(uint32_t src_prt,uint32_t dst_prt,uint32_t seq)
{
	if(Opened_TCP_session < 2*MAX_TCP_SESSION)
	{
		Acks_keep_track_info[Opened_TCP_session].Ack_seq_num=seq;
		Acks_keep_track_info[Opened_TCP_session].Bigger_Ack_num=0;
		Acks_keep_track_info[Opened_TCP_session].src_port=src_prt;
		Acks_keep_track_info[Opened_TCP_session].dst_port=dst_prt;
		Opened_TCP_session++;
	
		PRINT_D(TCP_ENH,"TCP Session %d to Ack %d\n",Opened_TCP_session,seq);
	}
	return 0;
}

static int inline Update_TCP_track_session(uint32_t index,uint32_t Ack)
{
	if(index < 2*MAX_TCP_SESSION)
	{
		if(Ack>Acks_keep_track_info[index].Bigger_Ack_num)
		{
			Acks_keep_track_info[index].Bigger_Ack_num=Ack;
		}
	}
	return 0;

}
static int inline add_TCP_Pending_Ack(uint32_t Ack,uint32_t Session_index,struct txq_entry_t  * txqe)
{
	Statisitcs_totalAcks++;
	if((PendingAcks_arrBase+Pending_Acks)<MAX_PENDING_ACKS)
	{
		Pending_Acks_info[PendingAcks_arrBase+Pending_Acks].ack_num=Ack;
		Pending_Acks_info[PendingAcks_arrBase+Pending_Acks].txqe=txqe;
		Pending_Acks_info[PendingAcks_arrBase+Pending_Acks].Session_index=Session_index;
		txqe->tcp_PendingAck_index=PendingAcks_arrBase+Pending_Acks;
		Pending_Acks++;

	}
	else
	{

	}
	return 0;
}
static int inline remove_TCP_related(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);

	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);
	return 0;
}

static int inline tcp_process(struct txq_entry_t * tqe)
{
	int ret;
	uint8_t *eth_hdr_ptr;
	uint8_t * buffer=tqe->buffer;
	unsigned short h_proto;
	int i;
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);

	eth_hdr_ptr = &buffer[0];
	h_proto = ntohs(*((unsigned short*)&eth_hdr_ptr[12]));
	if(h_proto == 0x0800) { /* IP */
		uint8_t * ip_hdr_ptr;
		uint8_t protocol;

		ip_hdr_ptr = &buffer[ETHERNET_HDR_LEN];
		protocol = ip_hdr_ptr[9];


		if(protocol == 0x06) {
			uint8_t * tcp_hdr_ptr;
			uint32_t IHL,Total_Length,Data_offset;
			tcp_hdr_ptr = &ip_hdr_ptr[IP_HDR_LEN];
			IHL=(ip_hdr_ptr[0]&0xf)<<2;
			Total_Length=(((uint32_t)ip_hdr_ptr[2])<<8)+((uint32_t)ip_hdr_ptr[3]);
			Data_offset=(((uint32_t)tcp_hdr_ptr[12]&0xf0)>>2);
			if(Total_Length==(IHL+Data_offset)) /*we want to recognize the clear Acks(packet only carry Ack infos not with data) so data size must be equal zero*/
			{
				uint32_t seq_no,Ack_no;
				seq_no	=(((uint32_t)tcp_hdr_ptr[4])<<24)+(((uint32_t)tcp_hdr_ptr[5])<<16)+(((uint32_t)tcp_hdr_ptr[6])<<8)+((uint32_t)tcp_hdr_ptr[7]);

				Ack_no	=(((uint32_t)tcp_hdr_ptr[8])<<24)+(((uint32_t)tcp_hdr_ptr[9])<<16)+(((uint32_t)tcp_hdr_ptr[10])<<8)+((uint32_t)tcp_hdr_ptr[11]);


				for(i=0;i<Opened_TCP_session;i++)
				{
					if(i < 2* MAX_TCP_SESSION && Acks_keep_track_info[i].Ack_seq_num == seq_no)
					{
						Update_TCP_track_session(i,Ack_no);
						break;
					}
				}
				if(i==Opened_TCP_session)
				{
					add_TCP_track_session( 0,  0,  seq_no);
				}
				add_TCP_Pending_Ack(Ack_no,i,tqe);


			}

		} else {
			ret = 0;
		}
	} else {
		ret = 0;
	}
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);
	return ret;
}


static int wilc_wlan_txq_filter_dup_tcp_ack(void)
{

	uint32_t i=0;
	uint32_t Dropped=0;
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;

	p->os_func.os_spin_lock(p->txq_spinlock, &p->txq_spinlock_flags);
	for(i=PendingAcks_arrBase;i<(PendingAcks_arrBase+Pending_Acks);i++) {
		if(i >= MAX_PENDING_ACKS || Pending_Acks_info[i].Session_index >= 2*MAX_TCP_SESSION)
		{
			break;
		}
		if(Pending_Acks_info[i].ack_num < Acks_keep_track_info[Pending_Acks_info[i].Session_index].Bigger_Ack_num) {
			struct txq_entry_t *tqe;
			PRINT_D(TCP_ENH, "DROP ACK: %u \n", Pending_Acks_info[i].ack_num);
			tqe = Pending_Acks_info[i].txqe;
			if(tqe)
			{
				wilc_wlan_txq_remove(tqe->q_num, tqe);
				Statisitcs_DroppedAcks++;
				tqe->status = 1;				/* mark the packet send */
				if (tqe->tx_complete_func) tqe->tx_complete_func(tqe->priv, tqe->status);
				p->os_func.os_free(tqe);
				Dropped++;
				//p->txq_entries -= 1;
			}
		}
	}
	Pending_Acks=0;
	Opened_TCP_session=0;

	if(PendingAcks_arrBase==0)
	{
		PendingAcks_arrBase=MAX_TCP_SESSION;
	}else
	{
		PendingAcks_arrBase=0;
	}


	p->os_func.os_spin_unlock(p->txq_spinlock, &p->txq_spinlock_flags);

	while(Dropped>0)
	{
		/*consume the semaphore count of the removed packet*/
		p->os_func.os_wait(p->txq_wait,1);
		Dropped--;
	}

	return 1;
}
#endif

#ifdef TCP_ENHANCEMENTS
WILC_Bool EnableTCPAckFilter = WILC_FALSE;

void Enable_TCP_ACK_Filter(WILC_Bool value)
{
	EnableTCPAckFilter = value;
}

WILC_Bool is_TCP_ACK_Filter_Enabled(void)
{
	return EnableTCPAckFilter;
}
#endif

static int wilc_wlan_txq_add_cfg_pkt(uint8_t *buffer, uint32_t buffer_size)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;

	PRINT_D(TX_DBG,"Adding config packet ...\n");
	if (p->quit){
		PRINT_D(TX_DBG,"Return due to clear function\n");
		p->os_func.os_signal(p->cfg_wait);
		return 0;
		}

	tqe = (struct txq_entry_t *)p->os_func.os_malloc_atomic(sizeof(struct txq_entry_t));
	if (tqe == NULL){
		PRINT_ER("Failed to allocate memory\n");
		return 0;
		}

	tqe->type = WILC_CFG_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = NULL;
	tqe->priv = NULL;
	tqe->q_num = AC_VO_Q;
#ifdef TCP_ACK_FILTER
	tqe->tcp_PendingAck_index=NOT_TCP_ACK;
#endif
	/**
		Configuration packet always at the front
	**/
	PRINT_D(TX_DBG,"Adding the config packet at the Queue tail\n");

	/*Edited by Amr - BugID_4720*/
	if(wilc_wlan_txq_add_to_head(AC_VO_Q, tqe))
		return 0;
	//wilc_wlan_txq_add_to_tail(tqe);
	return 1;
}

static void inline calculate_ac_q_limit(uint8_t ac, uint16_t* q_limit)
{
	static bool is_ac_linux_pkts_arrays_initialized = 0;
	static uint8_t ac_linux_pkts_buffer[AC_LINUX_PKTS_BUFFER_SIZE];
	static uint16_t ac_linux_pkts_weighted_cnt[NQUEUES];
	uint8_t ac_factors[NQUEUES] = {1, 1, 1, 1};
	static uint16_t ac_linux_pkts_weighted_sum = 0;
	uint16_t i;
	static uint16_t end_index;

	if (!is_ac_linux_pkts_arrays_initialized) {
		for (i = 0; i < AC_LINUX_PKTS_BUFFER_SIZE; i++) {
			ac_linux_pkts_buffer[i] = i % NQUEUES;
		}
		for (i = 0; i < NQUEUES; i++) {
			ac_linux_pkts_weighted_cnt[i] = AC_LINUX_PKTS_BUFFER_SIZE * ac_factors[i] / NQUEUES;
			ac_linux_pkts_weighted_sum += ac_linux_pkts_weighted_cnt[i];
		}
		end_index = AC_LINUX_PKTS_BUFFER_SIZE - 1;
		is_ac_linux_pkts_arrays_initialized = 1;
	}

	ac_linux_pkts_weighted_cnt[ac_linux_pkts_buffer[end_index]] -= ac_factors[ac_linux_pkts_buffer[end_index]];
	ac_linux_pkts_weighted_cnt[ac] += ac_factors[ac];
	ac_linux_pkts_weighted_sum += (ac_factors[ac] - ac_factors[ac_linux_pkts_buffer[end_index]]);
	
	ac_linux_pkts_buffer[end_index] = ac;
	if (end_index > 0)
		end_index--;
	else
		end_index = AC_LINUX_PKTS_BUFFER_SIZE - 1;
		
	for (i = 0; i < NQUEUES; i++)
		q_limit[i] = (ac_linux_pkts_weighted_cnt[i] * FLOW_CONTROL_UPPER_THRESHOLD / ac_linux_pkts_weighted_sum) + 1;

	return;
}

static int wilc_wlan_txq_add_net_pkt(void *priv, uint8_t *buffer, uint32_t buffer_size, wilc_tx_complete_func_t func)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;
	uint8_t q_num;
	uint16_t q_limit[NQUEUES] = {0, 0, 0, 0};

	if (p->quit)
		return 0;

	tqe = (struct txq_entry_t *)p->os_func.os_malloc_atomic(sizeof(struct txq_entry_t));

	if (tqe == NULL)
		return 0;
	tqe->type = WILC_NET_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = func;
	tqe->priv = priv;
	q_num = ac_classify(tqe);
	if(change_ac_if_needed(&q_num))
	{
		PRINT_D(GENERIC_DBG, "No suitable non-ACM queue\n");
		return 0;
	}
	calculate_ac_q_limit(q_num, q_limit);
	
	if ((q_num == AC_VO_Q && p->txq[q_num].count <= q_limit[AC_VO_Q]) || 
		(q_num == AC_VI_Q && p->txq[q_num].count <= q_limit[AC_VI_Q]) || 
		(q_num == AC_BE_Q && p->txq[q_num].count <= q_limit[AC_BE_Q]) || 
		(q_num == AC_BK_Q && p->txq[q_num].count <= q_limit[AC_BK_Q])) {
		PRINT_D(TX_DBG,"Adding mgmt packet at the Queue tail\n");
#ifdef TCP_ACK_FILTER
		tqe->tcp_PendingAck_index=NOT_TCP_ACK;
#ifdef TCP_ENHANCEMENTS
		if (is_TCP_ACK_Filter_Enabled() == WILC_TRUE)
#endif
		tcp_process(tqe);
#endif
		wilc_wlan_txq_add_to_tail(q_num, tqe);
	} else {
		//printk("discard ... q = %d, cnt = %d, entries = %d\n", q_num, p->txq[q_num].count, p->txq_entries);
		tqe->status = 0;				/* mark the packet failed to send  */
		if (tqe->tx_complete_func)  /* free buffer */
			tqe->tx_complete_func(tqe->priv, tqe->status);
		p->os_func.os_free(tqe);
	}
	return p->txq_entries;
}
/*Bug3959: transmitting mgmt frames received from host*/
#if defined(WILC_AP_EXTERNAL_MLME) || defined(WILC_P2P)
int wilc_wlan_txq_add_mgmt_pkt(void *priv, uint8_t *buffer, uint32_t buffer_size, wilc_tx_complete_func_t func)
{

	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;

	if (p->quit)
		return 0;

	tqe = (struct txq_entry_t *)p->os_func.os_malloc_atomic(sizeof(struct txq_entry_t));

	if (tqe == NULL)
		return 0;
	tqe->type = WILC_MGMT_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = func;
	tqe->priv = priv;
	tqe->q_num = AC_BE_Q;
#ifdef TCP_ACK_FILTER
	tqe->tcp_PendingAck_index=NOT_TCP_ACK;
#endif
	PRINT_D(TX_DBG,"Adding Network packet at the Queue tail\n");
	wilc_wlan_txq_add_to_tail(AC_BE_Q, tqe);
	return 1;
}

#ifdef WILC_FULLY_HOSTING_AP
int wilc_FH_wlan_txq_add_net_pkt(void *priv, uint8_t *buffer, uint32_t buffer_size, wilc_tx_complete_func_t func)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;

	if (p->quit)
		return 0;

	tqe = (struct txq_entry_t *)p->os_func.os_malloc_atomic(sizeof(struct txq_entry_t));

	if (tqe == NULL)
		return 0;
	tqe->type = WILC_FH_DATA_PKT;
	tqe->buffer = buffer;
	tqe->buffer_size = buffer_size;
	tqe->tx_complete_func = func;
	tqe->priv = priv;
	PRINT_D(TX_DBG,"Adding mgmt packet at the Queue tail\n");
	tqe->q_num = AC_BE_Q;
	wilc_wlan_txq_add_to_tail(AC_BE_Q, tqe);
	/*return number of itemes in the queue*/
	return p->txq_entries;
}
#endif	/* WILC_FULLY_HOSTING_AP*/
#endif /*WILC_AP_EXTERNAL_MLME*/
static struct txq_entry_t *wilc_wlan_txq_get_first(uint8_t q_num)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;
	unsigned long flags;

	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);

	//p->os_func.os_enter_cs(p->txq_lock);
	tqe = p->txq[q_num].txq_head;

	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);

	//p->os_func.os_leave_cs(p->txq_lock);

	return tqe;
}

static struct txq_entry_t *wilc_wlan_txq_get_next(struct txq_entry_t *tqe)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_lock(p->txq_spinlock,&flags);

	//p->os_func.os_enter_cs(p->txq_lock);
	tqe = tqe->next;

	/*Added by Amr - BugID_4720*/
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);

	//p->os_func.os_leave_cs(p->txq_lock);

	return tqe;
}

static int wilc_wlan_rxq_add(struct rxq_entry_t *rqe)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;

	if (p->quit)
		return 0;

	p->os_func.os_enter_cs(p->rxq_lock);
	if (p->rxq_head == NULL) {
		PRINT_D(RX_DBG,"Add to Queue head\n");
		rqe->next = NULL;
		p->rxq_head = rqe;
		p->rxq_tail = rqe;
	} else {
		PRINT_D(RX_DBG,"Add to Queue tail\n");
		p->rxq_tail->next = rqe;
		rqe->next = NULL;
		p->rxq_tail = rqe;
	}
	p->rxq_entries+=1;
	PRINT_D(RX_DBG,"Number of queue entries: %d\n",p->rxq_entries);
	p->os_func.os_leave_cs(p->rxq_lock);
	return p->rxq_entries;
}

static struct rxq_entry_t *wilc_wlan_rxq_remove(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;

	PRINT_D(RX_DBG,"Getting rxQ element\n");
	if (p->rxq_head) {
		struct rxq_entry_t *rqe;

		p->os_func.os_enter_cs(p->rxq_lock);
		rqe = p->rxq_head;
		p->rxq_head = p->rxq_head->next;
		p->rxq_entries-=1;
		PRINT_D(RX_DBG,"RXQ entries decreased\n");
		p->os_func.os_leave_cs(p->rxq_lock);
		return rqe;
	}
	PRINT_D(RX_DBG,"Nothing to get from Q\n");
	return NULL;
}


/********************************************

	Power Save handle functions

********************************************/



#ifdef WILC_OPTIMIZE_SLEEP_INT

void chip_allow_sleep(void)
{
	uint32_t reg = 0;

	/* Clear bit 1 */
	g_wlan.hif_func.hif_read_reg(WILC_WAKEUP_REG , &reg);

	g_wlan.hif_func.hif_write_reg(WILC_WAKEUP_REG , reg & ~(WILC_WAKEUP_BIT));
	g_wlan.hif_func.hif_write_reg(WILC_FROM_INTERFACE_TO_WF_REG , 0);
}

void chip_wakeup(void)
{
	uint32_t reg , clk_status_reg; 
	uint32_t trials = 0; 
	uint32_t val32;
	
	g_wlan.hif_func.hif_write_reg(WILC_FROM_INTERFACE_TO_WF_REG , 1);
	udelay(200);
	g_wlan.hif_func.hif_read_reg(WILC_WAKEUP_REG , &reg);
	do
	{
		/* Set bit 1 */
		g_wlan.hif_func.hif_write_reg(WILC_WAKEUP_REG , reg | (WILC_WAKEUP_BIT));

		// Check the clock status
		g_wlan.hif_func.hif_read_reg(WILC_CLK_STATUS_REG , &clk_status_reg);

		// in case of clocks off, wait 2ms, and check it again.
		// if still off, wait for another 2ms, for a total wait of 6ms.
		// If still off, redo the wake up sequence
		while( ((clk_status_reg & (WILC_CLK_STATUS_BIT)) == 0) && ((trials%3) != 0))
		{
			/* Wait for the chip to stabilize*/
			WILC_Sleep(2);

			// Make sure chip is awake. This is an extra step that can be removed
			// later to avoid the bus access overhead
			g_wlan.hif_func.hif_read_reg(WILC_CLK_STATUS_REG , &clk_status_reg);
			if((clk_status_reg & (WILC_CLK_STATUS_BIT)) == 0)
			{
				wilc_debug(N_ERR, "clocks still OFF. Wake up failed\n");
			}
			
			trials++;
		}
		
		// in case of failure, Reset the wakeup bit to introduce a new edge on the next loop
		if((clk_status_reg & (WILC_CLK_STATUS_BIT)) == 0)
		{
			// Reset bit 0
			g_wlan.hif_func.hif_write_reg(WILC_WAKEUP_REG , reg & (~ (WILC_WAKEUP_BIT)));
		}
	}while((clk_status_reg & (WILC_CLK_STATUS_BIT)) == 0);

	if(genuChipPSstate == CHIP_SLEEPING_MANUAL)
	{
		if(wilc_get_chipid(WILC_FALSE) < 0x1002b0)
		{
			/* Enable PALDO back right after wakeup */
			g_wlan.hif_func.hif_read_reg(0x1e1c , &val32);
			val32 |= (1 << 6);
			g_wlan.hif_func.hif_write_reg(0x1e1c , val32);

			g_wlan.hif_func.hif_read_reg(0x1e9c , &val32);
			val32 |= (1 << 6);
			g_wlan.hif_func.hif_write_reg(0x1e9c , val32);
		}
	}
	genuChipPSstate = CHIP_WAKEDUP;
}
#else
INLINE void chip_wakeup(void)
{
	uint32_t reg, trials=0;
	do
	{
		if ((g_wlan.io_func.io_type & 0x1) == HIF_SPI)
		{
			g_wlan.hif_func.hif_read_reg(1, &reg) ;
			/* Make sure bit 1 is 0 before we start. */
			g_wlan.hif_func.hif_write_reg(1, reg & ~(1 << 1));
			/* Set bit 1 */
			 g_wlan.hif_func.hif_write_reg(1, reg | (1 << 1)) ;
			/* Clear bit 1*/
			 g_wlan.hif_func.hif_write_reg(1, reg  & ~(1 << 1));
		}
		else if ((g_wlan.io_func.io_type & 0x1) == HIF_SDIO)
		{
			/* Make sure bit 0 is 0 before we start. */
			 g_wlan.hif_func.hif_read_reg(0xf0, &reg);
			 g_wlan.hif_func.hif_write_reg(0xf0, reg & ~(1 << 0));
			/* Set bit 1 */
			 g_wlan.hif_func.hif_write_reg(0xf0, reg | (1 << 0));
			/* Clear bit 1 */
			 g_wlan.hif_func.hif_write_reg(0xf0, reg  & ~(1 << 0));
		}

		do
		{
			/* Wait for the chip to stabilize*/
//			WILC_Sleep(2);
			mdelay(3);

			// Make sure chip is awake. This is an extra step that can be removed
			// later to avoid the bus access overhead
			if((wilc_get_chipid(WILC_TRUE) == 0))
			{
				wilc_debug(N_ERR, "Couldn't read chip id. Wake up failed\n");
			}
		}while((wilc_get_chipid(WILC_TRUE) == 0) && ((++trials %3) == 0));

	}while(wilc_get_chipid(WILC_TRUE) == 0);

	genuChipPSstate = CHIP_WAKEDUP;
}
#endif
void chip_sleep_manually(WILC_Uint32 u32SleepTime)
{
	uint32_t val32;

	if(genuChipPSstate != CHIP_WAKEDUP)
	{
		/* chip is already sleeping. Do nothing */
		return;
	}
	acquire_bus(ACQUIRE_ONLY);

#ifdef WILC_OPTIMIZE_SLEEP_INT
	chip_allow_sleep();
#endif

	/* Trigger the manual sleep interrupt */
	g_wlan.hif_func.hif_write_reg(0x10a8, 1);

	genuChipPSstate = CHIP_SLEEPING_MANUAL;
	release_bus(RELEASE_ONLY);
}

void host_wakeup_notify(void)
{
	acquire_bus(ACQUIRE_ONLY);
	g_wlan.hif_func.hif_write_reg(0x10b0, 1);
	release_bus(RELEASE_ONLY);
}

void host_sleep_notify(void)
{
	acquire_bus(ACQUIRE_ONLY);
	g_wlan.hif_func.hif_write_reg(0x10ac, 1);
	release_bus(RELEASE_ONLY);
}

/********************************************

	Tx, Rx queue handle functions

********************************************/
static uint8_t inline ac_classify(struct txq_entry_t * tqe)
{
	uint8_t *eth_hdr_ptr;
	uint8_t * buffer=tqe->buffer;
	unsigned short h_proto;
	uint8_t ac;
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	unsigned long flags;
	p->os_func.os_spin_lock(p->txq_spinlock, &flags);
	eth_hdr_ptr = &buffer[0];
	h_proto = ntohs(*((unsigned short*)&eth_hdr_ptr[12]));
	if(h_proto == 0x0800) 
	{ /* IP */
		uint8_t * ip_hdr_ptr;
		uint8_t protocol;
		uint8_t * tcp_hdr_ptr;
		uint32_t IHL,DSCP ;
		ip_hdr_ptr = &buffer[ETHERNET_HDR_LEN];
		IHL=(ip_hdr_ptr[0]&0xf)<<2;
		DSCP=(ip_hdr_ptr[1]&0xfc);
		switch (DSCP)
		{
			case 0x20:             /* IP-PL1 */
			case 0x40:             /* IP-PL2 */
			case 0x08:
			{
				ac = AC_BK_Q; /* background */
			}
			break;
			case 0x80:           /* IP-PL4 */
			case 0xA0:           /* IP-PL5 */
			case 0x28:           /* AF11-PHB */
			{
				ac = AC_VI_Q; /* Video */
			}
			break;
			case 0xC0:           /* IP-PL6 */
			case 0xd0:
			case 0xE0:           /* IP-PL7 */
			case 0x88:           /* AF41-PHB */
			case 0xB8:           /* EF-PHB */
			{
				ac = AC_VO_Q; /* Voice */
			}
			break;
			default:
			{
				ac = AC_BE_Q; /* Best Effort */
			}
			break;
		}
	}
	else 
	{
		ac  = AC_BE_Q;
	}
	
	tqe->q_num = ac;
	p->os_func.os_spin_unlock(p->txq_spinlock, &flags);
	return ac;
}

static inline int balance_ac_queues(uint8_t* actual_count, uint8_t* num_pkts_to_reach_desired_ratio)
{
	uint8_t i;
	uint8_t max_count = 0;
	if(actual_count == NULL || num_pkts_to_reach_desired_ratio == NULL) {
		//printk("[%s][%d]ps32RachRatio=%p\n",__FUNCTION__,__LINE__, num_pkts_to_reach_desired_ratio);
		return -1;
	}
	for (i = 0; i < NQUEUES; i++) {
		if (actual_count[i] > max_count) {
			max_count = actual_count[i];
		}
	}
	for (i = 0; i < NQUEUES; i++) {
		num_pkts_to_reach_desired_ratio[i] = max_count - actual_count[i];
	}
	return 0;
}

/***	--------------------------- WILC_HOST_TX_CTRL ------------------------------------		***/
/*** 	BITS 31:25		24		23:17	16		15:9		8		7:2		1		0 				***/
/***		 VO CNT 		VO ACM	VI CNT	VI ACM	BE CNT	BE ACM	BK CNT	BK ACM	VMM ready 		***/
/***	-----------------------------------------------------------------------------------		***/
static inline void get_fw_actual_pkt_count(uint32_t reg, uint8_t* ac_actual_count)
{
	ac_actual_count[AC_BK_Q] = (reg & 0x000000fa) >> BK_AC_COUNT_POS;
	ac_actual_count[AC_BE_Q] = (reg & 0x0000fe00) >> BE_AC_COUNT_POS;
	ac_actual_count[AC_VI_Q] = (reg & 0x00fe0000) >> VI_AC_COUNT_POS;
	ac_actual_count[AC_VO_Q] = (reg & 0xfe000000) >> VO_AC_COUNT_POS;
}

/*TicketId_803*/
/*Catch each AC ACM status.*/
static inline void set_ac_acm_bit(uint32_t reg)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;

	/*Bit 0 of each byte indicates the corresponding AC ACM staus.*/
	/*Since bit 0 is already in use, BK AC uses bit 1 instead for its ACM status indication.*/
	p->txq[AC_BK_Q].acm = (reg & 0x00000002) >> BK_AC_ACM_STAT_POS;
	p->txq[AC_BE_Q].acm = (reg & 0x00000100) >> BE_AC_ACM_STAT_POS;
	p->txq[AC_VI_Q].acm = (reg & 0x00010000) >> VI_AC_ACM_STAT_POS;
	p->txq[AC_VO_Q].acm = (reg & 0x01000000) >> VO_AC_ACM_STAT_POS;
}

/*Change packet AC if needed according to ACM status.*/
static inline uint8_t change_ac_if_needed(uint8_t* ac)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint8_t ret = 1;	//0:success , 1:failure

	do
	{
		if(p->txq[*ac].acm == 0)
			return 0;
		(*ac)++;
	}while(*ac < NQUEUES);

	return ret;
}

static int wilc_wlan_handle_txq(uint32_t* pu32TxqCount)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	int i, entries = 0;
	uint8_t k, ac;
	uint32_t sum;
	uint32_t reg;
	uint8_t ac_pkt_cnt_to_reach_desired_ratio[NQUEUES]={0, 0, 0, 0};
	uint8_t ac_pkt_cnt_to_reach_preserve_ratio[NQUEUES]={1, 1, 1, 1};
	uint8_t* num_pkts_to_add;
	uint8_t vmm_entries_ac[WILC_VMM_TBL_SIZE];
	uint8_t *txb = p->tx_buffer;
	uint32_t offset = 0;
	bool is_max_capacity_reached = 0, does_ac_txq_entry_exist = 0;
	int vmm_sz = 0;
	struct txq_entry_t *tqe_q[NQUEUES];
	int ret = 0;
	int counter;
	int timeout;
	uint32_t vmm_table[WILC_VMM_TBL_SIZE];
	static uint8_t ac_fw_actual_pkt_count[NQUEUES] = {0, 0, 0, 0};
	uint8_t ac_pkt_num_to_chip[NQUEUES] = {0, 0, 0, 0};
	
	p->txq_exit = 0;
	if(p->txq_entries) {
		p->os_func.os_wait(p->txq_add_to_head_lock, CFG_PKTS_TIMEOUT);
		do {
			if (p->quit)
				break;
			if(balance_ac_queues(ac_fw_actual_pkt_count, ac_pkt_cnt_to_reach_desired_ratio) == -1)
				return -1;
#ifdef	TCP_ACK_FILTER
			wilc_wlan_txq_filter_dup_tcp_ack();
#endif
			/**
				build the vmm list
			**/
			PRINT_D(TX_DBG,"Getting the head of the TxQ\n");
			for(ac = 0; ac < NQUEUES; ac++) {
				tqe_q[ac]= wilc_wlan_txq_get_first(ac);
			}
			i = 0;
			sum = 0;
			is_max_capacity_reached = 0;
			num_pkts_to_add = ac_pkt_cnt_to_reach_desired_ratio;
			do {
				does_ac_txq_entry_exist = 0;
				for(ac = 0; (ac < NQUEUES) && (!is_max_capacity_reached); ac++) {
					if(tqe_q[ac] != NULL) {	
						does_ac_txq_entry_exist = 1;
						for(k = 0; (k < num_pkts_to_add[ac]) && (!is_max_capacity_reached) && (tqe_q[ac] != NULL); k++) {
							if (i < (WILC_VMM_TBL_SIZE-1)) { /* reserve last entry to 0 */
								if (tqe_q[ac]->type == WILC_CFG_PKT) {
									vmm_sz = ETH_CONFIG_PKT_HDR_OFFSET;
								}
								/*Bug3959: transmitting mgmt frames received from host*/
								/*vmm_sz will only be equal to tqe->buffer_size + 4 bytes (HOST_HDR_OFFSET)*/
								/* in other cases WILC_MGMT_PKT and WILC_DATA_PKT_MAC_HDR*/
								else if (tqe_q[ac]->type == WILC_NET_PKT) {
									vmm_sz = ETH_ETHERNET_HDR_OFFSET;
								}
#ifdef WILC_FULLY_HOSTING_AP
								else if (tqe_q[ac]->type == WILC_FH_DATA_PKT) {
									vmm_sz = FH_TX_HOST_HDR_OFFSET;
								}
#endif
#ifdef WILC_AP_EXTERNAL_MLME
								else {
									vmm_sz = HOST_HDR_OFFSET;
								}
#endif
								vmm_sz += tqe_q[ac]->buffer_size;
								PRINT_D(TX_DBG,"VMM Size before alignment = %d\n",vmm_sz);
								if (vmm_sz & 0x3) {		/* has to be word aligned */
									vmm_sz = (vmm_sz + 4) & ~0x3;
								}
								if((sum+vmm_sz) > p->tx_buffer_size) {
									is_max_capacity_reached = 1;	
									break;
								}
								PRINT_D(TX_DBG,"VMM Size AFTER alignment = %d\n",vmm_sz);
								vmm_table[i] = vmm_sz/4;	/* table take the word size */
								PRINT_D(TX_DBG,"VMMTable entry size = %d\n",vmm_table[i]);

								if (tqe_q[ac]->type == WILC_CFG_PKT) {
									vmm_table[i] |= (1 << 10);
									PRINT_D(TX_DBG,"VMMTable entry changed for CFG packet = %d\n",vmm_table[i]);
								}
#ifdef BIG_ENDIAN
								vmm_table[i] = BYTE_SWAP(vmm_table[i]);
#endif
								//p->hif_func.hif_write_reg(0x1160,vmm_table[0]);

								//wilc_debug(N_TXQ, "[wilc txq]: vmm table[%d] = %08x\n", i, vmm_table[i]);
								vmm_entries_ac[i] = ac;
								i++;
								sum += vmm_sz;
								PRINT_D(TX_DBG,"sum = %d\n",sum);
								tqe_q[ac] = wilc_wlan_txq_get_next(tqe_q[ac]);
							} else {
								is_max_capacity_reached = 1;	
								break;
							}
						}
					}
				}
				num_pkts_to_add = ac_pkt_cnt_to_reach_preserve_ratio;
			}while(!is_max_capacity_reached && does_ac_txq_entry_exist);

			if (i == 0) {		/* nothing in the queue */
				PRINT_D(TX_DBG,"Nothing in TX-Q\n");
				break;
			} else {
				PRINT_D(TX_DBG,"Mark the last entry in VMM table - number of previous entries = %d\n",i);
				vmm_table[i] = 0x0;	/* mark the last element to 0 */
			}
			acquire_bus(ACQUIRE_AND_WAKEUP);
			counter = 0;
			do {

				ret = p->hif_func.hif_read_reg(WILC_HOST_TX_CTRL, &reg);
				if (!ret) {
					wilc_debug(N_ERR, "[wilc txq]: fail can't read reg vmm_tbl_entry..\n");
					break;
				}
				if ((reg&0x1) == 0) {
					get_fw_actual_pkt_count(reg, ac_fw_actual_pkt_count);
					set_ac_acm_bit(reg);

					
					PRINTARRAY("Set WmmAc", ac_fw_actual_pkt_count);
					/**
						write to vmm table
					**/

					break;
				} else {
					counter++;
					if(counter > 200) {
						counter = 0;
						PRINT_D(TX_DBG, "Looping in tx ctrl , forcce quit\n");
						ret = p->hif_func.hif_write_reg(WILC_HOST_TX_CTRL, 0);
						break;
					}
					/**
						wait for vmm table is ready
					**/
					PRINT_WRN(GENERIC_DBG, "[wilc txq]: warn, vmm table not clear yet, wait... \n");
					//release_bus(RELEASE_ALLOW_SLEEP);
					//p->os_func.os_sleep(3);	/* wait 3 ms */
					//acquire_bus(ACQUIRE_AND_WAKEUP);
				}
			} while (!p->quit);

			if(!ret) {
				goto _end_;
			}
			timeout = 200;
			do {

				/**
				write to vmm table
				**/
				ret = p->hif_func.hif_block_tx(WILC_VMM_TBL_RX_SHADOW_BASE, (uint8_t *)vmm_table, ((i+1)*4)); /* Bug 4477 fix */
				if (!ret) {
					wilc_debug(N_ERR, "ERR block TX of VMM table.\n");
					break;
				}

				/**
				interrupt firmware
				**/
				ret = p->hif_func.hif_write_reg(WILC_HOST_VMM_CTL, 0x2);
				if (!ret) {
					wilc_debug(N_ERR, "[wilc txq]: fail can't write reg host_vmm_ctl..\n");
					break;
				}

				/**
					wait for confirm...
				**/

				do {
					ret = p->hif_func.hif_read_reg(WILC_HOST_VMM_CTL, &reg);
					if (!ret) {
						wilc_debug(N_ERR, "[wilc txq]: fail can't read reg host_vmm_ctl..\n");
						break;
					}
					if ((reg>>2)&0x1) {
						/**
							Get the entries
						**/
						entries = ((reg>>3)&0x3f);
						//entries = ((reg>>3)&0x2f);
						break;
					} else {
						release_bus(RELEASE_ALLOW_SLEEP);
						//p->os_func.os_sleep(3);	/* wait 3 ms */
						//acquire_bus(ACQUIRE_AND_WAKEUP);
						//PRINT_WRN(GENERIC_DBG, "Can't get VMM entery - reg = %2x\n",reg);
					}
				} while (--timeout);
				if(timeout <= 0) {
					ret = p->hif_func.hif_write_reg(WILC_HOST_VMM_CTL, 0x0);
					break;
				}

				if (!ret) {
					break;
				}

				if (entries == 0) {
					PRINT_WRN(GENERIC_DBG, "[wilc txq]: no more buffer in the chip (reg: %08x), retry later [[ %d, %x ]] \n",reg, i, vmm_table[i-1]);

					/* undo the transaction. */
					ret = p->hif_func.hif_read_reg(WILC_HOST_TX_CTRL, &reg);
					if (!ret) {
						wilc_debug(N_ERR, "[wilc txq]: fail can't read reg WILC_HOST_TX_CTRL..\n");
						break;
					}
					reg &= ~(1ul << 0);
					ret = p->hif_func.hif_write_reg(WILC_HOST_TX_CTRL, reg);
					if (!ret) {
						wilc_debug(N_ERR, "[wilc txq]: fail can't write reg WILC_HOST_TX_CTRL..\n");
						break;
					}
					break;
				} else {
					break;
				}
			} while (1);

			if (!ret) {
				goto _end_;
			}
			if(entries == 0) {
				ret = WILC_TX_ERR_NO_BUF;
				goto _end_;
			}

			/* since copying data into txb takes some time, then
			allow the bus lock to be released let the RX task go. */
			release_bus(RELEASE_ALLOW_SLEEP);

			/**
				Copy data to the TX buffer
			**/
			offset = 0;
			i = 0;
			do {
				struct txq_entry_t * tqe;
				tqe = wilc_wlan_txq_remove_from_head(vmm_entries_ac[i]);
				ac_pkt_num_to_chip[vmm_entries_ac[i]]++;			
				if (tqe != NULL && (vmm_table[i] != 0)) {
					uint32_t header, buffer_offset;

#ifdef BIG_ENDIAN
					vmm_table[i] = BYTE_SWAP(vmm_table[i]);
#endif
					vmm_sz = (vmm_table[i] & 0x3ff);	/* in word unit */
					vmm_sz *= 4;
					header = (tqe->type << 31)|(tqe->buffer_size<<15)|vmm_sz;
					/*Bug3959: transmitting mgmt frames received from host*/
					/*setting bit 30 in the host header to indicate mgmt frame*/
#ifdef WILC_AP_EXTERNAL_MLME
					if(tqe->type == WILC_MGMT_PKT) {
						header |= (1<< 30);
					} else {
						header &= ~(1<< 30);
					}
#endif
					/*else if(tqe->type == WILC_DATA_PKT_MAC_HDR)
					{
						header |= (1<< 29);
					}*/
					//wilc_debug(N_TXQ, "[wilc txq]: header (%08x), real size (%d), vmm size (%d)\n", header, tqe->buffer_size, vmm_sz);

#ifdef BIG_ENDIAN
					header = BYTE_SWAP(header);
#endif
					memcpy(&txb[offset], &header, 4);
					if (tqe->type == WILC_CFG_PKT) {
						buffer_offset = ETH_CONFIG_PKT_HDR_OFFSET;
					}
					/*Bug3959: transmitting mgmt frames received from host*/
					/*buffer offset = HOST_HDR_OFFSET in other cases: WILC_MGMT_PKT*/
					/* and WILC_DATA_PKT_MAC_HDR*/
					else if (tqe->type == WILC_NET_PKT) {
						char * pBSSID = ((struct tx_complete_data*)(tqe->priv))->pBssid;
						int prio = tqe->q_num;
						buffer_offset = ETH_ETHERNET_HDR_OFFSET;
						//copy the bssid at the sart of the buffer
						memcpy(&txb[offset+4],&prio,sizeof(prio));
						memcpy(&txb[offset+8],pBSSID ,6);
					}
#ifdef WILC_FULLY_HOSTING_AP
					else if (tqe->type == WILC_FH_DATA_PKT) {
						buffer_offset = FH_TX_HOST_HDR_OFFSET;
					}
#endif
					else {
						buffer_offset = HOST_HDR_OFFSET;
					}

					memcpy(&txb[offset+buffer_offset], tqe->buffer, tqe->buffer_size);
					offset += vmm_sz;
					i++;
					tqe->status = 1;				/* mark the packet send */
					if (tqe->tx_complete_func)
						tqe->tx_complete_func(tqe->priv, tqe->status);
				#ifdef TCP_ACK_FILTER
					if(tqe->tcp_PendingAck_index != NOT_TCP_ACK) {
						if(tqe->tcp_PendingAck_index < MAX_PENDING_ACKS)
							Pending_Acks_info[tqe->tcp_PendingAck_index].txqe=NULL;
					}
				#endif
					p->os_func.os_free(tqe);
				} else {
				break;
				}
			} while (--entries);

			for(i = 0; i < NQUEUES; i++) {
				ac_fw_actual_pkt_count[i] += ac_pkt_num_to_chip[i];
			}
			PRINTARRAY("PktToChip",ac_pkt_num_to_chip);
			PRINTARRAY("WmmAc", ac_fw_actual_pkt_count);
			/**
				lock the bus
			**/
			acquire_bus(ACQUIRE_AND_WAKEUP);

			ret = p->hif_func.hif_clear_int_ext(ENABLE_TX_VMM);
			if (!ret) {
				wilc_debug(N_ERR, "[wilc txq]: fail can't start tx VMM ...\n");
				goto _end_;
			}

			/**
				transfer
			**/
			ret = p->hif_func.hif_block_tx_ext(0, txb, offset);
			if(!ret) {
				wilc_debug(N_ERR, "[wilc txq]: fail can't block tx ext...\n");
				goto _end_;
			}

_end_:

			release_bus(RELEASE_ALLOW_SLEEP);
			if (ret != 1)
				break;
		} while(0);
		//remove_TCP_related();
		/*Added by Amr - BugID_4720*/
		p->os_func.os_signal(p->txq_add_to_head_lock);
	}
	p->txq_exit = 1;
	PRINT_D(TX_DBG,"THREAD: Exiting txq\n");
	//return tx[]q count
	*pu32TxqCount = p->txq_entries;
	return ret;
}

static void wilc_wlan_handle_rxq(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	int offset = 0, size, has_packet = 0;
	uint8_t *buffer;
	struct rxq_entry_t *rqe;

	p->rxq_exit = 0;




	do {
		if (p->quit){
			PRINT_D(RX_DBG,"exit 1st do-while due to Clean_UP function \n");
			p->os_func.os_signal(p->cfg_wait);
			break;
		}
		rqe = wilc_wlan_rxq_remove();
		if (rqe == NULL){
			PRINT_D(RX_DBG,"nothing in the queue - exit 1st do-while\n");
			break;
		}
		buffer = rqe->buffer;
		size = rqe->buffer_size;
		PRINT_D(RX_DBG,"rxQ entery Size = %d - Address = %p\n",size,buffer);
		offset = 0;



		do {
			uint32_t header;
			uint32_t pkt_len, pkt_offset, tp_len;
			int is_cfg_packet;
			PRINT_D(RX_DBG,"In the 2nd do-while\n");
			memcpy(&header, &buffer[offset], 4);
#ifdef BIG_ENDIAN
			header = BYTE_SWAP(header);
#endif
			PRINT_D(RX_DBG,"Header = %04x - Offset = %d\n",header,offset);



			is_cfg_packet = (header >> 31) & 0x1;
			pkt_offset = (header >> 22) & 0x1ff;
			tp_len = (header >> 11)&0x7ff;
			pkt_len = header & 0x7ff;

			if (pkt_len == 0 || tp_len == 0) {
				wilc_debug(N_RXQ, "[wilc rxq]: data corrupt, packet len or tp_len is 0 [%d][%d]\n", pkt_len, tp_len);
				break;
			}

/*bug 3887: [AP] Allow Management frames to be passed to the host*/
			#if defined(WILC_AP_EXTERNAL_MLME) || defined(WILC_P2P)
			#define IS_MANAGMEMENT 				0x100
			#define IS_MANAGMEMENT_CALLBACK 		0x080
			#define IS_MGMT_STATUS_SUCCES			0x040


			if(pkt_offset & IS_MANAGMEMENT)
				{
					//reset mgmt indicator bit, to use pkt_offeset in furthur calculations
					pkt_offset &= ~(IS_MANAGMEMENT | IS_MANAGMEMENT_CALLBACK | IS_MGMT_STATUS_SUCCES);

#ifdef USE_WIRELESS
					WILC_WFI_mgmt_rx(&buffer[offset+HOST_HDR_OFFSET],pkt_len);

#endif

				}

			//BUG4530 fix
			else
			#endif
		{
			//wilc_debug(N_RXQ, "[wilc rxq]: packet, tp len(%d), len (%d), offset (%d), cfg (%d)\n", tp_len, pkt_len, pkt_offset, is_cfg_packet);

			if (!is_cfg_packet) {

				if (p->net_func.rx_indicate) {
					if (pkt_len > 0) {
						p->net_func.rx_indicate(&buffer[offset], pkt_len,pkt_offset);
						has_packet = 1;
					}
				}
			} else {
				wilc_cfg_rsp_t rsp;



				p->cif_func.rx_indicate(&buffer[pkt_offset+offset], pkt_len, &rsp);
				if (rsp.type == WILC_CFG_RSP) {
					/**
						wake up the waiting task...
					**/
				PRINT_D(RX_DBG,"p->cfg_seq_no = %d - rsp.seq_no = %d\n",p->cfg_seq_no,rsp.seq_no);
					if (p->cfg_seq_no == rsp.seq_no) {
						p->os_func.os_signal(p->cfg_wait);
					}
					//p->os_func.os_signal(p->cfg_wait);
				} else if (rsp.type == WILC_CFG_RSP_STATUS) {
					/**
						Call back to indicate status...
					**/
					if (p->indicate_func.mac_indicate) {
						p->indicate_func.mac_indicate(WILC_MAC_INDICATE_STATUS);
					}

				} else if (rsp.type == WILC_CFG_RSP_SCAN) {
					if (p->indicate_func.mac_indicate)
						p->indicate_func.mac_indicate(WILC_MAC_INDICATE_SCAN);
				}
			}
		}
			offset += tp_len;
			if (offset >= size)
				break;
		} while (1);


#ifndef MEMORY_STATIC
		if (buffer != NULL)
			p->os_func.os_free((void *)buffer);
#endif
		if (rqe != NULL)
			p->os_func.os_free((void *)rqe);

		if (has_packet) {
			if (p->net_func.rx_complete)
				p->net_func.rx_complete();
		}
	} while(1);

	p->rxq_exit = 1;
	PRINT_D(RX_DBG,"THREAD: Exiting RX thread \n");
	return;
}

/********************************************

	Fast DMA Isr

********************************************/
static void wilc_unknown_isr_ext(void){
	g_wlan.hif_func.hif_clear_int_ext(0);
}
static void wilc_pllupdate_isr_ext(uint32_t int_stats){

	int trials= 10;

	g_wlan.hif_func.hif_clear_int_ext(PLL_INT_CLR);

	/* Waiting for PLL */
	g_wlan.os_func.os_atomic_sleep(WILC_PLL_TO);

	//poll till read a valid data
	while(!(ISWILC1000(wilc_get_chipid(WILC_TRUE))&&--trials)) {
		PRINT_D(TX_DBG, "PLL update retrying\n");
		g_wlan.os_func.os_atomic_sleep(1);
	}
}

static void wilc_sleeptimer_isr_ext(uint32_t int_stats1)
{
	g_wlan.hif_func.hif_clear_int_ext(SLEEP_INT_CLR);
#ifndef WILC_OPTIMIZE_SLEEP_INT
	genuChipPSstate = CHIP_SLEEPING_AUTO;
#endif
}

static void wilc_wlan_handle_isr_ext(uint32_t int_status)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
#ifdef MEMORY_STATIC
	uint32_t offset = p->rx_buffer_offset;
#endif
	uint8_t *buffer = NULL;
	uint32_t size;
	uint32_t retries=0;
	int ret = 0;
	struct rxq_entry_t *rqe;


	/**
		Get the rx size
	**/

	size = ((int_status & 0x7fff) << 2);

	while(!size && retries < 10)
	{
		uint32_t time=0;
		/*looping more secure*/
		/*zero size make a crashe because the dma will not happen and that will block the firmware*/
		wilc_debug(N_ERR, "RX Size equal zero ... Trying to read it again for %d time\n",time++);
		p->hif_func.hif_read_size(&size);
		size = ((size & 0x7fff) << 2);
		retries++;

	}

	if (size > 0) {
#ifdef MEMORY_STATIC
		if (p->rx_buffer_size - offset < size)
			offset = 0;

		if(p->rx_buffer)
			buffer = &p->rx_buffer[offset];
		else
		{
			wilc_debug(N_ERR, "[wilc isr]: fail Rx Buffer is NULL...drop the packets (%d)\n", size);
			goto _end_;
		}

#else
		buffer = p->os_func.os_malloc(size);
		if (buffer == NULL) {
			wilc_debug(N_ERR, "[wilc isr]: fail alloc host memory...drop the packets (%d)\n", size);
			WILC_Sleep(100);
			goto _end_;
		}
#endif

		/**
			clear the chip's interrupt	 after getting size some register getting corrupted after clear the interrupt
		**/
		p->hif_func.hif_clear_int_ext(DATA_INT_CLR|ENABLE_RX_VMM);


		/**
		start transfer
		**/
		ret = p->hif_func.hif_block_rx_ext(0, buffer, size);

 		if (!ret) {
			wilc_debug(N_ERR, "[wilc isr]: fail block rx...\n");
			goto _end_;
		}
_end_:


		if (ret) {
#ifdef MEMORY_STATIC
			offset += size;
			p->rx_buffer_offset = offset;
#endif
			/**
				add to rx queue
			**/
			rqe = (struct rxq_entry_t *)p->os_func.os_malloc(sizeof(struct rxq_entry_t));
			if (rqe != NULL) {
				rqe->buffer = buffer;
				rqe->buffer_size = size;
				PRINT_D(RX_DBG,"rxq entery Size= %d - Address = %p\n",rqe->buffer_size,rqe->buffer);
				wilc_wlan_rxq_add(rqe);
				p->os_func.os_signal(p->rxq_wait);
			}
		} else {
#ifndef MEMORY_STATIC
			if (buffer != NULL)
				p->os_func.os_free(buffer);
#endif
		}
	}
#ifdef TCP_ENHANCEMENTS
	wilc_wlan_handle_rxq();
#endif
}

void wilc_handle_isr(void)
{
	uint32_t int_status;

	acquire_bus(ACQUIRE_AND_WAKEUP);
	g_wlan.hif_func.hif_read_int(&int_status);

	if(int_status & PLL_INT_EXT){
		wilc_pllupdate_isr_ext(int_status);
	}
	if(int_status & DATA_INT_EXT){
		wilc_wlan_handle_isr_ext(int_status);
	#ifndef WILC_OPTIMIZE_SLEEP_INT
		/* Chip is up and talking*/
		genuChipPSstate = CHIP_WAKEDUP;
	#endif
	}
	if(int_status & SLEEP_INT_EXT){
		wilc_sleeptimer_isr_ext(int_status);
	}

	if(!(int_status & (ALL_INT_EXT))) {
#ifdef WILC_SDIO
		PRINT_D(TX_DBG, ">> UNKNOWN_INTERRUPT - 0x%08x\n",int_status);
#endif
		wilc_unknown_isr_ext();
	}
#if ((!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO))
	linux_wlan_enable_irq();
#endif
	release_bus(RELEASE_ALLOW_SLEEP);
}

/********************************************

	Firmware download

********************************************/
static int wilc_wlan_firmware_download(const uint8_t *buffer, uint32_t buffer_size)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint32_t offset;
	uint32_t addr, size, size2, blksz;
	uint8_t *dma_buffer;
	int ret = 0;

	blksz = (1ul << 12); /* Bug 4703: 4KB Good enough size for most platforms = PAGE_SIZE. */
	/* Allocate a DMA coherent  buffer. */

#if (defined WILC_PREALLOC_AT_BOOT)
{
	extern void * get_fw_buffer(void);
	dma_buffer = (uint8_t *)get_fw_buffer();
	PRINT_D(TX_DBG, "fw_buffer = 0x%x\n", dma_buffer);
}
#else
	dma_buffer = (uint8_t *)g_wlan.os_func.os_malloc(blksz);
#endif
	if (dma_buffer == NULL) {
		/*EIO	5*/
		ret = -5;
		PRINT_ER("Can't allocate buffer for firmware download IO error\n ");
		goto _fail_1;
	}

	PRINT_D(INIT_DBG,"Downloading firmware size = %d ...\n",buffer_size);
	/**
		load the firmware
	**/
	offset = 0;
	do {
		memcpy(&addr, &buffer[offset], 4);
		memcpy(&size, &buffer[offset+4], 4);
#ifdef BIG_ENDIAN
		addr = BYTE_SWAP(addr);
		size = BYTE_SWAP(size);
#endif
		acquire_bus(ACQUIRE_ONLY);
		offset += 8;
		while(((int)size) && (offset < buffer_size)) {
			if(size <= blksz) {
				size2 = size;
			} else {
				size2 = blksz;
			}
			/* Copy firmware into a DMA coherent buffer */
			memcpy(dma_buffer, &buffer[offset], size2);
			ret = p->hif_func.hif_block_tx(addr, dma_buffer, size2);
			if (!ret) break;

			addr += size2;
			offset += size2;
			size -= size2;
		}
		release_bus(RELEASE_ONLY);

		if (!ret){
			/*EIO	5*/
			ret = -5;
			PRINT_ER("Can't download firmware IO error\n ");
			goto _fail_;
		}
		PRINT_D(INIT_DBG,"Offset = %d\n",offset);
	} while (offset < buffer_size);

_fail_:

#if (defined WILC_PREALLOC_AT_BOOT)

#else
		if(dma_buffer) g_wlan.os_func.os_free(dma_buffer);
#endif

_fail_1:

	return (ret < 0)? ret:0;
}

/********************************************

	Common

********************************************/
static int wilc_wlan_start(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint32_t reg = 0;
	int ret;
	uint32_t chipid;

	/**
		Set the host interface
	**/
#ifdef OLD_FPGA_BITFILE
	acquire_bus(ACQUIRE_ONLY);
	ret = p->hif_func.hif_read_reg(WILC_VMM_CORE_CTL, &reg);
	if (!ret) {
		wilc_debug(N_ERR, "[wilc start]: fail read reg vmm_core_ctl...\n");
		release_bus(RELEASE_ALLOW_SLEEP);
 		return ret;
	}
	reg |= (p->io_func.io_type<<2);
	ret = p->hif_func.hif_write_reg(WILC_VMM_CORE_CTL, reg);
	if (!ret) {
		wilc_debug(N_ERR, "[wilc start]: fail write reg vmm_core_ctl...\n");
		release_bus(RELEASE_ONLY);
 		return ret;
	}
#else
	if (p->io_func.io_type == HIF_SDIO) {
		reg = 0;
		reg |= (1 << 3); /* bug 4456 and 4557 */
	} else if (p->io_func.io_type == HIF_SPI) {
		reg = 1;
	}
	acquire_bus(ACQUIRE_ONLY);
	ret = p->hif_func.hif_write_reg(WILC_VMM_CORE_CFG, reg);
	if (!ret) {
		wilc_debug(N_ERR, "[wilc start]: fail write reg vmm_core_cfg...\n");
		release_bus(RELEASE_ONLY);
		/* EIO  5*/
		ret = -5;
 		return ret;
	}
	reg = 0;
#ifdef WILC_SDIO_IRQ_GPIO
	reg |= WILC_HAVE_SDIO_IRQ_GPIO;
#endif

#ifdef WILC_DISABLE_PMU
#else
	reg |= WILC_HAVE_USE_PMU;
#endif

#ifdef WILC_SLEEP_CLK_SRC_XO
	reg |= WILC_HAVE_SLEEP_CLK_SRC_XO;
#elif defined WILC_SLEEP_CLK_SRC_RTC
	reg |= WILC_HAVE_SLEEP_CLK_SRC_RTC;
#endif

#ifdef WILC_EXT_PA_INV_TX_RX
	reg |= WILC_HAVE_EXT_PA_INV_TX_RX;
#endif

#ifdef HAS_SUSPEND_RESUME
	reg |= WILC_HAVE_USE_IRQ_AS_HOST_WAKE;
#endif

#ifdef HAS_SINGLE_IP_ANTENNA_DEV_MODULE
	reg |= WILC_HAVE_SIN_IP_ANT_DEV_MODULE;
#elif defined(HAS_DUAL_IP_ANTENNA_DEV_MODULE)
	reg |= WILC_HAVE_SIN_IP_ANT_DEV_MODULE;
	reg |= WILC_HAVE_DUL_IP_ANT_DEV_MODULE;
#endif

	reg |= WILC_HAVE_LEGACY_RF_SETTINGS;


/*BugID_5257*/
/*Set oscillator frequency*/
#ifdef XTAL_24
	reg |= WILC_HAVE_XTAL_24;
#endif

/*BugID_5271*/
/*Enable/Disable GPIO configuration for FW logs*/
#ifdef DISABLE_WILC_UART
	reg |= WILC_HAVE_DISABLE_WILC_UART;
#endif

	ret = p->hif_func.hif_write_reg(WILC_GP_REG_1, reg);
	if (!ret) {
		wilc_debug(N_ERR, "[wilc start]: fail write WILC_GP_REG_1 ...\n");
		release_bus(RELEASE_ONLY);
		/* EIO  5*/
		ret = -5;
 		return ret;
	}
#endif


	/**
		Bus related
	**/
	p->hif_func.hif_sync_ext(NUM_INT_EXT);

	ret = p->hif_func.hif_read_reg(0x1000, &chipid);
	if (!ret) {
		wilc_debug(N_ERR, "[wilc start]: fail read reg 0x1000 ...\n");
		release_bus(RELEASE_ONLY);
		/* EIO  5*/
		ret = -5;
 		return ret;
	}

	/**
		Go...
	**/

	//p->hif_func.hif_write_reg(0x150014, reg);

	p->hif_func.hif_read_reg(WILC_GLB_RESET_0,&reg);
	if((reg & (1ul << 10)) == (1ul << 10)){
		reg &= ~(1ul << 10);
		p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);
		p->hif_func.hif_read_reg(WILC_GLB_RESET_0,&reg);
	}

	reg |= (1ul << 10);
	ret = p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);
	p->hif_func.hif_read_reg(WILC_GLB_RESET_0,&reg);
	release_bus(RELEASE_ONLY);

	return (ret<0)?ret:0;
}

void wilc_wlan_global_reset(void)
{

	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	acquire_bus(ACQUIRE_AND_WAKEUP);
	p->hif_func.hif_write_reg(WILC_GLB_RESET_0,0x0);
	release_bus(RELEASE_ONLY);
}
static int wilc_wlan_stop(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint32_t reg = 0;
	int ret;
	uint8_t timeout=10;
	/**
		TODO: stop the firmware, need a re-download
	**/
	acquire_bus(ACQUIRE_AND_WAKEUP);

	ret = p->hif_func.hif_read_reg(WILC_GLB_RESET_0, &reg);
	if (!ret) {
		PRINT_ER("Error while reading reg\n");
		release_bus(RELEASE_ALLOW_SLEEP);
		return ret;
	}

	reg &= ~(1 << 10);


	ret = p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);
	if (!ret) {
		PRINT_ER("Error while writing reg\n");
		release_bus(RELEASE_ALLOW_SLEEP);
		return ret;
	}



	do
	{
		ret = p->hif_func.hif_read_reg(WILC_GLB_RESET_0, &reg);
		if (!ret) {
			PRINT_ER("Error while reading reg\n");
			release_bus(RELEASE_ALLOW_SLEEP);
			return ret;
		}
		PRINT_D(GENERIC_DBG,"Read RESET Reg %x : Retry%d\n",reg,timeout);
        /*Workaround to ensure that the chip is actually reset*/
		if( (reg & (1 << 10) ) )
		{
			PRINT_D(GENERIC_DBG,"Bit 10 not reset : Retry %d\n",timeout);
			reg &= ~(1 << 10);
			ret = p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);
			timeout--;
		}
		else
		{
			PRINT_D(GENERIC_DBG,"Bit 10 reset after : Retry %d\n",timeout);
			ret = p->hif_func.hif_read_reg(WILC_GLB_RESET_0, &reg);
			if (!ret) {
			PRINT_ER("Error while reading reg\n");
			release_bus(RELEASE_ALLOW_SLEEP);
			return ret;
			}
			PRINT_D(GENERIC_DBG,"Read RESET Reg %x : Retry%d\n",reg,timeout);
		 	break;
		}

	}while(timeout)	;
#if 1
/******************************************************************************/
/* This was add at Bug 4595 to reset the chip while maintaining the bus state */
/******************************************************************************/
	reg = ((1<<0)|(1<<1)|(1<<2)|(1<<3)|(1<<8)|(1<<9)|(1<<26)|(1<<29)|(1<<30)|(1 << 31));/**/
																			/**/
	ret = p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);					/**/
	reg = ~(1 << 10);            											/**/
																			/**/
	ret = p->hif_func.hif_write_reg(WILC_GLB_RESET_0, reg);					/**/
/******************************************************************************/
#endif

	release_bus(RELEASE_ALLOW_SLEEP);

	return ret;
}

static void wilc_wlan_cleanup(void)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	struct txq_entry_t *tqe;
	struct rxq_entry_t *rqe;
	uint32_t reg = 0;
	int ret;
	uint8_t ac;

	p->quit = 1;
	/**
		wait for queue end
	**/
	//p->os_func.os_signal(p->txq_wait);
	//p->os_func.os_signal(p->rxq_wait);

	//complete(p->txq_wait);
	//complete(p->rxq_wait);
	/*do {
		if (p->txq_exit && p->rxq_exit)
			break;
	} while (1);*/

	/**
		clean up the queue
	**/
	for(ac = 0; ac < NQUEUES; ac++)
	
	do {
		tqe = wilc_wlan_txq_remove_from_head(ac);
		if (tqe == NULL)
			break;
		if (tqe->tx_complete_func)
			tqe->tx_complete_func(tqe->priv, 0);
		p->os_func.os_free((void *)tqe);
	} while (1);

	do {
		rqe = wilc_wlan_rxq_remove();
		if (rqe == NULL)
			break;
#ifdef MEMORY_DYNAMIC
		p->os_func.os_free((void *)tqe->buffer);
#endif
		p->os_func.os_free((void *)rqe);
	} while (1);

	/**
		clean up buffer
	**/

#if (defined WILC_PREALLOC_AT_BOOT)

#else
	#ifdef MEMORY_STATIC
	if (p->rx_buffer)
	{
		p->os_func.os_free(p->rx_buffer);
		p->rx_buffer = WILC_NULL;
	}
	#endif
	if (p->tx_buffer)
	{
		p->os_func.os_free(p->tx_buffer);
		p->tx_buffer = WILC_NULL;
	}
#endif

	acquire_bus(ACQUIRE_AND_WAKEUP);


	ret = p->hif_func.hif_read_reg(WILC_GP_REG_0,&reg);
	if (!ret) {
		PRINT_ER("Error while reading reg\n");
		release_bus(RELEASE_ALLOW_SLEEP);
	}
	PRINT_ER("Writing ABORT reg\n");
  	ret = p->hif_func.hif_write_reg(WILC_GP_REG_0,(reg | ABORT_INT ));
	if (!ret) {
		PRINT_ER("Error while writing reg\n");
		release_bus(RELEASE_ALLOW_SLEEP);
	}
	release_bus(RELEASE_ALLOW_SLEEP);
	/**
		io clean up
	**/
	p->hif_func.hif_deinit(NULL);

}

static int wilc_wlan_cfg_commit(int type,uint32_t drvHandler)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	wilc_cfg_frame_t *cfg = &p->cfg_frame;
	int total_len = p->cfg_frame_offset+4+ DRIVER_HANDLER_SIZE ;
	int seq_no = p->cfg_seq_no%256;
	int driver_handler=(WILC_Uint32)drvHandler;


	/**
		Set up header
	**/
	if (type == WILC_CFG_SET) {		/* Set */
		cfg->wid_header[0] = 'W';
	} else {					/* Query */
		cfg->wid_header[0] = 'Q';
	}
	cfg->wid_header[1] = seq_no;	/* sequence number */
	cfg->wid_header[2] = (uint8_t)total_len;
	cfg->wid_header[3] = (uint8_t)(total_len>>8);
	cfg->wid_header[4] = (uint8_t)driver_handler;
	cfg->wid_header[5] = (uint8_t)(driver_handler>>8);
	cfg->wid_header[6] = (uint8_t)(driver_handler>>16);
	cfg->wid_header[7] = (uint8_t)(driver_handler>>24);
	p->cfg_seq_no = seq_no;

	/**
		Add to TX queue
	**/

	/*Edited by Amr - BugID_4720*/
	if(!wilc_wlan_txq_add_cfg_pkt(&cfg->wid_header[0], total_len))
		return -1;

	return 0;
}

static int wilc_wlan_cfg_set(int start, uint32_t wid, uint8_t *buffer, uint32_t buffer_size, int commit,uint32_t drvHandler)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint32_t offset;
	int ret_size;


	if (p->cfg_frame_in_use)
		return 0;

	if (start)
		p->cfg_frame_offset = 0;

	offset = p->cfg_frame_offset;
	ret_size = p->cif_func.cfg_wid_set(p->cfg_frame.frame, offset, (uint16_t)wid, buffer, buffer_size);
	offset += ret_size;
	p->cfg_frame_offset = offset;

	if (commit) {
		PRINT_D(TX_DBG,"[WILC]PACKET Commit with sequence number %d\n",p->cfg_seq_no);
		PRINT_D(RX_DBG,"Processing cfg_set()\n");
		p->cfg_frame_in_use = 1;

		/*Edited by Amr - BugID_4720*/
		if(wilc_wlan_cfg_commit(WILC_CFG_SET,drvHandler))
			ret_size = 0;	//BugID_5213

		if(p->os_func.os_wait(p->cfg_wait,CFG_PKTS_TIMEOUT))
		{
			PRINT_D(TX_DBG, "Set Timed Out\n");
			ret_size = 0;
		}
		p->cfg_frame_in_use = 0;
		p->cfg_frame_offset = 0;
		p->cfg_seq_no += 1;

	}

	return ret_size;
}
static int wilc_wlan_cfg_get(int start, uint32_t wid, int commit,uint32_t drvHandler)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	uint32_t offset;
	int ret_size;


	if (p->cfg_frame_in_use)
		return 0;

	if (start)
		p->cfg_frame_offset = 0;

	offset = p->cfg_frame_offset;
	ret_size = p->cif_func.cfg_wid_get(p->cfg_frame.frame, offset, (uint16_t)wid);
	offset += ret_size;
	p->cfg_frame_offset = offset;

	if (commit) {
		p->cfg_frame_in_use = 1;

		/*Edited by Amr - BugID_4720*/
		if(wilc_wlan_cfg_commit(WILC_CFG_QUERY,drvHandler))
			ret_size = 0;	//BugID_5213


		if(p->os_func.os_wait(p->cfg_wait,CFG_PKTS_TIMEOUT))
		{
			PRINT_D(TX_DBG, "Get Timed Out\n");
			ret_size = 0;
		}
		PRINT_D(GENERIC_DBG, "[WILC]Get Response received\n");
		p->cfg_frame_in_use = 0;
		p->cfg_frame_offset = 0;
		p->cfg_seq_no += 1;
	}

	return ret_size;
}

static int wilc_wlan_cfg_get_val(uint32_t wid, uint8_t *buffer, uint32_t buffer_size)
{
	wilc_wlan_dev_t *p = (wilc_wlan_dev_t *)&g_wlan;
	int ret;

	ret = p->cif_func.cfg_wid_get_val((uint16_t)wid, buffer, buffer_size);

	return ret;
}

void wilc_bus_set_max_speed(void){

	/* Increase bus speed to max possible.  */
	g_wlan.hif_func.hif_set_max_bus_speed();
}

void wilc_bus_set_default_speed(void){

	/* Restore bus speed to default.  */
	g_wlan.hif_func.hif_set_default_bus_speed();
}

uint32_t init_chip(void)
{
	uint32_t chipid;
	uint32_t reg,ret=0;


	acquire_bus(ACQUIRE_ONLY);
	chipid = wilc_get_chipid(WILC_TRUE);



	if((chipid & 0xfff) != 0xa0) {
		/**
		Avoid booting from boot ROM. Make sure that Drive IRQN [SDIO platform]
		or SD_DAT3 [SPI platform] to ?1?
		**/
		/* Set cortus reset register to register control. */
		ret = g_wlan.hif_func.hif_read_reg(0x1118, &reg);
		if (!ret) {
			wilc_debug(N_ERR, "[wilc start]: fail read reg 0x1118 ...\n");
			return ret;
		}
		reg |= (1 << 0);
		ret = g_wlan.hif_func.hif_write_reg(0x1118, reg);
		if (!ret) {
			wilc_debug(N_ERR, "[wilc start]: fail write reg 0x1118 ...\n");
			return ret;
		}
		/**
		Write branch intruction to IRAM (0x71 trap) at location 0xFFFF0000
		(Cortus map) or C0000 (AHB map).
		**/
		ret = g_wlan.hif_func.hif_write_reg(0xc0000, 0x71);
		if (!ret) {
			wilc_debug(N_ERR, "[wilc start]: fail write reg 0xc0000 ...\n");
			return ret;
		}
	}
#ifdef USE_ANTNENNA_SWITCHING
	ret = g_wlan.hif_func.hif_read_reg(0x1408, &reg);
	

	reg &= ~(0xf<<(ANTENNA_SWITCH_GPIO_NUM*4));	
	
	ret = g_wlan.hif_func.hif_write_reg(0x1408, reg);
	
	/*Configure GPIO to be output*/	
	ret = g_wlan.hif_func.hif_read_reg(0x20108, &reg);
	ret = g_wlan.hif_func.hif_write_reg(0x20108, reg|(1<<ANTENNA_SWITCH_GPIO_NUM));

	ret = g_wlan.hif_func.hif_read_reg(0x20100, &reg);
	reg &= ~(1<<ANTENNA_SWITCH_GPIO_NUM);
	/*Initially Enable antenna 1 and disable antenna 2 */
	ret = g_wlan.hif_func.hif_write_reg(0x20100,reg);
#endif
	#if 0
	if((chipid& 0xfff) < 0xf0) {
		/* Setting MUX to probe sleep signal on pin 6 of J216*/
		g_wlan.hif_func.hif_write_reg(0x1060, 0x1);
		g_wlan.hif_func.hif_write_reg(0x1180, 0x33333333);
		g_wlan.hif_func.hif_write_reg(0x1184, 0x33333333);
		g_wlan.hif_func.hif_read_reg(0x1408, &reg);
		/* set MUX for GPIO_4 (pin 4) to cortus GPIO*/
		reg &= ~((0x7 << 16));
		g_wlan.hif_func.hif_write_reg(0x1408, (reg|(0x7 << 12)));
	}else {
		/* Enable test bus*/
		g_wlan.hif_func.hif_write_reg(0x1060, 0x1);
		/* Rotate bus signals to get sleep signal on pin 6 like it was on previous chips*/
		g_wlan.hif_func.hif_write_reg(0x1188, 0x70);
		/* Set output of pin 6 to test bus 0x1*/
		/* Set output of pin 9 to test bus 0x2*/
		g_wlan.hif_func.hif_write_reg(0x1180, 0x200100);
		g_wlan.hif_func.hif_read_reg(0x1408, &reg);

		/* set MUX for GPIO_4 (pin 4) to cortus GPIO*/
		reg &= ~((0x7 << 16));
		/* set MUX for GPIO_3 (pin 6) to test bus*/
		reg |= (0x7 << 12) | (0x7 << 24);
		g_wlan.hif_func.hif_write_reg(0x1408, reg);
	}
	#endif



	release_bus(RELEASE_ONLY);

	return ret;

}

#ifdef USE_ANTNENNA_SWITCHING
uint32_t wilc_switch_current_antenna(unsigned char antenna_num)
{
	
	uint32_t reg,ret=0;
	if(antenna_num > 1)
		return 1;
	
	acquire_bus(ACQUIRE_AND_WAKEUP);
	ret = g_wlan.hif_func.hif_read_reg(0x1408, &reg);
	reg &= ~(0xf<<(ANTENNA_SWITCH_GPIO_NUM*4));
	ret = g_wlan.hif_func.hif_write_reg(0x1408, reg);
	/*Configure GPIO to be output*/
	ret = g_wlan.hif_func.hif_read_reg(0x20108, &reg);
	ret = g_wlan.hif_func.hif_write_reg(0x20108, reg|(1<<ANTENNA_SWITCH_GPIO_NUM));
	ret = g_wlan.hif_func.hif_read_reg(0x20100, &reg);
	reg &= ~(1<<ANTENNA_SWITCH_GPIO_NUM);
	reg |= (antenna_num<<ANTENNA_SWITCH_GPIO_NUM);
	ret = g_wlan.hif_func.hif_write_reg(0x20100,reg);
	release_bus(RELEASE_ALLOW_SLEEP);
	return 0;	
}
#endif

uint32_t wilc_get_chipid(uint8_t update)
{
	static uint32_t chipid = 0;
	// SDIO can't read into global variables
	// Use this variable as a temp, then copy to the global
	uint32_t tempchipid = 0;
	uint32_t rfrevid;

	if(chipid == 0 || update != 0) {
		g_wlan.hif_func.hif_read_reg(0x1000,&tempchipid);
		g_wlan.hif_func.hif_read_reg(0x13f4,&rfrevid);
		if(!ISWILC1000(tempchipid)) {
			chipid = 0;
			goto _fail_;
		}
		chipid = tempchipid;
	}
_fail_:
	return chipid;
}

#ifdef COMPLEMENT_BOOT
uint8_t core_11b_ready(void)
{
	uint32_t reg_val;

	acquire_bus(ACQUIRE_ONLY);
	g_wlan.hif_func.hif_write_reg(0x16082c,1);
	g_wlan.hif_func.hif_write_reg(0x161600,0x90);
	g_wlan.hif_func.hif_read_reg(0x161600,&reg_val);
	release_bus(RELEASE_ONLY);

	if(reg_val == 0x90)
		return 0;
	else
		return 1;
}
#endif

int wilc_wlan_init(wilc_wlan_inp_t *inp, wilc_wlan_oup_t *oup)
{

	int ret = 0;

	PRINT_D(INIT_DBG,"Initializing WILC_Wlan ...\n");

	memset((void *)&g_wlan, 0, sizeof(wilc_wlan_dev_t));

	/**
		store the input
	**/
	memcpy((void *)&g_wlan.os_func, (void *)&inp->os_func, sizeof(wilc_wlan_os_func_t));
	memcpy((void *)&g_wlan.io_func, (void *)&inp->io_func, sizeof(wilc_wlan_io_func_t));
	memcpy((void *)&g_wlan.net_func, (void *)&inp->net_func, sizeof(wilc_wlan_net_func_t));
	memcpy((void *)&g_wlan.indicate_func, (void *)&inp->indicate_func, sizeof(wilc_wlan_net_func_t));
	g_wlan.hif_lock = inp->os_context.hif_critical_section;
	g_wlan.txq_lock = inp->os_context.txq_critical_section;

	/*Added by Amr - BugID_4720*/
	g_wlan.txq_add_to_head_lock = inp->os_context.txq_add_to_head_critical_section;

	/*Added by Amr - BugID_4720*/
	g_wlan.txq_spinlock = inp->os_context.txq_spin_lock;

	g_wlan.rxq_lock = inp->os_context.rxq_critical_section;
	g_wlan.txq_wait = inp->os_context.txq_wait_event;
	g_wlan.rxq_wait = inp->os_context.rxq_wait_event;
	g_wlan.cfg_wait = inp->os_context.cfg_wait_event;
	g_wlan.tx_buffer_size = inp->os_context.tx_buffer_size;
#if defined (MEMORY_STATIC)
	g_wlan.rx_buffer_size = inp->os_context.rx_buffer_size;
#endif
	//g_wlan.os_func.os_lock(g_wlan.cfg_wait);
	/***
		host interface init
	**/
	

	if ((inp->io_func.io_type & 0x1) == HIF_SDIO) {
		if (!hif_sdio.hif_init(inp, wilc_debug)) {
			/* EIO	5 */
			ret = -5;
			goto _fail_;
		}
		memcpy((void *)&g_wlan.hif_func, &hif_sdio, sizeof(wilc_hif_func_t));
	} else{
	if ((inp->io_func.io_type & 0x1) == HIF_SPI) {
		/**
			TODO:
		**/
		if (!hif_spi.hif_init(inp, wilc_debug)) {
			/* EIO	5 */
			ret = -5;
			goto _fail_;
		}
		memcpy((void *)&g_wlan.hif_func, &hif_spi, sizeof(wilc_hif_func_t));
	} else {
		/* EIO	5 */
		ret = -5;
		goto _fail_;
	}
	}

	/***
		mac interface init
	**/
	if (!mac_cfg.cfg_init(wilc_debug)) {
		/* ENOBUFS	105 */
		ret = -105;
		goto _fail_;
	}
	memcpy((void *)&g_wlan.cif_func, &mac_cfg, sizeof(wilc_cfg_func_t));


	/**
		alloc tx, rx buffer
	**/
#if (defined WILC_PREALLOC_AT_BOOT)
	extern void * get_tx_buffer(void);
	extern void * get_rx_buffer(void);

	PRINT_D(TX_DBG, "malloc before, g_wlan.tx_buffer = 0x%x, g_wlan.rx_buffer = 0x%x\n", g_wlan.tx_buffer, g_wlan.rx_buffer);
#endif



	if(g_wlan.tx_buffer == WILC_NULL)
#if (defined WILC_PREALLOC_AT_BOOT)
		g_wlan.tx_buffer = (uint8_t *)get_tx_buffer();
#else
		g_wlan.tx_buffer = (uint8_t *)g_wlan.os_func.os_malloc(g_wlan.tx_buffer_size);
#endif
	PRINT_D(TX_DBG, "g_wlan.tx_buffer = 0x%x\n", g_wlan.tx_buffer);

	if (g_wlan.tx_buffer == WILC_NULL) {
		/* ENOBUFS	105 */
		ret = -105;
		PRINT_ER("Can't allocate Tx Buffer");
		goto _fail_;
		}

/* rx_buffer is not used unless we activate USE_MEM STATIC which is not applicable, allocating such memory is useless*/
#if defined (MEMORY_STATIC)
	if(g_wlan.rx_buffer == WILC_NULL)
  #if (defined WILC_PREALLOC_AT_BOOT)
		g_wlan.rx_buffer = (uint8_t *)get_rx_buffer();
  #else
		g_wlan.rx_buffer = (uint8_t *)g_wlan.os_func.os_malloc(g_wlan.rx_buffer_size);
  #endif
	PRINT_D(TX_DBG, "g_wlan.rx_buffer =0x%x\n", g_wlan.rx_buffer);
	if (g_wlan.rx_buffer == WILC_NULL)
	{
		/* ENOBUFS	105 */
		ret = -105;
		PRINT_ER("Can't allocate Rx Buffer");
		goto _fail_;
	}
#endif

	/**
		export functions
	**/
	oup->wlan_firmware_download = wilc_wlan_firmware_download;
	oup->wlan_start = wilc_wlan_start;
	oup->wlan_stop = wilc_wlan_stop;
	oup->wlan_add_to_tx_que = wilc_wlan_txq_add_net_pkt;
	oup->wlan_handle_tx_que = wilc_wlan_handle_txq;
	oup->wlan_handle_rx_que = wilc_wlan_handle_rxq;
	//oup->wlan_handle_rx_isr = wilc_wlan_handle_isr;
	oup->wlan_handle_rx_isr = wilc_handle_isr;
	oup->wlan_cleanup = wilc_wlan_cleanup;
	oup->wlan_cfg_set = wilc_wlan_cfg_set;
	oup->wlan_cfg_get = wilc_wlan_cfg_get;
	oup->wlan_cfg_get_value = wilc_wlan_cfg_get_val;

	/*Bug3959: transmitting mgmt frames received from host*/
	#if defined(WILC_AP_EXTERNAL_MLME) || defined(WILC_P2P)
	oup->wlan_add_mgmt_to_tx_que = wilc_wlan_txq_add_mgmt_pkt;

	#ifdef WILC_FULLY_HOSTING_AP
	oup->wlan_add_data_to_tx_que = wilc_FH_wlan_txq_add_net_pkt;
	#endif
	#endif

	if(!init_chip()){
		/* EIO	5 */
		ret = -5;
		goto _fail_;
	}
#ifdef	TCP_ACK_FILTER
 	Init_TCP_tracking();
#endif
	return 1;

_fail_:

#if (defined WILC_PREALLOC_AT_BOOT)

#else
  #ifdef MEMORY_STATIC
	if (g_wlan.rx_buffer)
	{
		g_wlan.os_func.os_free(g_wlan.rx_buffer);
		g_wlan.rx_buffer = WILC_NULL;
	}
  #endif
	if (g_wlan.tx_buffer)
	{
		g_wlan.os_func.os_free(g_wlan.tx_buffer);
		g_wlan.tx_buffer = WILC_NULL;
	}
#endif
	
	return ret;

}

#define BIT31 (1<<31)
WILC_Uint16 Set_machw_change_vir_if(WILC_Bool bValue)
{
	WILC_Uint16 ret;
	WILC_Uint32 reg;

	/*Reset WILC_CHANGING_VIR_IF register to allow adding futrue keys to CE H/W*/
	(&g_wlan)->os_func.os_enter_cs((&g_wlan)->hif_lock);
	ret = (&g_wlan)->hif_func.hif_read_reg(WILC_CHANGING_VIR_IF, &reg);
	if (!ret)
	{
		PRINT_ER("Error while Reading reg WILC_CHANGING_VIR_IF\n");
	}

	if(bValue== WILC_TRUE)
	{
		reg |= (BIT31);
	}
	else
	{
		reg &= ~(BIT31);
	}

	ret = (&g_wlan)->hif_func.hif_write_reg(WILC_CHANGING_VIR_IF, reg);

	if (!ret)
	{
		PRINT_ER("Error while writing reg WILC_CHANGING_VIR_IF\n");
	}
	(&g_wlan)->os_func.os_leave_cs((&g_wlan)->hif_lock);

	return ret;
}

#ifdef WILC_FULLY_HOSTING_AP
wilc_wlan_dev_t* Get_wlan_context(WILC_Uint16* pu16size)
{
	*pu16size = sizeof(wilc_wlan_dev_t);
	return &g_wlan;
}
#endif

