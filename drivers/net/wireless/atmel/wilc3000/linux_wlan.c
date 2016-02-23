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

#include "wilc_wfi_cfg_operations.h"
#include "wilc_wlan_if.h"
#include "wilc_wlan.h"
#include "linux_wlan_common.h"
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#ifndef ALLWINNER_BOARD	// tony
#include <asm/gpio.h>
#endif
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
#include <linux/inetdevice.h>
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#ifdef WILC_SDIO
#include "linux_wlan_sdio.h"
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#else
#include "linux_wlan_spi.h"
#endif /* WILC_SDIO */
#include "at_pwr_dev.h"
#include "linux_wlan.h"

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
static int dev_state_ev_handler(struct notifier_block *this, unsigned long event, void *ptr);

static struct notifier_block g_dev_notifier = {
	.notifier_call = dev_state_ev_handler
};
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

#define at_wlan_deinit(nic)						\
	do {								\
		if (&g_linux_wlan->oup != NULL)			\
			if (g_linux_wlan->oup.wlan_cleanup != NULL)	\
				g_linux_wlan->oup.wlan_cleanup();	\
	} while (0)

struct android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
};

#define IRQ_WAIT	1
#define IRQ_NO_WAIT	0

static struct semaphore close_exit_sync;

static int wlan_deinit_locks(struct linux_wlan *nic);
static void wlan_deinitialize_threads(struct linux_wlan *nic);

static void linux_wlan_tx_complete(void *priv, int status);
static int  mac_init_fn(struct net_device *ndev);
static struct net_device_stats *mac_stats(struct net_device *dev);
static int mac_ioctl(struct net_device *ndev, struct ifreq *req, int cmd);
static void wilc_set_multicast_list(struct net_device *dev);

struct linux_wlan *g_linux_wlan = NULL;
struct wilc_wlan_oup *gpstrWlanOps;
bool bEnablePS = true;

extern struct WILC_WFIDrv *wfidrv_list[NUM_CONCURRENT_IFC + 1]; 
	
volatile int gbCrashRecover = 0;
volatile int g_bWaitForRecovery = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
static const struct net_device_ops wilc_netdev_ops = {
	.ndo_init = mac_init_fn,
	.ndo_open = mac_open,
	.ndo_stop = mac_close,
	.ndo_start_xmit = mac_xmit,
	.ndo_do_ioctl = mac_ioctl,
	.ndo_get_stats = mac_stats,
	.ndo_set_rx_mode  = wilc_set_multicast_list,
};
#define wilc_set_netdev_ops(ndev) ((ndev)->netdev_ops = &wilc_netdev_ops)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)

static const struct net_device_ops wilc_netdev_ops = {
	.ndo_init = mac_init_fn,
	.ndo_open = mac_open,
	.ndo_stop = mac_close,
	.ndo_start_xmit = mac_xmit,
	.ndo_do_ioctl = mac_ioctl,
	.ndo_get_stats = mac_stats,
	.ndo_set_multicast_list = wilc_set_multicast_list,
};

#define wilc_set_netdev_ops(ndev) ((ndev)->netdev_ops = &wilc_netdev_ops)

#else

static void wilc_set_netdev_ops(struct net_device *ndev)
{
	ndev->init = mac_init_fn;
	ndev->open = mac_open;
	ndev->stop = mac_close;
	ndev->hard_start_xmit = mac_xmit;
	ndev->do_ioctl = mac_ioctl;
	ndev->get_stats = mac_stats;
	ndev->set_multicast_list = wilc_set_multicast_list,
}

#endif

#ifdef DEBUG_MODE
#define DEGUG_BUFFER_LENGTH 1000
volatile int WatchDogdebuggerCounter = 0;
char DebugBuffer[DEGUG_BUFFER_LENGTH + 20] = {0};
static char *ps8current = DebugBuffer;

void printk_later(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ps8current += vsprintf(ps8current, format, args);
	va_end(args);
	if ((ps8current - DebugBuffer) > DEGUG_BUFFER_LENGTH)
		ps8current = DebugBuffer;

}

void dump_logs(void)
{
	if (DebugBuffer[0]) {
		DebugBuffer[DEGUG_BUFFER_LENGTH] = 0;
		PRINT_D(GENERIC_DBG, "early printed\n");
		printk(ps8current + 1);
		ps8current[1] = 0;
		printk("latest printed\n");
		printk(DebugBuffer);
		DebugBuffer[0] = 0;
		ps8current = DebugBuffer;
	}
}

void Reset_WatchDogdebugger(void)
{
	WatchDogdebuggerCounter = 0;
}
#endif /* DEBUG_MODE */

int bDebugThreadRunning = 0;
static int DebuggingThreadTask(void *vp)
{
	struct WILC_WFIDrv *pstrWFIDrv;
	unsigned int drvHandler;
	int timeout = 50;
	int i = 0;

	/* inform wilc_wlan_init that Debugging task is started. */
	up(&g_linux_wlan->wdt_thread_sem);

	while (1) {
		if (g_linux_wlan->wilc_initialized) {
			if (!down_timeout(&g_linux_wlan->wdt_thread_sem, msecs_to_jiffies(6000))) {
				while (!kthread_should_stop())
					schedule();
				PRINT_D(GENERIC_DBG, "Exit debug thread\n");
				return 0;
			}

			if (bDebugThreadRunning) {
				PRINT_D(GENERIC_DBG, "*** Debug Thread Running ***\n");
				if (cfg_timed_out_cnt >= 5) {
					cfg_timed_out_cnt = 0;
					timeout = 10;

					gbCrashRecover = 1;
					g_bWaitForRecovery = 1;

					PRINT_D(GENERIC_DBG, "\n\n<<<<< Recover >>>>>\n\n");

					/*TicketId1003*/
					/*Close all interfaces*/
					for (i = 0; i < NUM_CONCURRENT_IFC; i++)
						mac_close(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);

					/*Open all interfaces (First, open P2P interface, then WLAN interface)*/
					for (i = NUM_CONCURRENT_IFC; i > 0; i--) {
						while (mac_open(g_linux_wlan->strInterfaceInfo[i - 1].wilc_netdev) && --timeout)
							msleep(100);

						if (timeout == 0)
							PRINT_WRN(GENERIC_DBG, "Couldn't restart interface %d again\n", i);
					}
					pstrWFIDrv = (struct WILC_WFIDrv *)(g_linux_wlan->strInterfaceInfo[0].drvHandler);
					drvHandler = (unsigned int)(g_linux_wlan->strInterfaceInfo[0].drvHandler);

					if (pstrWFIDrv->enuHostIFstate == HOST_IF_CONNECTED) {
						struct tstrDisconnectNotifInfo strDisconnectNotifInfo;

						PRINT_D(GENERIC_DBG, "notify the upper layer with the wlan Disconnection\n");

						memset(&strDisconnectNotifInfo, 0, sizeof(struct tstrDisconnectNotifInfo));

						if (pstrWFIDrv->strWILC_UsrScanReq.pfUserScanResult) {
							PRINT_D(GENERIC_DBG, "\n\n<< Abort the running OBSS Scan >>\n\n");
							del_timer(&(pstrWFIDrv->hScanTimer));
							Handle_ScanDone((void *)pstrWFIDrv, SCAN_EVENT_ABORTED);
						}

						strDisconnectNotifInfo.u16reason = 0;
						strDisconnectNotifInfo.ie = NULL;
						strDisconnectNotifInfo.ie_len = 0;

						if (pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult != NULL) {
							#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
							g_obtainingIP = false;
							host_int_set_power_mgmt((struct WFIDrvHandle *)pstrWFIDrv, 0, 0);
							#endif

							pstrWFIDrv->strWILC_UsrConnReq.pfUserConnectResult(CONN_DISCONN_EVENT_DISCONN_NOTIF,
													     NULL,
													     0,
													     &strDisconnectNotifInfo,
													     pstrWFIDrv->strWILC_UsrConnReq.u32UserConnectPvoid);
						} else {
							PRINT_ER("Connect result callback function is NULL\n");
						}
						memset(pstrWFIDrv->au8AssociatedBSSID, 0, ETH_ALEN);

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

						/*
						 * BugID_521
						 * Freeing flushed join request params on receiving
						 * MAC_DISCONNECTED while connected
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
					}
					gbCrashRecover = 0;
				}
			}
		} else {
			msleep(1000);
		}
	}
	return 0;
}

#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
static int dev_state_ev_handler(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *dev_iface = (struct in_ifaddr *)ptr;
	struct WILC_WFI_priv *priv;
	struct WILC_WFIDrv *pstrWFIDrv;
	struct net_device *dev;
	u8 *pIP_Add_buff;
	struct perInterface_wlan *nic;
	u8 null_ip[4] = {0};
	char wlan_dev_name[5] = "wlan0";

	if (dev_iface == NULL || dev_iface->ifa_dev == NULL ||
	    dev_iface->ifa_dev->dev == NULL) {
		PRINT_ER("dev_iface = NULL\n");
		return NOTIFY_DONE;
	}

	if ((memcmp(dev_iface->ifa_label, IFC_0, 5)) &&
	    (memcmp(dev_iface->ifa_label, IFC_1, 4))) {
		PRINT_D(GENERIC_DBG, "Interface is neither WLAN0 nor P2P0\n");
		return NOTIFY_DONE;
	}

	dev  = (struct net_device *)dev_iface->ifa_dev->dev;
	if (dev->ieee80211_ptr == NULL || dev->ieee80211_ptr->wiphy == NULL) {
		PRINT_WRN(GENERIC_DBG, "No Wireless registerd\n");
		return NOTIFY_DONE;
	}

	priv = wiphy_priv(dev->ieee80211_ptr->wiphy);
	if (priv == NULL) {
		PRINT_WRN(GENERIC_DBG, "No Wireless Priv\n");
		return NOTIFY_DONE;
	}

	pstrWFIDrv = (struct WILC_WFIDrv *)priv->hWILCWFIDrv;
	nic = netdev_priv(dev);
	if (nic == NULL || pstrWFIDrv == NULL) {
		PRINT_WRN(GENERIC_DBG, "No Wireless Priv\n");
		return NOTIFY_DONE;
	}
	PRINT_D(GENERIC_DBG, "dev_state_ev_handler +++\n");

	switch (event) {
	case NETDEV_UP:
		PRINT_D(GENERIC_DBG, "dev_state_ev_handler event=NETDEV_UP\n");

		if (nic->iftype == STATION_MODE || nic->iftype == CLIENT_MODE) {
			pstrWFIDrv->IFC_UP = 1;
			g_obtainingIP = false;
			del_timer(&hDuringIpTimer);
			if(bEnablePS	== true)
					host_int_set_power_mgmt((struct WFIDrvHandle *)pstrWFIDrv, 1, 0);
			PRINT_D(GENERIC_DBG, "IP obtained , enable scan\n");
		}

		
		

		PRINT_D(GENERIC_DBG, "[%s] Up IP\n", dev_iface->ifa_label);

		pIP_Add_buff = (char *) (&(dev_iface->ifa_address));
		PRINT_D(GENERIC_DBG, "IP add=%d:%d:%d:%d\n", pIP_Add_buff[0], pIP_Add_buff[1], pIP_Add_buff[2], pIP_Add_buff[3]);
		host_int_setup_ipaddress((struct WFIDrvHandle *)pstrWFIDrv, pIP_Add_buff, nic->u8IfIdx);
		break;
	case NETDEV_DOWN:
		PRINT_D(GENERIC_DBG, "dev_state_ev_handler event=NETDEV_DOWN\n");

		if (nic->iftype == STATION_MODE || nic->iftype == CLIENT_MODE) {
			pstrWFIDrv->IFC_UP = 0;
			g_obtainingIP = false;
		}

		host_int_set_power_mgmt((struct WFIDrvHandle *)pstrWFIDrv, 0, 0);
		resolve_disconnect_aberration(pstrWFIDrv);
		PRINT_D(GENERIC_DBG, "[%s] Down IP\n", dev_iface->ifa_label);

		pIP_Add_buff = null_ip;
		PRINT_D(GENERIC_DBG, "IP add=%d:%d:%d:%d\n", pIP_Add_buff[0],
			pIP_Add_buff[1], pIP_Add_buff[2], pIP_Add_buff[3]);
		host_int_setup_ipaddress((struct WFIDrvHandle *)pstrWFIDrv,
					 pIP_Add_buff, nic->u8IfIdx);
		break;
	default:
		PRINT_D(GENERIC_DBG, "dev_state_ev_handler [%s] unknown dev event: %lu\n",
			 dev_iface->ifa_label, event);
		break;
	}
	return NOTIFY_DONE;
}
#endif /* DISABLE_PWRSAVE_AND_SCAN_DURING_IP */

/*
 * Interrupt initialization and handling functions
 */
void linux_wlan_enable_irq(void)
{
#if (RX_BH_TYPE != RX_BH_THREADED_IRQ)
#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
	PRINT_D(INT_DBG, "Enabling IRQ ...\n");
	enable_irq(g_linux_wlan->dev_irq_num);
#endif
#endif
}

void linux_wlan_disable_irq(int wait)
{
#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
	if (wait) {
		PRINT_D(INT_DBG, "Disabling IRQ ...\n");
		disable_irq(g_linux_wlan->dev_irq_num);
	} else {
		PRINT_D(INT_DBG, "Disabling IRQ ...\n");
		disable_irq_nosync(g_linux_wlan->dev_irq_num);
	}
#endif
}

#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
static irqreturn_t isr_uh_routine(int irq, void *user_data)
{
PRINT_D(INT_DBG, "Interrupt received UH\n");
#if (RX_BH_TYPE != RX_BH_THREADED_IRQ)
	linux_wlan_disable_irq(IRQ_NO_WAIT);
#endif
    /*While mac is closing cacncel the handling of any interrupts received*/
	if (g_linux_wlan->close) {
		PRINT_ER("Driver is CLOSING: Can't handle UH interrupt\n");
	#if (RX_BH_TYPE == RX_BH_THREADED_IRQ)
		return IRQ_HANDLED;
	#else
		return IRQ_NONE;
	#endif
	}
#if (RX_BH_TYPE == RX_BH_WORK_QUEUE)
	schedule_work(&g_linux_wlan->rx_work_queue);
	return IRQ_HANDLED;
#elif (RX_BH_TYPE == RX_BH_KTHREAD)
	up(&g_linux_wlan->rx_sem);
	return IRQ_HANDLED;
#elif (RX_BH_TYPE == RX_BH_THREADED_IRQ)
	return IRQ_WAKE_THREAD;
#endif
}
#endif

#if (RX_BH_TYPE == RX_BH_WORK_QUEUE || RX_BH_TYPE == RX_BH_THREADED_IRQ)

#if (RX_BH_TYPE == RX_BH_THREADED_IRQ)
irqreturn_t isr_bh_routine(int irq, void *userdata)
{
	struct linux_wlan *nic;

	nic = (struct linux_wlan *)userdata;
#else
static void isr_bh_routine(struct work_struct *work)
{
	struct perInterface_wlan *nic;

	nic = (struct perInterface_wlan *)container_of(work, struct linux_wlan,
						       rx_work_queue);
#endif

	/*While mac is closing cacncel the handling of any interrupts received*/
	if (g_linux_wlan->close) {
		PRINT_ER("Driver is CLOSING: Can't handle BH interrupt\n");
	#if (RX_BH_TYPE == RX_BH_THREADED_IRQ)
		return IRQ_HANDLED;
	#else
		return;
	#endif
	}

	PRINT_D(INT_DBG, "Interrupt received BH\n");
	if (g_linux_wlan->oup.wlan_handle_rx_isr != 0)
		g_linux_wlan->oup.wlan_handle_rx_isr();
	else
		PRINT_ER("wlan_handle_rx_isr() hasn't been initialized\n");


#if (RX_BH_TYPE == RX_BH_THREADED_IRQ)
	return IRQ_HANDLED;
#endif
}
#elif (RX_BH_TYPE == RX_BH_KTHREAD)
static int isr_bh_routine(void *vp)
{
	struct linux_wlan *nic;

	nic = (struct linux_wlan *)vp;

	while (1) {
		while (down_interruptible(&nic->rx_sem))
			;

		if (g_linux_wlan->close) {
			while (!kthread_should_stop())
				schedule();

			break;
		}
		
		PRINT_D(INT_DBG, "Interrupt received BH\n");
		if (g_linux_wlan->oup.wlan_handle_rx_isr != 0)
			g_linux_wlan->oup.wlan_handle_rx_isr();
		else
			PRINT_ER("wlan_handle_rx_isr() hasn't been initialized\n");
	}

	return 0;
}
#endif

#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
static int init_irq(struct linux_wlan *p_nic)
{
	int ret = 0;
	struct linux_wlan *nic = p_nic;

		/*initialize GPIO and register IRQ num
		*GPIO request
		*/
	if ((gpio_request(GPIO_NUM, "WILC_INTR") == 0) &&
	    (gpio_direction_input(GPIO_NUM) == 0)) {
		gpio_export(GPIO_NUM, 1);
		nic->dev_irq_num = OMAP_GPIO_IRQ(GPIO_NUM);
		irq_set_irq_type(nic->dev_irq_num, IRQ_TYPE_LEVEL_LOW);
	} else {
		ret = -1;
		PRINT_ER("could not obtain gpio for WILC_INTR\n");
	}

#if (RX_BH_TYPE == RX_BH_THREADED_IRQ)
	if ((ret != -1) &&
	    (request_threaded_irq(g_linux_wlan->dev_irq_num, isr_uh_routine,
			       isr_bh_routine, IRQF_TRIGGER_LOW | IRQF_ONESHOT,
				 "WILC_IRQ", nic)) < 0) {
#else
		/*Request IRQ*/
	if ((ret != -1) && (request_irq(nic->dev_irq_num, isr_uh_routine,
				     IRQF_TRIGGER_LOW, "WILC_IRQ", nic) < 0)) {
#endif
		PRINT_ER("Failed to request IRQ for GPIO: %d\n", GPIO_NUM);
		ret = -1;
	} else {
		PRINT_D(INT_DBG, "IRQ request succeeded IRQ-NUM= %d on GPIO: %d\n",
			g_linux_wlan->dev_irq_num, GPIO_NUM);
	}

	return ret;
}
#endif

static void deinit_irq(struct linux_wlan *nic)
{
	#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
		/* Deintialize IRQ */
	if (&g_linux_wlan->dev_irq_num != 0) {
		free_irq(g_linux_wlan->dev_irq_num, g_linux_wlan);
		gpio_free(GPIO_NUM);
	}
	#endif
}

static void linux_wlan_mac_indicate(int flag){
	/*I have to do it that way becuase there is no mean to encapsulate device pointer 
	 * as a parameter
	 */
	struct linux_wlan *pd = g_linux_wlan;
	int status;

	if (flag == WILC_MAC_INDICATE_STATUS) {
		pd->oup.wlan_cfg_get_value(WID_STATUS, (u8 *)&status, 4);
		if (pd->mac_status == WILC_MAC_STATUS_INIT) {
			pd->mac_status = status;
			up(&pd->sync_event);
		} else {
			pd->mac_status = status;
		}
	} else if (flag == WILC_MAC_INDICATE_SCAN) {
		PRINT_D(GENERIC_DBG, "Scanning ...\n");
	}
}

/*TicketId1001*/
/* Free buffered eapol allocated in priv struct */
void free_EAP_buff_params(void *pUserVoid)
{
	struct WILC_WFI_priv *priv;

	priv = (struct WILC_WFI_priv *)pUserVoid;

	/*Free allocated memory for buffered frame*/
	if (priv->pStrBufferedEAP != NULL) {
		if (priv->pStrBufferedEAP->pu8buff != NULL) {
			kfree(priv->pStrBufferedEAP->pu8buff);
			priv->pStrBufferedEAP->pu8buff = NULL;
		}
		kfree(priv->pStrBufferedEAP);
		priv->pStrBufferedEAP = NULL;
	}
}

/*
 * TicketId1001
 * Timeout function for a bufferd eapol 1/4
 * The function checks if successful connection is reported to upper layer,
 * then pass buffered eapol 1/4
 */
void EAP_buff_timeout(unsigned long pUserVoid)
{
	u8 null_bssid[ETH_ALEN] = {0};
	static u8 timeout = 5;
	signed int status = ATL_FAIL;
	struct WILC_WFI_priv *priv;

	priv = (struct WILC_WFI_priv *)pUserVoid;

	/*If successful connection is not yet reported, keep waiting*/
	if (!(memcmp(priv->au8AssociatedBss, null_bssid, ETH_ALEN)) && (timeout-- > 0))	{
		hEAPFrameBuffTimer.data = (unsigned long)pUserVoid;
		mod_timer(&hEAPFrameBuffTimer, (jiffies + msecs_to_jiffies(10)));
		return;
	}
	timeout = 5;

	/*Pass frame to upper layer through host interface thread*/
	status = host_int_send_buffered_eap(priv->hWILCWFIDrv
					    , frmw_to_linux
					    , free_EAP_buff_params
					    , priv->pStrBufferedEAP->pu8buff
					    , priv->pStrBufferedEAP->u32Size
					    , priv->pStrBufferedEAP->u32PktOffset
					    , (void *)priv);
	if (status)
		PRINT_ER("Failed so send buffered eap\n");
}

struct net_device *GetIfHandler(uint8_t *pMacHeader)
{
	uint8_t *Bssid, *Bssid1,offset = 10;
	int i = 0;

	Bssid  = pMacHeader + 10;
	Bssid1 = pMacHeader + 4;

	offset = 10;
	for(i=0;i<g_linux_wlan->u8NoIfcs;i++)
	{
		if(g_linux_wlan->strInterfaceInfo[i].u8IfcType == STATION_MODE)
		{
			if(!memcmp(pMacHeader+offset,g_linux_wlan->strInterfaceInfo[i].aBSSID,ETH_ALEN))			
			{
				return g_linux_wlan->strInterfaceInfo[i].wilc_netdev;
			}
		}
	}
	offset = 4;
	for(i=0;i<g_linux_wlan->u8NoIfcs;i++)
	{
		if(g_linux_wlan->strInterfaceInfo[i].u8IfcType == AP_MODE)
		{
			if(!memcmp(pMacHeader+offset,g_linux_wlan->strInterfaceInfo[i].aBSSID,ETH_ALEN))			
			{				
				return g_linux_wlan->strInterfaceInfo[i].wilc_netdev;
			}
		}
	}

	PRINT_WRN(GENERIC_DBG, "Invalide handle\n");
	
	return NULL;
}

int linux_wlan_set_bssid(struct net_device *wilc_netdev, uint8_t *pBSSID, uint8_t mode)
{
	int i = 0;
	int ret = -1;

	PRINT_D(GENERIC_DBG, "set bssid on[%p]\n", wilc_netdev);
	for (i = 0; i < g_linux_wlan->u8NoIfcs; i++) {
		if (g_linux_wlan->strInterfaceInfo[i].wilc_netdev == wilc_netdev) {
			PRINT_D(GENERIC_DBG, "set bssid [%x][%x][%x]\n", pBSSID[0], pBSSID[1], pBSSID[2]);
			memcpy(g_linux_wlan->strInterfaceInfo[i].aBSSID, pBSSID, 6);
			g_linux_wlan->strInterfaceInfo[i].u8IfcType = mode;
			ret = 0;
			break;
		}
	}
	return ret;
}

/* BugID_5213*/
/* Function to get number of connected interfaces */
int linux_wlan_get_num_conn_ifcs(void)
{
	uint8_t i = 0;
	uint8_t null_bssid[6] = {0};
	uint8_t ret_val = 0;

	for (i = 0; i < g_linux_wlan->u8NoIfcs; i++) {
		if (memcmp(g_linux_wlan->strInterfaceInfo[i].aBSSID,
			   null_bssid, 6))
			ret_val++;
	}
	return ret_val;
}

/*TicketId883*/
#ifdef WILC_BT_COEXISTENCE
int linux_wlan_change_bt_coex_mode(u8 u8BtCoexMode)
{
	struct WILC_WFIDrv * pstrWFIDrv=NULL;
	struct WILC_WFI_priv* priv;
	struct net_device * dev;
	uint8_t i = 0;
	
	/*Bug 215*/
	/*Use the firstly intialized and ready interface to send the WID to the firmware*/
	for (i = 0; i < g_linux_wlan->u8NoIfcs; i++)
	{
		dev = g_linux_wlan->strInterfaceInfo[i].wilc_netdev;
		priv = wiphy_priv(dev->ieee80211_ptr->wiphy);
		if(priv == NULL)
		{
			PRINT_ER("No Wireless Priv\n");
			return -1;
		}
		pstrWFIDrv = (struct WILC_WFIDrv *)priv->hWILCWFIDrv;
		if(pstrWFIDrv)
			break;
	}
	
	if(pstrWFIDrv)
		host_int_change_bt_coex_mode((struct WFIDrvHandle*)pstrWFIDrv, u8BtCoexMode);
	else
	{
		PRINT_ER("No driver handler initialized\n");
		return -1;
	}
	
	return 0;
}
#endif /*WILC_BT_COEXISTENCE*/

static int linux_wlan_rxq_task(void *vp)
{
	/* inform wilc_wlan_init that RXQ task is started. */
	up(&g_linux_wlan->rxq_thread_started);
	while (1) {
		while (down_interruptible(&g_linux_wlan->rxq_event))
			;

		if (g_linux_wlan->close) {
			/*Unlock the mutex in the mac_close function to indicate the exiting of the RX thread */
			up(&g_linux_wlan->rxq_thread_started);

			while (!kthread_should_stop())
				schedule();

			PRINT_D(RX_DBG, " RX thread stopped\n");
			break;
		}
		PRINT_D(RX_DBG, "Calling wlan_handle_rx_que()\n");

		g_linux_wlan->oup.wlan_handle_rx_que();
	}
	return 0;
}

#define USE_TX_BACKOFF_DELAY_IF_NO_BUFFERS
static int linux_wlan_txq_task(void *vp)
{
	int ret, txq_count;

#if defined USE_TX_BACKOFF_DELAY_IF_NO_BUFFERS
#define TX_BACKOFF_WEIGHT_INCR_STEP (1)
#define TX_BACKOFF_WEIGHT_DECR_STEP (1)
#define TX_BACKOFF_WEIGHT_MAX (7)
#define TX_BACKOFF_WEIGHT_MIN (0)
#define TX_BACKOFF_WEIGHT_UNIT_MS (10)
	int backoff_weight = TX_BACKOFF_WEIGHT_MIN;
	signed long timeout;
#endif

	up(&g_linux_wlan->txq_thread_started);
	while (1) {
		PRINT_D(TX_DBG, "txq_task Taking a nap\n");
		while (down_interruptible(&g_linux_wlan->txq_event))
			;
		PRINT_D(TX_DBG, "txq_task Who waked me up\n");

		if (g_linux_wlan->close) {
			up(&g_linux_wlan->txq_thread_started);
			while (!kthread_should_stop())
				schedule();

			PRINT_D(TX_DBG, "TX thread stopped\n");
			break;
		}
		PRINT_D(TX_DBG, "txq_task handle the sending packet and let me go to sleep.\n");
#if !defined USE_TX_BACKOFF_DELAY_IF_NO_BUFFERS
		g_linux_wlan->oup.wlan_handle_tx_que();
#else
		do {
			ret = g_linux_wlan->oup.wlan_handle_tx_que(&txq_count);
			if (txq_count < FLOW_CONTROL_LOWER_THRESHOLD) {
				PRINT_D(TX_DBG, "Waking up queue\n");
				if (netif_queue_stopped(g_linux_wlan->strInterfaceInfo[0].wilc_netdev))
					netif_wake_queue(g_linux_wlan->strInterfaceInfo[0].wilc_netdev);
				if (netif_queue_stopped(g_linux_wlan->strInterfaceInfo[1].wilc_netdev))
					netif_wake_queue(g_linux_wlan->strInterfaceInfo[1].wilc_netdev);
			}

			if (ret == WILC_TX_ERR_NO_BUF) {
				timeout = msecs_to_jiffies(TX_BACKOFF_WEIGHT_UNIT_MS << backoff_weight);
				backoff_weight += TX_BACKOFF_WEIGHT_INCR_STEP;
				if (backoff_weight > TX_BACKOFF_WEIGHT_MAX)
					backoff_weight = TX_BACKOFF_WEIGHT_MAX;
			} else	if (backoff_weight > TX_BACKOFF_WEIGHT_MIN) {
				backoff_weight -= TX_BACKOFF_WEIGHT_DECR_STEP;
				if (backoff_weight < TX_BACKOFF_WEIGHT_MIN)
					backoff_weight = TX_BACKOFF_WEIGHT_MIN;
			}
			/*TODO: drop packets after a certain time/number of retry count. */
		} while (ret == WILC_TX_ERR_NO_BUF && !g_linux_wlan->close);
#endif
	}
	return 0;
}

static void linux_wlan_rx_complete(void)
{
	PRINT_D(RX_DBG, "RX completed\n");
}

int linux_wlan_get_firmware(struct perInterface_wlan *p_nic)
{
	struct perInterface_wlan *nic = p_nic;
	int ret = 0;
	const struct firmware *wilc_firmware;
#ifdef DOWNLOAD_BT_FW
	const struct firmware *wilc_bt_firmware;
#endif /* DOWNLOAD_BT_FW */
	char *firmware;

	firmware = WIFI_FIRMWARE;

	if (nic == NULL) {
		PRINT_ER("NIC is NULL\n");
		goto _fail_;
	}

	if (&nic->wilc_netdev->dev == NULL) {
		PRINT_ER("&nic->wilc_netdev->dev  is NULL\n");
		goto _fail_;
	}

	/*	the firmare should be located in /lib/firmware in 
	 *	root file system with the name specified above
	 */
	PRINT_WRN(PWRDEV_DBG, "WLAN firmware: %s\n", firmware);
#ifdef WILC_SDIO
	if (request_firmware(&wilc_firmware, firmware,
			     &g_linux_wlan->wilc_sdio_func->dev) != 0) {
		PRINT_ER("%s - firmare not available\n", firmware);
		ret = -1;
		goto _fail_;
	}
#ifdef DOWNLOAD_BT_FW
	if (request_firmware(&wilc_bt_firmware, BT_FIRMWARE,
			     &g_linux_wlan->wilc_sdio_func->dev) != 0)
		PRINT_ER("%s - firmare not available. Skip!\n", BT_FIRMWARE);

#endif /* DOWNLOAD_BT_FW */
#else
	if (request_firmware(&wilc_firmware, firmware,
			     &g_linux_wlan->wilc_spidev->dev) != 0) {
		PRINT_ER("%s - firmare not available\n", firmware);
		ret = -1;
		goto _fail_;
	}
#ifdef DOWNLOAD_BT_FW
	PRINT_WRN(PWRDEV_DBG, "Bluetooth firmware: %s\n", BT_FIRMWARE);
	if (request_firmware(&wilc_bt_firmware, BT_FIRMWARE,
			     &g_linux_wlan->wilc_spidev->dev) != 0)
		PRINT_ER("%s - firmare not available. Skip\n", BT_FIRMWARE);

#endif /* DOWNLOAD_BT_FW */
#endif /* WILC_SDIO */
	g_linux_wlan->wilc_firmware = wilc_firmware;
#ifdef DOWNLOAD_BT_FW
	g_linux_wlan->wilc_bt_firmware = wilc_bt_firmware;
#endif /* DOWNLOAD_BT_FW */

_fail_:

	return ret;
}

static int linux_wlan_start_firmware(struct perInterface_wlan *nic)
{
	int ret = 0;

	/* start firmware */
	PRINT_D(INIT_DBG, "Starting Firmware ...\n");
	ret = g_linux_wlan->oup.wlan_start();
	if (ret < 0) {
		PRINT_ER("Failed to start Firmware\n");
		goto _fail_;
	}

	/* wait for mac ready */
	PRINT_D(INIT_DBG, "Waiting for Firmware to get ready ...\n");

	/* TicketId908
	* Waiting for 500ms is much more enough for firmware to respond
	*/
	ret = down_timeout(&g_linux_wlan->sync_event, msecs_to_jiffies(500));
	if (ret) {
		PRINT_D(INIT_DBG, "Firmware start timed out\n");
		goto _fail_;
	}
	/*
	 * TODO: Driver shouoldn't wait forever for firmware to get started -
	 * in case of timeout this should be handled properly
	 */
	PRINT_D(INIT_DBG, "Firmware successfully started\n");

_fail_:
	return ret;
}
static int linux_wlan_firmware_download(struct linux_wlan *p_nic)
{
	int ret = 0;

	if (g_linux_wlan->wilc_firmware == NULL) {
		PRINT_ER("Firmware buffer is NULL\n");
		ret = -ENOBUFS;
		goto _FAIL_;
	}
	/* do the firmware download */
	PRINT_D(INIT_DBG, "Downloading Firmware ...\n");
	ret = g_linux_wlan->oup.wlan_firmware_download(g_linux_wlan->wilc_firmware->data,
						       g_linux_wlan->wilc_firmware->size);
	if (ret < 0)
		goto _FAIL_;

	PRINT_D(INIT_DBG, "Download Succeeded\n");

_FAIL_:
	return ret;
}

#ifdef DOWNLOAD_BT_FW
static int linux_bt_start_firmware(struct perInterface_wlan *nic)
{
	int ret = 0;
	/* start firmware */
	PRINT_D(INIT_DBG, "Starting BT Firmware ...\n");
	ret = g_linux_wlan->oup.bt_start();
	if (ret < 0) {
		PRINT_ER("Failed to start BT Firmware\n");
		goto _fail_;
	}

	/*
	 *	TODO: Driver shouoldn't wait forever for firmware to get started -
	 *	in case of timeout this should be handled properly
	 */
	PRINT_D(INIT_DBG, "BT Firmware successfully started\n");

_fail_:
	return ret;
}

static int linux_bt_firmware_download(void)
{
	int ret = 0;

	if (g_linux_wlan->wilc_bt_firmware == NULL) {
		PRINT_ER("BT Firmware buffer is NULL\n");
		ret = -ENOBUFS;
		goto _FAIL_;
	}
	/* do the firmware download */
	PRINT_D(INIT_DBG, "Downloading BT Firmware ...\n");
	ret = g_linux_wlan->oup.bt_firmware_download(g_linux_wlan->wilc_bt_firmware->data,
						     g_linux_wlan->wilc_bt_firmware->size);
	if (ret < 0)
		goto _FAIL_;

	/* Freeing FW buffer */
	PRINT_D(GENERIC_DBG, "Releasing BT firmware\n");
	release_firmware(g_linux_wlan->wilc_bt_firmware);
	g_linux_wlan->wilc_bt_firmware = NULL;

	PRINT_D(INIT_DBG, "BT Download Succeeded\n");

_FAIL_:
	return ret;
}
#endif

/* startup configuration - could be changed later using iconfig*/
static int linux_wlan_init_test_config(struct net_device *dev, struct linux_wlan *p_nic)
{
	u8 c_val[64];
	

	/*BugID_5077*/
	struct WILC_WFI_priv *priv;
	struct WILC_WFIDrv *pstrWFIDrv;
	struct perInterface_wlan *nic;
	nic = netdev_priv(dev);
	PRINT_D(TX_DBG, "Start configuring Firmware\n");

	priv = wiphy_priv(dev->ieee80211_ptr->wiphy);
	pstrWFIDrv = (struct WILC_WFIDrv *)priv->hWILCWFIDrv;
	PRINT_D(INIT_DBG, "Host = %x\n",(unsigned int)pstrWFIDrv);
	wilc_get_chipid(0);

	if (g_linux_wlan->oup.wlan_cfg_set == NULL) {
		PRINT_ER("Null p[ointer\n");
		goto _fail_;
	}

	*(int *)c_val = (unsigned int)nic->iftype;
	
	if (!g_linux_wlan->oup.wlan_cfg_set(1, WID_SET_OPERATION_MODE, c_val,
					    4, 0, 0))
		goto _fail_;

	/*to tell fw that we are going to use PC test - WILC specific*/
	c_val[0] = 0;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_PC_TEST_MODE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = INFRASTRUCTURE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_BSS_TYPE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = RATE_AUTO;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_CURRENT_TX_RATE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = G_MIXED_11B_2_MODE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11G_OPERATING_MODE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = 1;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_CURRENT_CHANNEL, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = G_SHORT_PREAMBLE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_PREAMBLE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = AUTO_PROT;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_PROT_MECH, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = ACTIVE_SCAN;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_SCAN_TYPE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = SITE_SURVEY_OFF;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_SITE_SURVEY, c_val,
					    1, 0, 0))
		goto _fail_;

	/* Never use RTS-CTS */
	*((int *)c_val) = 0xffff;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_RTS_THRESHOLD, c_val,
					    2, 0, 0))
		goto _fail_;

	*((int *)c_val) = 2346;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_FRAG_THRESHOLD, c_val,
					    2, 0, 0))
		goto _fail_;

	c_val[0] = 0;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_BCAST_SSID, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = 1;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_QOS_ENABLE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = NO_POWERSAVE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_POWER_MANAGEMENT, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = NO_ENCRYPT;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11I_MODE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = OPEN_SYSTEM;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_AUTH_TYPE, c_val, 1, 0, 0))
		goto _fail_;

/*  WEP/802 11I Configuration
 *  Configuration : WEP Key
 *  Values (0x)   : 5 byte for WEP40 and 13 bytes for WEP104
 *                  In case more than 5 bytes are passed on for WEP 40
 *                  only first 5 bytes will be used as the key
 */

	strcpy(c_val, "123456790abcdef1234567890");
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_WEP_KEY_VALUE, c_val,
					    (strlen(c_val) + 1), 0, 0))
		goto _fail_;

/*  WEP/802 11I Configuration
 *  Configuration : AES/TKIP WPA/RSNA Pre-Shared Key
 *  Values to set : Any string with length greater than equal to 8 bytes
 *                  and less than 64 bytes
 */
	strcpy(c_val, "12345678");
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11I_PSK, c_val,
					    (strlen(c_val)), 0, 0))
		goto _fail_;

/*  IEEE802.1X Key Configuration
 *  Configuration : Radius Server Access Secret Key
 *  Values to set : Any string with length greater than equal to 8 bytes
 *                  and less than 65 bytes
 */
	strcpy(c_val, "password");
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_1X_KEY, c_val,
					   (strlen(c_val) + 1), 0, 0))
		goto _fail_;

/*   IEEE802.1X Server Address Configuration
 *  Configuration : Radius Server IP Address
 *  Values to set : Any valid IP Address
 */
	c_val[0] = 192;
	c_val[1] = 168;
	c_val[2] = 1;
	c_val[3] = 112;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_1X_SERV_ADDR, c_val,
					    4, 0, 0))
		goto _fail_;

	c_val[0] = 3;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_LISTEN_INTERVAL, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = 3;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_DTIM_PERIOD, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = NORMAL_ACK;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_ACK_POLICY, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = 0;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_USER_CONTROL_ON_TX_POWER,
					    c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = 48;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_TX_POWER_LEVEL_11A, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = 28;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_TX_POWER_LEVEL_11B, c_val,
					    1, 0, 0))
		goto _fail_;

/*  Beacon Interval
 *  Configuration : Sets the beacon interval value
 *  Values to set : Any 16-bit value
 */

	*((int *)c_val) = 100;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_BEACON_INTERVAL, c_val,
					    2, 0, 0))
		goto _fail_;

	c_val[0] = REKEY_DISABLE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_REKEY_POLICY, c_val,
					    1, 0, 0))
		goto _fail_;

/*  Rekey Time (s) (Used only when the Rekey policy is 2 or 4)
 *  Configuration : Sets the Rekey Time (s)
 *  Values to set : 32-bit value
 */
	*((int *)c_val) = 84600;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_REKEY_PERIOD, c_val,
					    4, 0, 0))
		goto _fail_;

/*  Rekey Packet Count (in 1000s; used when Rekey Policy is 3)
 *  Configuration : Sets Rekey Group Packet count
 *  Values to set : 32-bit Value
 */
	*((int *)c_val) = 500;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_REKEY_PACKET_COUNT,
					    c_val, 4, 0, 0))
		goto _fail_;

	c_val[0] = 1;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_SHORT_SLOT_ALLOWED,
					    c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = G_SELF_CTS_PROT;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_ERP_PROT_TYPE, c_val,
					    1, 0, 0))
		goto _fail_;

	/* Enable N */	
	c_val[0] = 1;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_ENABLE, c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = HT_MIXED_MODE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_OPERATING_MODE, c_val,
					    1, 0, 0))
		goto _fail_;

	/* TXOP Prot disable in N mode: No RTS-CTS on TX A-MPDUs to save air-time. */
	c_val[0] = 1;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_TXOP_PROT_DISABLE,
					    c_val, 1, 0, 0))
		goto _fail_;

	/* AP only */
	c_val[0] = DETECT_PROTECT_REPORT;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_OBSS_NONHT_DETECTION,
					    c_val, 1, 0, 0))
		goto _fail_;

	c_val[0] = RTS_CTS_NONHT_PROT;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_HT_PROT_TYPE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = 0;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_RIFS_PROT_ENABLE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = MIMO_MODE;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_SMPS_MODE, c_val,
					    1, 0, 0))
		goto _fail_;

	c_val[0] = 7;
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_CURRENT_TX_MCS, c_val,
					    1, 0, 0))
		goto _fail_;

	
#ifdef WILC_BT_COEXISTENCE
	/*TicketId842*/
	/*If Hostspot is turning on,  set COEX_FORCE_WIFI mode.*/
	if(nic->iftype == AP_MODE)
	{
		/* Disable coexistence in the initialization */
		c_val[0] = COEX_FORCE_WIFI;
		if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_BT_COEX_MODE, c_val, 1, 0, 0))
			goto _fail_;
	}
#endif /* WILC_BT_COEXISTENCE */
	c_val[0] = 1; /* Enable N with immediate block ack. */
	/* changed from zero to 1 */
	if (!g_linux_wlan->oup.wlan_cfg_set(0, WID_11N_IMMEDIATE_BA_ENABLED, c_val, 1, 1,0))
		goto _fail_;
	return 0;

_fail_:
	return -1;
}

void wilc_wlan_deinit(struct linux_wlan *nic)
{
	int ret = 0;
	
	if (g_linux_wlan->wilc_initialized) {
		PRINT_D(INIT_DBG, "Deinitializing wilc  ...\n");

		if (nic == NULL) {
			PRINT_ER("nic is NULL\n");
			return;
		}

		PRINT_D(INIT_DBG, "Disabling IRQ\n");
#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
		linux_wlan_disable_irq(IRQ_WAIT);
#endif

		/* not sure if the following unlocks are needed or not*/
		if (&g_linux_wlan->rxq_event != NULL)
			up(&g_linux_wlan->rxq_event);

		if (&g_linux_wlan->txq_event != NULL)
			up(&g_linux_wlan->txq_event);


#if (RX_BH_TYPE == RX_BH_WORK_QUEUE)
		/*Removing the work struct from the linux kernel workqueue*/
		if (&g_linux_wlan->rx_work_queue != NULL)
			flush_work(&g_linux_wlan->rx_work_queue);
#endif

		PRINT_D(INIT_DBG, "Deinitializing Threads\n");
		wlan_deinitialize_threads(nic);

		PRINT_D(INIT_DBG, "Deinitializing IRQ\n");
		deinit_irq(g_linux_wlan);

		if (&g_linux_wlan->oup != NULL)
			if (g_linux_wlan->oup.wlan_stop != NULL)
			{
				ret = g_linux_wlan->oup.wlan_stop();
				if(ret == 0)
				{
					PRINT_ER("failed in wlan_stop\n");
				}
			}

		PRINT_D(INIT_DBG, "Deinitializing WILC Wlan\n");
		at_wlan_deinit(nic);
#if (defined WILC_SDIO) && (!defined WILC_SDIO_IRQ_GPIO)
    	PRINT_D(INIT_DBG,"Disabling IRQ 2\n");
		mutex_lock(g_linux_wlan->hif_cs);
		disable_sdio_interrupt();
		mutex_unlock(g_linux_wlan->hif_cs);
#endif

		/*De-Initialize locks*/
		PRINT_D(INIT_DBG, "Deinitializing Locks\n");
		wlan_deinit_locks(g_linux_wlan);

		/* announce that wilc is not initialized */
		g_linux_wlan->wilc_initialized = 0;

		PRINT_D(INIT_DBG, "wilc deinitialization Done\n");
	} else {
		PRINT_D(INIT_DBG, "wilc is not initialized\n");
	}
}

int wlan_init_locks(struct linux_wlan *p_nic)
{
	PRINT_D(INIT_DBG, "Initializing Locks ...\n");

	/*initialize mutexes*/
	g_linux_wlan->hif_cs = at_pwr_dev_get_bus_lock();
	mutex_init(&g_linux_wlan->rxq_cs);
	mutex_init(&g_linux_wlan->txq_cs);

	spin_lock_init(&g_linux_wlan->txq_spinlock);

	sema_init(&g_linux_wlan->txq_add_to_head_cs, 1);
	sema_init(&g_linux_wlan->txq_event, 0);
	sema_init(&g_linux_wlan->rxq_event, 0);
	sema_init(&g_linux_wlan->cfg_event, 0);
	sema_init(&g_linux_wlan->sync_event, 0);
	sema_init(&g_linux_wlan->rxq_thread_started, 0);
	sema_init(&g_linux_wlan->txq_thread_started, 0);
	sema_init(&g_linux_wlan->wdt_thread_sem, 0);

#if (RX_BH_TYPE == RX_BH_KTHREAD)
	sema_init(&g_linux_wlan->rx_sem, 0);
#endif

	return 0;
}

static int wlan_deinit_locks(struct linux_wlan *nic)
{
	PRINT_D(INIT_DBG, "De-Initializing Locks\n");

	if (&g_linux_wlan->rxq_cs != NULL)
		mutex_destroy(&g_linux_wlan->rxq_cs);

	if (&g_linux_wlan->txq_cs != NULL)
		mutex_destroy(&g_linux_wlan->txq_cs);

	return 0;
}

void linux_to_wlan(struct wilc_wlan_inp *nwi, struct linux_wlan *nic)
{
	PRINT_D(INIT_DBG, "Linux to Wlan services ...\n");

	nwi->os_context.hif_critical_section = (void *)g_linux_wlan->hif_cs;
	nwi->os_context.os_private = (void *)nic;
	nwi->os_context.tx_buffer_size = LINUX_TX_SIZE;
	nwi->os_context.txq_critical_section = (void *)&g_linux_wlan->txq_cs;
	nwi->os_context.txq_add_to_head_critical_section =
				   (void *)&g_linux_wlan->txq_add_to_head_cs;
	nwi->os_context.txq_spin_lock = (void *)&g_linux_wlan->txq_spinlock;
	nwi->os_context.txq_wait_event = (void *)&g_linux_wlan->txq_event;
#ifdef MEMORY_STATIC
	nwi->os_context.rx_buffer_size = LINUX_RX_SIZE;
#endif
	nwi->os_context.rxq_critical_section = (void *)&g_linux_wlan->rxq_cs;
	nwi->os_context.rxq_wait_event = (void *)&g_linux_wlan->rxq_event;
	nwi->os_context.cfg_wait_event = (void *)&g_linux_wlan->cfg_event;

#ifdef WILC_SDIO
	nwi->io_func.io_type = HIF_SDIO;
#else
	nwi->io_func.io_type = HIF_SPI;
#endif


	nwi->net_func.rx_indicate = frmw_to_linux;

	nwi->net_func.rx_complete = linux_wlan_rx_complete;
	nwi->indicate_func.mac_indicate = linux_wlan_mac_indicate;
}

int wlan_initialize_threads(struct perInterface_wlan *nic)
{
	int ret = 0;

	PRINT_D(INIT_DBG, "Initializing Threads ...\n");

#if (RX_BH_TYPE == RX_BH_WORK_QUEUE)
	/*Initialize rx work queue task*/
	INIT_WORK(&g_linux_wlan->rx_work_queue, isr_bh_routine);
#elif (RX_BH_TYPE == RX_BH_KTHREAD)
	PRINT_D(INIT_DBG, "Creating kthread for Rxq BH\n");
	g_linux_wlan->rx_bh_thread = kthread_run(isr_bh_routine,
					     (void *)g_linux_wlan, "K_RXQ_BH");
	if (g_linux_wlan->rx_bh_thread == 0) {
		PRINT_ER("couldn't create RX BH thread\n");
		ret = -ENOBUFS;
		goto _fail_;
	}
#endif

#ifndef TCP_ENHANCEMENTS
	PRINT_D(INIT_DBG, "Creating kthread for reception\n");
	g_linux_wlan->rxq_thread = kthread_run(linux_wlan_rxq_task,
					   (void *)g_linux_wlan, "K_RXQ_TASK");
	if (g_linux_wlan->rxq_thread == 0) {
		PRINT_ER("couldn't create RXQ thread\n");
		ret = -ENOBUFS;
		goto _fail_1;
	}

	while (down_interruptible(&g_linux_wlan->rxq_thread_started))
		;

#endif

	/* create tx task */
	PRINT_D(INIT_DBG, "Creating kthread for transmission\n");
	g_linux_wlan->txq_thread = kthread_run(linux_wlan_txq_task,
					   (void *)g_linux_wlan, "K_TXQ_TASK");
	if (g_linux_wlan->txq_thread == 0) {
		PRINT_ER("couldn't create TXQ thread\n");
		ret = -ENOBUFS;
		goto _fail_2;
	}

	while (down_interruptible(&g_linux_wlan->txq_thread_started))
		;

	if (bDebugThreadRunning == 0) {
		PRINT_D(INIT_DBG, "Creating kthread for Debugging\n");
		g_linux_wlan->wdt_thread = kthread_run(DebuggingThreadTask,
					  (void *)g_linux_wlan, "DebugThread");
		if (g_linux_wlan->wdt_thread == 0) {
			PRINT_ER("couldn't create DebugThread\n");
			ret = -ENOBUFS;
			goto _fail_3;
		}
		bDebugThreadRunning = 1;
		while (down_interruptible(&g_linux_wlan->wdt_thread_sem))
			;
	}

	return 0;

	/*TicketId1003*/
	/*De-Initialize 3rd thread*/
_fail_3:
	g_linux_wlan->close = 1;
	up(&g_linux_wlan->txq_event);
	kthread_stop(g_linux_wlan->txq_thread);

_fail_2:
	/*De-Initialize 2nd thread*/
	g_linux_wlan->close = 1;
#ifndef TCP_ENHANCEMENTS
	up(&g_linux_wlan->rxq_event);
	kthread_stop(g_linux_wlan->rxq_thread);
#endif /* TCP_ENHANCEMENTS */

#ifndef TCP_ENHANCEMENTS
_fail_1:
#endif
	g_linux_wlan->close = 1;
#if (RX_BH_TYPE == RX_BH_KTHREAD)
		/*De-Initialize 1st thread*/
	up(&g_linux_wlan->rx_sem);
	kthread_stop(g_linux_wlan->rx_bh_thread);
#endif
#if (RX_BH_TYPE == RX_BH_KTHREAD)
_fail_:
	g_linux_wlan->close = 1;
#endif
	return ret;
}

static void wlan_deinitialize_threads(struct linux_wlan *nic)
{
	/*TicketId1003*/
	PRINT_D(INIT_DBG, "Deinitializing Threads\n");
	if (!gbCrashRecover) {
		PRINT_D(INIT_DBG, "Deinitializing debug Thread\n");
		bDebugThreadRunning = 0;
		if (&g_linux_wlan->wdt_thread_sem != NULL)
			up(&g_linux_wlan->wdt_thread_sem);
		if (nic->wdt_thread != NULL) {
			kthread_stop(nic->wdt_thread);
			nic->wdt_thread = NULL;
		}
	}

	g_linux_wlan->close = 1;

#ifndef TCP_ENHANCEMENTS
	if (&g_linux_wlan->rxq_event != NULL)
		up(&g_linux_wlan->rxq_event);

	if (g_linux_wlan->rxq_thread != NULL) {
		kthread_stop(g_linux_wlan->rxq_thread);
		g_linux_wlan->rxq_thread = NULL;
	}
#endif /* TCP_ENHANCEMENTS */

	if (&g_linux_wlan->txq_event != NULL)
		up(&g_linux_wlan->txq_event);

	if (g_linux_wlan->txq_thread != NULL) {
		kthread_stop(g_linux_wlan->txq_thread);
		g_linux_wlan->txq_thread = NULL;
	}

#if (RX_BH_TYPE == RX_BH_KTHREAD)
	if (&g_linux_wlan->rx_sem != NULL)
		up(&g_linux_wlan->rx_sem);

	if (g_linux_wlan->rx_bh_thread != NULL) {
		kthread_stop(g_linux_wlan->rx_bh_thread);
		g_linux_wlan->rx_bh_thread = NULL;
	}
#endif
}

/* Release firmware after downloading and starting it */
void linux_wlan_free_firmware(void)
{
	if (g_linux_wlan->wilc_firmware == NULL) {
		PRINT_ER("Firmware not found!\n");
		return;
	}
	PRINT_D(INIT_DBG, "Releasing firmware\n");
	release_firmware(g_linux_wlan->wilc_firmware);
	g_linux_wlan->wilc_firmware = NULL;
}

int is_wilc3000_initalized(void)
{
	return g_linux_wlan->wilc_initialized ;
}

int wilc_wlan_init(struct net_device *dev, struct perInterface_wlan *p_nic)
{
	struct wilc_wlan_inp nwi;
	struct wilc_wlan_oup nwo;
	struct perInterface_wlan *nic = p_nic;
	int ret = 0;
	int timeout = 5;

	if (!g_linux_wlan->wilc_initialized) {
		g_linux_wlan->mac_status = WILC_MAC_STATUS_INIT;
		g_linux_wlan->close = 0;
		g_linux_wlan->wilc_initialized = 0;

		wlan_init_locks(g_linux_wlan);

		linux_to_wlan(&nwi, g_linux_wlan);

		ret = at_wlan_init(&nwi, &nwo);
		if (ret < 0) {
			PRINT_ER("Initializing WILC_Wlan FAILED\n");
			ret = -EIO;
			goto _fail_locks_;
		}
		PRINT_D(GENERIC_DBG, "WILC Initialization done\n");
		memcpy(&g_linux_wlan->oup, &nwo, sizeof(struct wilc_wlan_oup));

		/* Save the oup structre into global pointer */
		gpstrWlanOps = &g_linux_wlan->oup;

		ret = wlan_initialize_threads(nic);
		if (ret < 0) {
			PRINT_ER("Initializing Threads FAILED\n");
			ret = -EIO;
			goto _fail_wilc_wlan_;
		}

#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
		if (init_irq(g_linux_wlan)) {
			PRINT_ER("couldn't initialize IRQ\n");
			ret = -EIO;
			goto _fail_threads_;
		}
#endif

#if (defined WILC_SDIO) && (!defined WILC_SDIO_IRQ_GPIO)
		if (enable_sdio_interrupt(wilc_handle_isr)) {
			PRINT_ER("couldn't initialize IRQ\n");
			ret = -EIO;
			goto _fail_irq_init_;
		}
#endif

		if (linux_wlan_get_firmware(nic)) {
			PRINT_ER("Can't get firmware\n");
			ret = -EIO;
			goto _fail_irq_enable_;
		}

/* TicketId908
 * Keep trying to download+start firmware in case of failures
 * This to workaround problem of firmware startup being stuck somewhere in turing_on_rf_blocks
 */
		do {
			/*Download firmware*/
			ret = linux_wlan_firmware_download(g_linux_wlan);
			if (ret < 0) {
				PRINT_ER("Failed to download firmware\n");
				/* Freeing FW buffer */
				linux_wlan_free_firmware();

				ret = -EIO;
				goto _fail_irq_enable_;
			}

			/* Start firmware*/
			ret = linux_wlan_start_firmware(nic);
			if (ret < 0) {
				PRINT_ER("Failed to start firmware - timeout = %d\n", timeout);
				ret = -EIO;
				if (timeout-- == 0) {
					/* Freeing FW buffer */
					linux_wlan_free_firmware();
					goto _fail_irq_enable_;
				}
			}
		} while (ret == -EIO);

		/* Freeing FW buffer */
		linux_wlan_free_firmware();

#ifdef DOWNLOAD_BT_FW
		/*Download BT firmware*/
		ret = linux_bt_firmware_download();
		if (ret < 0) {
			PRINT_ER("Failed to download BT firmware\n");
		} else {
			/* Start BT firmware*/
			ret = linux_bt_start_firmware(nic);
			if (ret < 0)
				PRINT_ER("Failed to start BT firmware\n");
		}

#endif /* DOWNLOAD_BT_FW */
		if (g_linux_wlan->oup.wlan_cfg_get(1, WID_FIRMWARE_VERSION, 1,
						   0)) {
			int size;
			char Firmware_ver[50];

			size = g_linux_wlan->oup.wlan_cfg_get_value(
					WID_FIRMWARE_VERSION,
					Firmware_ver, sizeof(Firmware_ver));
			Firmware_ver[size] = '\0';
			PRINT_D(GENERIC_DBG, "**** Firmware Ver = %s ****\n", Firmware_ver);
		}
		/* Initialize firmware with default configuration */
		ret = linux_wlan_init_test_config(dev, g_linux_wlan);

		if (ret < 0) {
			PRINT_ER("Failed to configure firmware\n");
			ret = -EIO;
			goto _fail_fw_start_;
		}

		g_linux_wlan->wilc_initialized = 1;
		return 0;

_fail_fw_start_:
		if (&g_linux_wlan->oup != NULL)
			if (g_linux_wlan->oup.wlan_stop != NULL)
				g_linux_wlan->oup.wlan_stop();

_fail_irq_enable_:
#if (defined WILC_SDIO) && (!defined WILC_SDIO_IRQ_GPIO)
		disable_sdio_interrupt();
#endif
_fail_irq_init_:
#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
		deinit_irq(g_linux_wlan);
#endif
#if (!defined WILC_SDIO) || (defined WILC_SDIO_IRQ_GPIO)
_fail_threads_:
#endif
		wlan_deinitialize_threads(g_linux_wlan);
_fail_wilc_wlan_:
		at_wlan_deinit(g_linux_wlan);
_fail_locks_:
		wlan_deinit_locks(g_linux_wlan);
		PRINT_ER("WLAN Iinitialization FAILED\n");
	} else {
		PRINT_D(INIT_DBG, "wilc already initialized\n");
	}
	return ret;
}

int mac_init_fn(struct net_device *ndev)
{
	netif_start_queue(ndev);
	netif_stop_queue(ndev);
	return 0;
}

	/* TODO: get MAC address whenever the source is EPROM - hardcoded and copy it to ndev*/
void WILC_WFI_frame_register(struct wiphy *wiphy, struct net_device *dev,
				  u16 frame_type, bool reg);

/* This fn is called, when this device is setup using ifconfig */
int mac_open(struct net_device *ndev)
{
	struct perInterface_wlan *nic;

	u8 mac_add[ETH_ALEN] = {0};
	#ifndef HW_HAS_EFUSED_MAC_ADDR
	unsigned char mac_address[NUM_CONCURRENT_IFC][ETH_ALEN] = {{0x00, 0x80, 0xC2, 0x5E, 0xa2, 0x01}	/*IFC_0 mac address*/
															, {0x00, 0x80, 0xC2, 0x5E, 0xa2, 0x02}};	/*IFC_1 mac address*/
	#endif	
	int ifc;
	int ret = 0;
	int i = 0;
	static int count = 0;
	struct WILC_WFI_priv *priv;

	nic = netdev_priv(ndev);
	priv = wiphy_priv(nic->wilc_netdev->ieee80211_ptr->wiphy);
	PRINT_D(GENERIC_DBG, "MAC OPEN[%p] %s\n",ndev, ndev->name);

	if (!gbCrashRecover) {
		ret = WILC_WFI_InitHostInt(ndev);
		if (ret < 0) {
			PRINT_ER("Failed to initialize host interface\n");

			return ret;
		}
	}

	/*initialize platform*/
	ret = wilc_wlan_init(ndev, nic);
	if (ret < 0) {
		PRINT_ER("Failed to initialize wilc\n");
		/*If recovering from a crash, then actually host interface was not reinitializaed, so don't re-deinit it*/
		if(!gbCrashRecover)
		{
			WILC_WFI_DeInitHostInt(ndev);
		}
		return ret;
	}

	

/*TicketId1003
 *Reset the recovery flag here to allow getting mac address and registering frames
 */
	g_bWaitForRecovery = 0;
	if(!(memcmp(ndev->name, IFC_0, sizeof(IFC_0))))
		ifc = 0;
	else if(!(memcmp(ndev->name, IFC_1, sizeof(IFC_1))))
		ifc = 1;
	else
	{
		PRINT_D(INIT_DBG, "Unknown interface name\n");
		ret = -EINVAL;
		goto _err_;
	}
	host_int_set_wfi_drv_handler((unsigned int)priv->hWILCWFIDrv, nic->iftype, ndev->name);
	#ifndef HW_HAS_EFUSED_MAC_ADDR
	PRINT_D(INIT_DBG, "HW doesn't have Efused mac address, set mac address from host\n");
	host_int_set_MacAddress(priv->hWILCWFIDrv, mac_address[ifc]);
	#endif
	host_int_get_MacAddress(priv->hWILCWFIDrv, mac_add);
	PRINT_D(INIT_DBG, "Mac address: %x:%x:%x:%x:%x:%x\n", mac_add[0], mac_add[1],
		 mac_add[2], mac_add[3], mac_add[4], mac_add[5]);
	
	memcpy(g_linux_wlan->strInterfaceInfo[ifc].aSrcAddress, mac_add, ETH_ALEN);
	g_linux_wlan->strInterfaceInfo[ifc].drvHandler = (unsigned int)priv->hWILCWFIDrv;

	/* TODO: get MAC address whenever the source is EPROM - hardcoded and copy it to ndev*/
	memcpy(ndev->dev_addr, g_linux_wlan->strInterfaceInfo[ifc].aSrcAddress,
	       ETH_ALEN);

	if (!is_valid_ether_addr(ndev->dev_addr)) {
		PRINT_ER("Error: Wrong MAC address\n");
		ret = -EINVAL;
		goto _err_;
	}

	WILC_WFI_frame_register(nic->wilc_netdev->ieee80211_ptr->wiphy,
				nic->wilc_netdev,
				nic->g_struct_frame_reg[0].frame_type,
				nic->g_struct_frame_reg[0].reg);
	WILC_WFI_frame_register(nic->wilc_netdev->ieee80211_ptr->wiphy,
				nic->wilc_netdev,
				nic->g_struct_frame_reg[1].frame_type,
				nic->g_struct_frame_reg[1].reg);
	netif_wake_queue(ndev);
	g_linux_wlan->open_ifcs++;
	nic->mac_opened = 1;
	
	return 0;

_err_:
	WILC_WFI_DeInitHostInt(ndev);
	wilc_wlan_deinit(g_linux_wlan);
	return ret;
}

struct net_device_stats *mac_stats(struct net_device *dev)
{
	struct perInterface_wlan *nic = netdev_priv(dev);

	return &nic->netstats;
}

/* Setup the multicast filter */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
static void wilc_set_multicast_list(struct net_device *dev)
{
	struct netdev_hw_addr *ha;
	struct WILC_WFI_priv *priv;
	struct WILC_WFIDrv *pstrWFIDrv;
	int i = 0;

	priv = wiphy_priv(dev->ieee80211_ptr->wiphy);
	pstrWFIDrv = (struct WILC_WFIDrv *)priv->hWILCWFIDrv;

	if (!dev)
		return;

	PRINT_D(INIT_DBG,"Setting Multicast List with count = %d. \n",dev->mc.count);
	if (dev->flags & IFF_PROMISC) {
	/* Normally, we should configure the chip to retrive all packets
	 * but we don't wanna support this right now
	 * TODO: add promiscuous mode support
	 */
		PRINT_D(INIT_DBG, "Set promiscuous mode ON, retrive all packets\n");
		return;
	}

	/* If there's more addresses than we handle, get all multicast
	packets and sort them out in software. */
	if ((dev->flags & IFF_ALLMULTI) || (dev->mc.count) > WILC_MULTICAST_TABLE_SIZE) {
		PRINT_D(INIT_DBG, "Disable multicast filter, retrive all multicast packets\n");
	    /* get all multicast packets*/
		host_int_setup_multicast_filter((struct WFIDrvHandle *)pstrWFIDrv, false, 0);
		return;
	}

   	 /* No multicast?  Just get our own stuff */
	if ((dev->mc.count) == 0) {
		PRINT_D(INIT_DBG, "Enable multicast filter, retrive directed packets only.\n");
		host_int_setup_multicast_filter((struct WFIDrvHandle *)pstrWFIDrv, true, 0);
		return;
	}

	netdev_for_each_mc_addr(ha, dev) {
		memcpy(gau8MulticastMacAddrList[i], ha->addr, ETH_ALEN);
		PRINT_D(INIT_DBG, "Entry[%d]: %x:%x:%x:%x:%x:%x\n", i,
			gau8MulticastMacAddrList[i][0],
			gau8MulticastMacAddrList[i][1],
			gau8MulticastMacAddrList[i][2],
			gau8MulticastMacAddrList[i][3],
			gau8MulticastMacAddrList[i][4],
			gau8MulticastMacAddrList[i][5]);
		i++;
	}

	host_int_setup_multicast_filter((struct WFIDrvHandle *)pstrWFIDrv,
					true, (dev->mc.count));
}
#else
static void wilc_set_multicast_list(struct net_device *dev)
{
	struct dev_mc_list *mc_ptr;
	int i = 0;

	if (!dev)
		return;

	PRINT_D(INIT_DBG, "Setting Multicast List.\n");
	PRINT_D(INIT_DBG, ("dev->mc_count = %d\n", dev->mc_count);

	if (dev->flags & IFF_PROMISC) {
		/* 
		 * Normally, we should configure the chip to retrive all packets
		 * but we don't wanna support this right now
		 * TODO: add promiscuous mode support
		 */
		PRINT_D(INIT_DBG, "Set promiscuous mode ON, retrive all packets\n");
		return;
	}

	/* 
	 * If there's more addresses than we handle, get all multicast
	 * packets and sort them out in software.
	 */
	if ((dev->flags & IFF_ALLMULTI) || (dev->mc_count > WILC_MULTICAST_TABLE_SIZE)) {
		PRINT_D(INIT_DBG, "Disable multicast filter, retrive all multicast packets\n");
		host_int_setup_multicast_filter((struct WFIDrvHandle *)gWFiDrvHandle, false, 0);
		return;
	}

    /* No multicast?  Just get our own stuff */
	if (dev->mc_count == 0) {
		PRINT_D(INIT_DBG, "Enable multicast filter, retrive directed packets only.\n");
		host_int_setup_multicast_filter((struct WFIDrvHandle *)gWFiDrvHandle, true, 0);
		return;
	}
    /* Store all of the multicast addresses in the hardware filter */

	for (mc_ptr = dev->mc_list; mc_ptr; mc_ptr = mc_ptr->next, i++) {
		memcpy(gau8MulticastMacAddrList[i], mc_ptr->dmi_addr, ETH_ALEN);
		i++;
	}

	host_int_setup_multicast_filter((struct WFIDrvHandle *)gWFiDrvHandle,
					 true, (dev->mc_count));
}
#endif

static void linux_wlan_tx_complete(void *priv, int status)
{
	struct tx_complete_data *pv_data = (struct tx_complete_data *)priv;

	if (status == 1)
		PRINT_D(TX_DBG, "Packet sent successfully-Size= %d\n", pv_data->size);
	else
		PRINT_D(TX_DBG, "Couldn't send packet\n");
   	 /* Free the SK Buffer, its work is done */
	dev_kfree_skb(pv_data->skb);
	kfree(pv_data);
}

int mac_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct perInterface_wlan *nic;
	struct tx_complete_data *tx_data = NULL;
	int QueueCount;
	char *pu8UdpBuffer;
	struct iphdr *ih;
	struct ethhdr *eth_h;

	nic = netdev_priv(ndev);

	PRINT_D(TX_DBG, "Sending packet just received from TCP/IP\n");

	/* Stop the network interface queue */
	if (skb->dev != ndev) {
		PRINT_ER("Packet not destined to this device\n");
		return 0;
	}

	tx_data = kmalloc(sizeof(struct tx_complete_data), GFP_ATOMIC);
	if (tx_data == NULL) {
		dev_kfree_skb(skb);
		netif_wake_queue(ndev);
		return 0;
	}

	tx_data->buff = skb->data;
	tx_data->size = skb->len;
	tx_data->skb  = skb;

	eth_h = (struct ethhdr *)(skb->data);
	if (eth_h->h_proto == 0x8e88)
		PRINT_D(TX_DBG, "EAPOL transmitted\n");

	/*get source and dest ip addresses*/
	ih = (struct iphdr *)(skb->data + sizeof(struct ethhdr));

	pu8UdpBuffer = (char *)ih + sizeof(struct iphdr);
	if ((pu8UdpBuffer[1] == 68 && pu8UdpBuffer[3] == 67) ||
	    (pu8UdpBuffer[1] == 67 && pu8UdpBuffer[3] == 68))
		PRINT_D(GENERIC_DBG, "DHCP Message transmitted, type:%x %x %x\n",
		     pu8UdpBuffer[248], pu8UdpBuffer[249], pu8UdpBuffer[250]);

	PRINT_D(TX_DBG, "Sending packet - Size = %d\n", tx_data->size);

	/* Send packet to MAC HW - for now the tx_complete function will be just status
 	* indicator. still not sure if I need to suspend host transmission till the tx_complete
 	* function called or not?
 	* allocated buffer will be freed in tx_complete function.
 	*/
	PRINT_D(TX_DBG, "Adding tx packet to TX Queue\n");
	nic->netstats.tx_packets++;
	nic->netstats.tx_bytes += tx_data->size;
	tx_data->pBssid = g_linux_wlan->strInterfaceInfo[nic->u8IfIdx].aBSSID;

	QueueCount = g_linux_wlan->oup.wlan_add_to_tx_que((void *)tx_data,
						       tx_data->buff,
						       tx_data->size,
						       linux_wlan_tx_complete);


	if (QueueCount > FLOW_CONTROL_UPPER_THRESHOLD) {
		netif_stop_queue(g_linux_wlan->strInterfaceInfo[0].wilc_netdev);
		netif_stop_queue(g_linux_wlan->strInterfaceInfo[1].wilc_netdev);
	}

	return 0;
}

int mac_close(struct net_device *ndev)
{
	struct WILC_WFI_priv *priv;
	struct perInterface_wlan *nic;
	struct WILC_WFIDrv *pstrWFIDrv;

	nic = netdev_priv(ndev);

	if ((nic == NULL) || (nic->wilc_netdev == NULL) ||
	    (nic->wilc_netdev->ieee80211_ptr == NULL) ||
	    (nic->wilc_netdev->ieee80211_ptr->wiphy == NULL)) {
		PRINT_ER("nic = NULL\n");
		return 0;
	}

	priv = wiphy_priv(nic->wilc_netdev->ieee80211_ptr->wiphy);

	if (priv == NULL) {
		PRINT_ER("priv = NULL\n");
		return 0;
	}

	pstrWFIDrv = (struct WILC_WFIDrv *)priv->hWILCWFIDrv;
	PRINT_D(GENERIC_DBG, "Mac close\n");

	if (g_linux_wlan == NULL) {
		PRINT_ER("g_linux_wlan = NULL\n");
		return 0;
	}

	if (pstrWFIDrv == NULL)	{
		PRINT_ER("pstrWFIDrv = NULL\n");
		return 0;
	}

	if ((g_linux_wlan->open_ifcs) > 0) {
		g_linux_wlan->open_ifcs--;
	} else {
		PRINT_ER("ERROR: MAC close called while number of opened interfaces is zero\n");
		return 0;
	}

	if (nic->wilc_netdev != NULL)	{
		// Stop the network interface queue 
		netif_stop_queue(nic->wilc_netdev);

		/*
		 * TicketId1003
		 * If recovering from a crash, don't de-init host interface
		 */
		if (!gbCrashRecover)
			WILC_WFI_DeInitHostInt(nic->wilc_netdev);
	}

	if (g_linux_wlan->open_ifcs == 0) {
		PRINT_D(GENERIC_DBG, "Deinitializing wilc\n");
		g_linux_wlan->close = 1;
		wilc_wlan_deinit(g_linux_wlan);
		#ifdef WILC_AP_EXTERNAL_MLME
		WILC_WFI_deinit_mon_interface();
		#endif
	}

	nic->mac_opened = 0;
	up(&close_exit_sync);
	

	return 0;
}

int mac_ioctl(struct net_device *ndev, struct ifreq *req, int cmd)
{
	u8 *buff = NULL;
	s8 rssi;
	unsigned int size = 0;
	struct perInterface_wlan *nic;
	struct WILC_WFI_priv *priv;
	signed int s32Error = ATL_SUCCESS;

	nic = netdev_priv(ndev);
	priv = wiphy_priv(nic->wilc_netdev->ieee80211_ptr->wiphy);

	if (!g_linux_wlan->wilc_initialized)
		return 0;

	switch (cmd) {
	case SIOCDEVPRIVATE + 1:
	{
		struct android_wifi_priv_cmd priv_cmd;

		if (copy_from_user(&priv_cmd, req->ifr_data,
				   sizeof(struct android_wifi_priv_cmd))) {
			s32Error = -EFAULT;
			goto done;
		}

		buff = memdup_user(priv_cmd.buf, priv_cmd.total_len);
		if (IS_ERR(buff)) {
			s32Error = PTR_ERR(buff);
			goto done;
		}

		if (strncasecmp(buff, "BTCOEXMODE", strlen("BTCOEXMODE")) == 0) {
			uint32_t mode = *(buff + strlen("BTCOEXMODE") + 1) - '0';
#ifdef WILC_BT_COEXISTENCE
			PRINT_D(GENERIC_DBG, "[COEX] [DRV] rcvd IO ctrl << BT-MODE: %d >>\n", mode);
			/*TicketId1092*/
			/*If WiFi is off and BT is turning on, set COEX_ON mode*/
			//host_int_change_bt_coex_mode(priv->hWILCWFIDrv, mode);
#endif
		}
	} break;

	case SIOCSIWPRIV:
	{
		struct iwreq *wrq = (struct iwreq *) req;

		size = wrq->u.data.length;

		if (size && wrq->u.data.pointer) {
			buff = memdup_user(wrq->u.data.pointer, wrq->u.data.length);
			if (IS_ERR(buff)) {
				s32Error = PTR_ERR(buff);
				goto done;
			}

			PRINT_D(GENERIC_DBG, "IOCTRL priv: %s", buff);

			if (strncasecmp(buff, "RSSI", size) == 0) {
				s32Error = host_int_get_rssi(priv->hWILCWFIDrv, &(rssi));
				if (s32Error)
					PRINT_ER("Failed to send get rssi param's message queue ");

				PRINT_INFO(GENERIC_DBG, "RSSI :%d\n", rssi);
					/*Rounding up the rssi negative value*/		
				rssi += 5;
				snprintf(buff, size, "rssi %d", rssi);

				if (copy_to_user(wrq->u.data.pointer, buff, size)) {
					PRINT_ER("%s: failed to copy data to user buffer\n", __func__);
					s32Error = -EFAULT;
					goto done;
				}
			} else if (strncasecmp(buff, "BTCOEXMODE", strlen("BTCOEXMODE")) == 0) {
				uint32_t mode = *(buff + strlen("BTCOEXMODE") + 1) - '0';
#ifdef WILC_BT_COEXISTENCE
				PRINT_D(GENERIC_DBG, "[COEX] [DRV] rcvd IO ctrl << BT-MODE: %d >>\n", mode);
				/*if (mode != 1 && mode != 0)
					host_int_change_bt_coex_mode(priv->hWILCWFIDrv, mode);
				*/

#endif
			} else if (strncasecmp(buff, "BTCOEXSCAN-START", strlen("BTCOEXSCAN-START")) == 0) {
#ifdef WILC_BT_COEXISTENCE
				PRINT_D(GENERIC_DBG, "[COEX] [DRV] rcvd IO ctrl << BTCOEXSCAN-START >>\n");
#endif
			} else if (strncasecmp(buff, "BTCOEXSCAN-STOP", strlen("BTCOEXSCAN-STOP")) == 0) {
#ifdef WILC_BT_COEXISTENCE
				PRINT_D(GENERIC_DBG, "[COEX] [DRV] rcvd IO ctrl << BTCOEXSCAN-STOP >>\n");
#endif
			}
		}
	} break;

	default:
	{
		PRINT_INFO(GENERIC_DBG, "Command - %d - has been received\n", cmd);
		s32Error = -EOPNOTSUPP;
		goto done;
	}
	}

done:

	if (buff != NULL)
		kfree(buff);

	return s32Error;
}

void frmw_to_linux(uint8_t *buff, uint32_t size, uint32_t pkt_offset)
{
	unsigned int frame_len = 0;
	int stats;
	u8 *buff_to_send = NULL;
	struct sk_buff *skb;
#ifndef TCP_ENHANCEMENTS
	char *pu8UdpBuffer;
	struct iphdr *ih;
#endif /* TCP_ENHANCEMENTS */
	struct net_device *wilc_netdev;
	struct perInterface_wlan *nic;
	struct WILC_WFI_priv *priv;
	u8 null_bssid[ETH_ALEN] = {0};

	wilc_netdev = GetIfHandler(buff);
	if (wilc_netdev == NULL)
		return;

	buff += pkt_offset;
	nic = netdev_priv(wilc_netdev);

	if (size > 0) {
		frame_len = size;
		buff_to_send = buff;

		/*
		 * TicketId1001
		 * If eapol frame and successful connection is not yet reported,		 
		 * buffer it to be passed later.
		 */
		priv = wdev_priv(wilc_netdev->ieee80211_ptr);
		if ((buff_to_send[12] == 0x88 && buff_to_send[13] == 0x8e)
		    && (nic->iftype == STATION_MODE || nic->iftype == CLIENT_MODE)
		    && (!(memcmp(priv->au8AssociatedBss, null_bssid, ETH_ALEN)))) {
				/*Allocate memory*/
			if (priv->pStrBufferedEAP == NULL) {
				priv->pStrBufferedEAP = kmalloc(sizeof(struct wilc_buffered_eap), GFP_ATOMIC);
				if(priv->pStrBufferedEAP != NULL)
				{
					priv->pStrBufferedEAP->pu8buff = NULL;
					priv->pStrBufferedEAP->u32Size = 0;
					priv->pStrBufferedEAP->u32PktOffset = 0;
				}
				else
				{
					PRINT_ER("failed to alloc priv->pStrBufferedEAP\n");
					return;
				}
			}
			else
			{
				kfree(priv->pStrBufferedEAP->pu8buff);
			}
			
			priv->pStrBufferedEAP->pu8buff = kmalloc(size + pkt_offset, GFP_ATOMIC);

			priv->pStrBufferedEAP->u32Size = size;
			priv->pStrBufferedEAP->u32PktOffset = pkt_offset;
			memcpy(priv->pStrBufferedEAP->pu8buff, buff - pkt_offset, size + pkt_offset);

			/*
			 * TO DO: Stop timer before starting it
			 * Wait about 10 ms then check again if successful connection is reported
			 */
			hEAPFrameBuffTimer.data = (unsigned long)priv;
			mod_timer(&hEAPFrameBuffTimer, (jiffies + msecs_to_jiffies(10)));
			return;
		}

		/* Need to send the packet up to the host, allocate a skb buffer */
		skb = dev_alloc_skb(frame_len);
		if (skb == NULL)
			return;

		if (g_linux_wlan == NULL || wilc_netdev == NULL)
			PRINT_ER("wilc_netdev in g_linux_wlan is NULL");
		skb->dev = wilc_netdev;

		if (skb->dev == NULL)
			PRINT_ER("skb->dev is NULL\n");

		memcpy(skb_put(skb, frame_len), buff_to_send, frame_len);

		skb->protocol = eth_type_trans(skb, wilc_netdev);
#ifndef TCP_ENHANCEMENTS
		ih = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
		pu8UdpBuffer = (char *)ih + sizeof(struct iphdr);
			if((buff_to_send[35] == 67 && buff_to_send[37] == 68) || (buff_to_send[35] == 68 && buff_to_send[37] == 67))
			PRINT_D(RX_DBG, "DHCP Message received\n");
		if (buff_to_send[12] == 0x88 && buff_to_send[13] == 0x8e)
			PRINT_D(GENERIC_DBG, "eapol received\n");
#endif
		nic->netstats.rx_packets++;
		nic->netstats.rx_bytes += frame_len;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		stats = netif_rx(skb);
		PRINT_D(RX_DBG, "netif_rx ret value is: %d\n", stats);
	} else {
#ifndef TCP_ENHANCEMENTS
		PRINT_ER("Discard sending packet with len = %d\n", size);
#endif
	}
}

void WILC_WFI_mgmt_rx(uint8_t *buff, uint32_t size)
{
	int i = 0;
	struct perInterface_wlan *nic;

	/*
	 * BugID_5450
	* Pass the frame on the monitor interface, if any.
	* Otherwise, pass it on p2p0 netdev, if registered on it
	*/
	for (i = 0; i < g_linux_wlan->u8NoIfcs; i++) {
		nic = netdev_priv(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
		if (nic->monitor_flag) {
			WILC_WFI_monitor_rx(buff, size);
			return;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#ifdef WILC_P2P
	nic = netdev_priv(g_linux_wlan->strInterfaceInfo[1].wilc_netdev);
	if ((buff[0] == nic->g_struct_frame_reg[0].frame_type &&
	     nic->g_struct_frame_reg[0].reg) ||
	    (buff[0] == nic->g_struct_frame_reg[1].frame_type &&
	     nic->g_struct_frame_reg[1].reg))
		WILC_WFI_p2p_rx(g_linux_wlan->strInterfaceInfo[1].wilc_netdev, buff, size);
#endif
#endif
}

int wilc_netdev_init(void)
{
	int i;
	struct perInterface_wlan *nic;
	struct net_device *ndev;
	struct wireless_dev *wdev;

	sema_init(&close_exit_sync, 0);

	g_linux_wlan = kmalloc(sizeof(struct linux_wlan), GFP_ATOMIC);
	memset(g_linux_wlan, 0, sizeof(struct linux_wlan));

	for(i = 1; i < ARRAY_SIZE(wfidrv_list); i++)
	{
		wfidrv_list[i] = NULL;
	}
	
	/*create the common structure*/
	/*Reset interrupt count debug*/
#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
	register_inetaddr_notifier(&g_dev_notifier);
#endif

	for (i = 0; i < NUM_CONCURRENT_IFC; i++) {
		/*allocate first ethernet device with perinterface_wlan_t as its private data*/
		ndev = alloc_etherdev(sizeof(struct perInterface_wlan));
		if (!ndev) {
			PRINT_ER("Failed to allocate ethernet dev\n");
			return -1;
		}

		nic = netdev_priv(ndev);
		memset(nic, 0, sizeof(struct perInterface_wlan));

		/*Name the Devices*/	
		if (i == 0)
			strcpy(ndev->name, "wlan%d");
		else
			strcpy(ndev->name, "p2p%d");

		nic->u8IfIdx = g_linux_wlan->u8NoIfcs;
		nic->wilc_netdev = ndev;
		g_linux_wlan->strInterfaceInfo[g_linux_wlan->u8NoIfcs].wilc_netdev = ndev;
		g_linux_wlan->u8NoIfcs++;
		wilc_set_netdev_ops(ndev);

			/*Register WiFi*/
		wdev = WILC_WFI_WiphyRegister(ndev);

		if (wdev == NULL) {
			PRINT_ER("Can't register WILC Wiphy\n");
			return -1;
		}

			/*linking the wireless_dev structure with the netdevice*/
		nic->wilc_netdev->ieee80211_ptr = wdev;
		nic->wilc_netdev->ml_priv = nic;
		wdev->netdev = nic->wilc_netdev;
		nic->netstats.rx_packets = 0;
		nic->netstats.tx_packets = 0;
		nic->netstats.rx_bytes = 0;
		nic->netstats.tx_bytes = 0;

		if (register_netdev(ndev)) {
			PRINT_ER("Device couldn't be registered - %s\n",
			       ndev->name);
			return -1;
		}

		nic->iftype = STATION_MODE;
		nic->mac_opened = 0;
	}

#ifndef WILC_SDIO
	g_linux_wlan->wilc_spidev = wilc_spi_dev;
#else
	g_linux_wlan->wilc_sdio_func = local_sdio_func;
#endif

	return 0;
}

/*The 1st function called after module inserted*/
static int __init init_wilc_driver(void)
{
	int ret = 0;

	PRINT_D(INIT_DBG, "WILC3000 driver v11.2\n");
	set_pf_chip_sleep_manually(chip_sleep_manually);
	set_pf_get_num_conn_ifcs( linux_wlan_get_num_conn_ifcs);
	set_pf_host_wakeup_notify(wilc_host_wakeup_notify);
	set_pf_host_sleep_notify(wilc_host_sleep_notify);
	set_pf_get_u8SuspendOnEvent_value(WILC_WFI_get_u8SuspendOnEvent_value);
	set_pf_is_wilc3000_initalized(is_wilc3000_initalized);
	at_pwr_power_up(PWR_DEV_SRC_WIFI);
	ret = at_pwr_register_bus(PWR_DEV_SRC_WIFI);

	if (ret < 0)
		return ret;
	
	PRINT_D(INIT_DBG, "Initializing netdev\n");
	if (wilc_netdev_init())
		PRINT_ER("Couldn't initialize netdev\n");
	
	/*TicketId883*/
	/*Pass to pwr dev a function pointer to change coex mode*/
	#ifdef WILC_BT_COEXISTENCE
	wilc_set_pf_change_coex_mode(linux_wlan_change_bt_coex_mode);
	#endif

	PRINT_D(INIT_DBG, "Device has been initialized successfully\n");
	return 0;
}
module_init(init_wilc_driver);

static void __exit exit_wilc_driver(void)
{
	int i = 0;
	struct perInterface_wlan *nic[NUM_CONCURRENT_IFC];
#define CLOSE_TIMEOUT (3 * 1000)

		/*TicketId883*/
	/*Reset chnage coex mode function pointer to NULL*/
	#ifdef WILC_BT_COEXISTENCE
	wilc_set_pf_change_coex_mode(NULL);
	#endif
	
	if ((g_linux_wlan != NULL) &&
	    (((g_linux_wlan->strInterfaceInfo[0].wilc_netdev) != NULL) ||
	    ((g_linux_wlan->strInterfaceInfo[1].wilc_netdev) != NULL)))	{

		for (i = 0; i < NUM_CONCURRENT_IFC; i++)
			nic[i] = netdev_priv(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
		
		PRINT_D(INIT_DBG, "Waiting for mac_close ....\n");

		if (down_timeout(&close_exit_sync, msecs_to_jiffies(CLOSE_TIMEOUT)) < 0)
			PRINT_D(INIT_DBG, "Closed TimedOUT\n");
		else
			PRINT_D(INIT_DBG, "mac_closed\n");

		for (i = 0; i < NUM_CONCURRENT_IFC; i++) {
			//close all opened interfaces
			if (g_linux_wlan->strInterfaceInfo[i].wilc_netdev != NULL)
				if (nic[i]->mac_opened)
				{
					PRINT_D(INIT_DBG, "calling mac_close from exit_drv\n");
					mac_close(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
				}
		}
		for (i = 0; i < NUM_CONCURRENT_IFC; i++) {
			PRINT_D(INIT_DBG, "Unregistering netdev %p\n", g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
			unregister_netdev(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
			PRINT_D(INIT_DBG, "Freeing Wiphy...\n");
			WILC_WFI_WiphyFree(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
			PRINT_D(INIT_DBG, "Freeing netdev...\n");
			free_netdev(g_linux_wlan->strInterfaceInfo[i].wilc_netdev);
		}
	}

	#ifdef DISABLE_PWRSAVE_AND_SCAN_DURING_IP
		unregister_inetaddr_notifier(&g_dev_notifier);
	#endif

	if ((g_linux_wlan != NULL) && g_linux_wlan->wilc_firmware != NULL) {
		release_firmware(g_linux_wlan->wilc_firmware);
		g_linux_wlan->wilc_firmware = NULL;
	}

	at_pwr_unregister_bus(PWR_DEV_SRC_WIFI);

	if (g_linux_wlan != NULL) {
		kfree(g_linux_wlan);
		g_linux_wlan = NULL;
	}
	PRINT_D(INIT_DBG, "Module_exit Done.\n");

	at_pwr_power_down(PWR_DEV_SRC_WIFI);
}
module_exit(exit_wilc_driver);

MODULE_LICENSE("GPL");
