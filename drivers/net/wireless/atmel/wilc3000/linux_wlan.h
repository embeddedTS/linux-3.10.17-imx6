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

#ifndef WILC_LINUX_WLAN_H
#define WILC_LINUX_WLAN_H
#include <linux/types.h>
#include "wilc_wfi_netdevice.h"
#include "wilc_wlan_if.h"
#include <linux/skbuff.h>
#include <linux/netdevice.h>

extern struct linux_wlan *g_linux_wlan;
extern struct wilc_wlan_oup *gpstrWlanOps;
extern volatile int g_bWaitForRecovery;
extern bool bEnablePS;

#define duringIP_TIME		15000

#define IP_STATE_OBTAINING						1
#define IP_STATE_OBTAINED						2
#define IP_STATE_GO_ASSIGNING					3
#define IP_STATE_DEFAULT							4


void handle_pwrsave_during_obtainingIP(struct WILC_WFIDrv *pstrWFIDrv, uint8_t state);
void set_obtaining_IP_flag(bool val);
bool get_obtaining_IP_flag(void);
void store_power_save_current_state(struct WILC_WFIDrv *pstrWFIDrv, bool val);
void obtaining_IP_timer_handler(unsigned long data);


int linux_wlan_get_num_conn_ifcs(void);
struct net_device* linux_wlan_get_if_netdev(uint8_t ifc);
uint32_t linux_wlan_get_drv_handler_by_ifc(uint8_t ifc);
void WILC_WFI_monitor_rx(uint8_t *buff, uint32_t size);
int mac_xmit(struct sk_buff *skb, struct net_device *dev);
void WILC_WFI_mgmt_rx(uint8_t *buff, uint32_t size);
int linux_wlan_get_firmware(struct perInterface_wlan *p_nic);
int mac_open(struct net_device *ndev);
int mac_close(struct net_device *ndev);
void EAP_buff_timeout(unsigned long pUserVoid);
void wilc_wlan_deinit(struct linux_wlan *nic);
void frmw_to_linux(uint8_t *buff, uint32_t size, uint32_t pkt_offset, uint8_t status);
int linux_wlan_set_bssid(struct net_device *wilc_netdev, uint8_t *pBSSID, uint8_t mode);
int wilc_wlan_init(struct net_device *dev, struct perInterface_wlan *p_nic);
void linux_wlan_enable_irq(void);

#endif /* WILC_LINUX_WLAN_H */
