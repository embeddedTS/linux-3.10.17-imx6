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

#ifndef __ATL_MSG_QUEUE_H__
#define __ATL_MSG_QUEUE_H__

/* Message Queue type is a structure */
struct Message {
	void *pvBuffer;
	unsigned int u32Length;
	struct Message *pstrNext;
};

struct MsgQueueHandle {
	struct semaphore hSem;
	spinlock_t strCriticalSection;
	bool bExiting;
	unsigned int u32ReceiversCount;
	struct Message *pstrMessageList;
};

/*
 * Creates a new Message queue, if the feature
 * CONFIG_ATL_MSG_QUEUE_IPC_NAME is enabled and pstrAttrs->pcName
 * is not Null, then this message queue can be used for IPC with
 * any other message queue having the same name in the system
 */
signed int ATL_MsgQueueCreate(struct MsgQueueHandle *pHandle);

/*
 * Sends a message, this API will block unil the message is
 * actually sent or until it is timedout (as long as the feature
 * CONFIG_ATL_MSG_QUEUE_TIMEOUT is enabled and pstrAttrs->u32Timeout
 * is not set to ATL_OS_INFINITY), zero timeout is a valid value
 */
signed int ATL_MsgQueueSend(struct MsgQueueHandle *pHandle,
		const void *pvSendBuffer, unsigned int u32SendBufferSize);

/*
 * Receives a message, this API will block unil a message is
 * received or until it is timedout (as long as the feature
 * CONFIG_ATL_MSG_QUEUE_TIMEOUT is enabled and pstrAttrs->u32Timeout
 * is not set to ATL_OS_INFINITY), zero timeout is a valid value
 */
signed int ATL_MsgQueueRecv(struct MsgQueueHandle *pHandle,
		void *pvRecvBuffer, unsigned int u32RecvBufferSize,
		unsigned int *pu32ReceivedLength);

/*
 * Destroys an existing  Message queue
 */
signed int ATL_MsgQueueDestroy(struct MsgQueueHandle *pHandle);
#endif
