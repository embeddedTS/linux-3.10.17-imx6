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

#ifndef __ATL_ERRORSUPPORT_H__
#define __ATL_ERRORSUPPORT_H__

#include "linux_wlan_common.h"

/* Psitive Numbers to indicate sucess with special status */
#define ATL_ALREADY_EXSIT	(+100)	/* The requested object already
					    exists */

/* Generic success will return 0 */
#define ATL_SUCCESS		0	/* Generic success */

/* Negative numbers to indicate failures */
#define ATL_FAIL		-100	/* Generic Fail */
#define ATL_BUSY		-101	/* Busy with another operation*/
#define ATL_INVALID_ARGUMENT	-102	/* A given argument is invalid*/
#define ATL_INVALID_STATE	-103	/* An API request would violate the
		   Driver state machine (i.e. to start PID while not camped)*/
#define ATL_BUFFER_OVERFLOW	-104	/* In copy operations if the copied
				    data is larger than the allocated buffer*/
#define ATL_NULL_PTR		-105	/* null pointer is passed or used */
#define ATL_EMPTY		-107
#define ATL_FULL		-108
#define ATL_TIMEOUT		-109
#define ATL_CANCELED		-110	/* The required operation have been
					    canceled by the user*/
#define ATL_INVALID_FILE	-112	/* The Loaded file is corruped or
					    having an invalid format */
#define ATL_NOT_FOUND		-113	/* Cant find the file to load */
#define ATL_NO_MEM		-114
#define ATL_UNSUPPORTED_VERSION	-115
#define ATL_FILE_EOF		-116


/* Error type */
typedef signed int  ATL_ErrNo;

#define ATL_IS_ERR(__status__) (__status__ < ATL_SUCCESS)

#define ATL_ERRORCHECK(__status__) do {\
	if (ATL_IS_ERR(__status__)) {\
		PRINT_ER("ATL_ERRORCHECK(%d)\n", __status__);\
		goto ERRORHANDLER;\
	} \
} while (0)

#define ATL_ERRORREPORT(__status__, __err__) do {\
	PRINT_ER("ATL_ERRORREPORT(%d)\n", __err__);\
	__status__ = __err__;\
	goto ERRORHANDLER;\
} while (0)

#define  ATL_NULLCHECK(__status__, __ptr__) do {\
	if (__ptr__ == NULL) {\
		ATL_ERRORREPORT(__status__, ATL_NULL_PTR);\
	} \
} while (0)

#define ATL_CATCH(__status__) \
ERRORHANDLER :\
if(ATL_IS_ERR(__status__)) \

#endif
