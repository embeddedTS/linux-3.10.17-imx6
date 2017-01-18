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

#ifndef __WILC_ERRORSUPPORT_H__
#define __WILC_ERRORSUPPORT_H__

#include "linux_wlan_common.h"

/* Psitive Numbers to indicate sucess with special status */
#define WILC_ALREADY_EXSIT	(+100)	/* The requested object already
					    exists */

/* Generic success will return 0 */
#define WILC_SUCCESS		0	/* Generic success */

/* Negative numbers to indicate failures */
#define WILC_FAIL		-100	/* Generic Fail */
#define WILC_BUSY		-101	/* Busy with another operation*/
#define WILC_INVALID_ARGUMENT	-102	/* A given argument is invalid*/
#define WILC_INVALID_STATE	-103	/* An API request would violate the
		   Driver state machine (i.e. to start PID while not camped)*/
#define WILC_BUFFER_OVERFLOW	-104	/* In copy operations if the copied
				    data is larger than the allocated buffer*/
#define WILC_NULL_PTR		-105	/* null pointer is passed or used */
#define WILC_EMPTY		-107
#define WILC_FULL		-108
#define WILC_TIMEOUT		-109
#define WILC_CANCELED		-110	/* The required operation have been
					    canceled by the user*/
#define WILC_INVALID_FILE	-112	/* The Loaded file is corruped or
					    having an invalid format */
#define WILC_NOT_FOUND		-113	/* Cant find the file to load */
#define WILC_NO_MEM		-114
#define WILC_UNSUPPORTED_VERSION	-115
#define WILC_FILE_EOF		-116


/* Error type */
typedef signed int  WILC_ErrNo;

#define WILC_IS_ERR(__status__) (__status__ < WILC_SUCCESS)

#define WILC_ERRORCHECK(__status__) do {\
	if (WILC_IS_ERR(__status__)) {\
		PRINT_ER("WILC_ERRORCHECK(%d)\n", __status__);\
		goto ERRORHANDLER;\
	} \
} while (0)

#define WILC_ERRORREPORT(__status__, __err__) do {\
	PRINT_ER("WILC_ERRORREPORT(%d)\n", __err__);\
	__status__ = __err__;\
	goto ERRORHANDLER;\
} while (0)

#define  WILC_NULLCHECK(__status__, __ptr__) do {\
	if (__ptr__ == NULL) {\
		WILC_ERRORREPORT(__status__, WILC_NULL_PTR);\
	} \
} while (0)

#define WILC_CATCH(__status__) \
ERRORHANDLER :\
if(WILC_IS_ERR(__status__)) \

#endif
