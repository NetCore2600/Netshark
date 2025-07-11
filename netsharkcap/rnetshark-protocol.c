/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2008 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <config.h>

#include <string.h>		/* for strlen(), ... */
#include <stdlib.h>		/* for malloc(), free(), ... */
#include <stdarg.h>		/* for functions with variable number of arguments */
#include <stdint.h>		/* for intN_t and uintN_t types */
#include <errno.h>		/* for the errno variable */
#include "sockutils.h"
#include "portability.h"
#include "rnetshark-protocol.h"
#include <netshark/netshark.h>

/*
 * This file contains functions used both by the rnetshark client and the
 * rnetshark daemon.
 */

/*
 * This function sends a RNETSHARK error to our peer.
 *
 * It has to be called when the main program detects an error.
 * It will send to our peer the 'buffer' specified by the user.
 * This function *does not* request a RNETSHARK CLOSE connection. A CLOSE
 * command must be sent explicitly by the program, since we do not know
 * whether the error can be recovered in some way or if it is a
 * non-recoverable one.
 *
 * \param sock: the socket we are currently using.
 *
 * \param ssl: if compiled with openssl, the optional ssl handler to use with the above socket.
 *
 * \param ver: the protocol version we want to put in the reply.
 *
 * \param errcode: a integer which tells the other party the type of error
 * we had.
 *
 * \param error: an user-allocated (and '0' terminated) buffer that contains
 * the error description that has to be transmitted to our peer. The
 * error message cannot be longer than NETSHARK_ERRBUF_SIZE.
 *
 * \param errbuf: a pointer to a user-allocated buffer (of size
 * NETSHARK_ERRBUF_SIZE) that will contain the error message (in case there
 * is one). It could be network problem.
 *
 * \return '0' if everything is fine, '-1' if some errors occurred. The
 * error message is returned in the 'errbuf' variable.
 */
int
rnetshark_senderror(NETSHARK_SOCKET sock, SSL *ssl, uint8_t ver, unsigned short errcode, const char *error, char *errbuf)
{
	char sendbuf[RNETSHARK_NETBUF_SIZE];	/* temporary buffer in which data to be sent is buffered */
	int sendbufidx = 0;			/* index which keeps the number of bytes currently buffered */
	uint16_t length;

	length = (uint16_t)strlen(error);

	if (length > NETSHARK_ERRBUF_SIZE)
		length = NETSHARK_ERRBUF_SIZE;

	rnetshark_createhdr((struct rnetshark_header *) sendbuf, ver, RNETSHARK_MSG_ERROR, errcode, length);

	if (sock_bufferize(NULL, sizeof(struct rnetshark_header), NULL, &sendbufidx,
		RNETSHARK_NETBUF_SIZE, SOCKBUF_CHECKONLY, errbuf, NETSHARK_ERRBUF_SIZE))
		return -1;

	if (sock_bufferize(error, length, sendbuf, &sendbufidx,
		RNETSHARK_NETBUF_SIZE, SOCKBUF_BUFFERIZE, errbuf, NETSHARK_ERRBUF_SIZE))
		return -1;

	if (sock_send(sock, ssl, sendbuf, sendbufidx, errbuf, NETSHARK_ERRBUF_SIZE) < 0)
		return -1;

	return 0;
}

/*
 * This function fills in a structure of type rnetshark_header.
 *
 * It is provided just because the creation of an rnetshark header is a common
 * task. It accepts all the values that appears into an rnetshark_header, and
 * it puts them in place using the proper hton() calls.
 *
 * \param header: a pointer to a user-allocated buffer which will contain
 * the serialized header, ready to be sent on the network.
 *
 * \param ver: a value (in the host byte order) which will be placed into the
 * header.ver field and that represents the protocol version number of the
 * current message.
 *
 * \param type: a value (in the host byte order) which will be placed into the
 * header.type field and that represents the type of the current message.
 *
 * \param value: a value (in the host byte order) which will be placed into
 * the header.value field and that has a message-dependent meaning.
 *
 * \param length: a value (in the host by order) which will be placed into
 * the header.length field, representing the payload length of the message.
 *
 * \return Nothing. The serialized header is returned into the 'header'
 * variable.
 */
void
rnetshark_createhdr(struct rnetshark_header *header, uint8_t ver, uint8_t type, uint16_t value, uint32_t length)
{
	memset(header, 0, sizeof(struct rnetshark_header));

	header->ver = ver;
	header->type = type;
	header->value = htons(value);
	header->plen = htonl(length);
}

/*
 * Convert a message type to a string containing the type name.
 */
static const char *requests[] =
{
	NULL,				/* not a valid message type */
	"RNETSHARK_MSG_ERROR",
	"RNETSHARK_MSG_FINDALLIF_REQ",
	"RNETSHARK_MSG_OPEN_REQ",
	"RNETSHARK_MSG_STARTCAP_REQ",
	"RNETSHARK_MSG_UPDATEFILTER_REQ",
	"RNETSHARK_MSG_CLOSE",
	"RNETSHARK_MSG_PACKET",
	"RNETSHARK_MSG_AUTH_REQ",
	"RNETSHARK_MSG_STATS_REQ",
	"RNETSHARK_MSG_ENDCAP_REQ",
	"RNETSHARK_MSG_SETSAMPLING_REQ",
};
#define NUM_REQ_TYPES	(sizeof requests / sizeof requests[0])

static const char *replies[] =
{
	NULL,
	NULL,			/* this would be a reply to RNETSHARK_MSG_ERROR */
	"RNETSHARK_MSG_FINDALLIF_REPLY",
	"RNETSHARK_MSG_OPEN_REPLY",
	"RNETSHARK_MSG_STARTCAP_REPLY",
	"RNETSHARK_MSG_UPDATEFILTER_REPLY",
	NULL,			/* this would be a reply to RNETSHARK_MSG_CLOSE */
	NULL,			/* this would be a reply to RNETSHARK_MSG_PACKET */
	"RNETSHARK_MSG_AUTH_REPLY",
	"RNETSHARK_MSG_STATS_REPLY",
	"RNETSHARK_MSG_ENDCAP_REPLY",
	"RNETSHARK_MSG_SETSAMPLING_REPLY",
};
#define NUM_REPLY_TYPES	(sizeof replies / sizeof replies[0])

const char *
rnetshark_msg_type_string(uint8_t type)
{
	if (type & RNETSHARK_MSG_IS_REPLY) {
		type &= ~RNETSHARK_MSG_IS_REPLY;
		if (type >= NUM_REPLY_TYPES)
			return NULL;
		return replies[type];
	} else {
		if (type >= NUM_REQ_TYPES)
			return NULL;
		return requests[type];
	}
}
