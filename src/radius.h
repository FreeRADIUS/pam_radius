/*
 *
 *	RADIUS
 *	Remote Authentication Dial In User Service
 *
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 */

/*
 *	@(#)radius.h	1.9 11/14/94
 */
#ifndef RADIUS_H
#define RADIUS_H

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_STRING_LEN		128	/* maximum of 254 */

typedef struct pw_auth_hdr {
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
	uint8_t		vector[AUTH_VECTOR_LEN];
	uint8_t		data[2];
} AUTH_HDR;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1645
#define PW_ACCT_UDP_PORT		1646

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3


#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define PW_PASSWORD_REQUEST		7
#define PW_PASSWORD_ACK			8
#define PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define PW_ACCESS_CHALLENGE		11

#define	PW_USER_NAME			1
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_NAS_IP_ADDRESS	       	4
#define	PW_NAS_PORT_ID			5
#define	PW_USER_SERVICE_TYPE		6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_ADDRESS		8
#define	PW_FRAMED_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FRAMED_FILTER_ID		11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_HOST			14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16
#define PW_OLD_PASSWORD			17
#define PW_REPLY_MESSAGE		18
#define PW_CALLBACK_NUMBER     		19
#define PW_CALLBACK_ID			20
#define PW_EXPIRATION			21
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_CLASS                        25      /* string */
#define PW_VENDOR_SPECIFIC              26      /* vendor */
#define PW_SESSION_TIMEOUT              27      /* integer */
#define PW_IDLE_TIMEOUT                 28      /* integer */
#define PW_TERMINATION_ACTION           29      /* integer */
#define PW_CALLED_STATION_ID            30      /* string */
#define PW_CALLING_STATION_ID           31      /* string */
#define PW_NAS_IDENTIFIER               32      /* string */
#define PW_PROXY_STATE                  33      /* string */
#define PW_LOGIN_LAT_SERVICE            34      /* string */
#define PW_LOGIN_LAT_NODE               35      /* string */
#define PW_LOGIN_LAT_GROUP              36      /* string */
#define PW_FRAMED_APPLETALK_LINK        37      /* integer */
#define PW_FRAMED_APPLETALK_NETWORK     38      /* integer */
#define PW_FRAMED_APPLETALK_ZONE        39      /* string */

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46

#define PW_CHAP_CHALLENGE               60      /* string */
#define PW_NAS_PORT_TYPE                61      /* integer */
#define PW_PORT_LIMIT                   62      /* integer */
#define PW_LOGIN_LAT_PORT               63      /* string */
#define PW_PROMPT                       64      /* integer */

/*
 *	INTEGER TRANSLATIONS
 */

/*	USER TYPES	*/

#define	PW_LOGIN_USER			1
#define	PW_FRAMED_USER			2
#define	PW_DIALBACK_LOGIN_USER	3
#define	PW_DIALBACK_FRAMED_USER	4
#define PW_OUTBOUND_USER		5
#define PW_SHELL_USER			6

/*	FRAMED PROTOCOLS	*/

#define	PW_PPP				1
#define	PW_SLIP				2

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST			1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN		3

/*	NAS PORT TYPES */
#define PW_NAS_PORT_TYPE_VIRTUAL	5

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSEN_TCP_IP		1

/*	LOGIN SERVICES	*/

#define	PW_TELNET			0
#define	PW_RLOGIN			1
#define	PW_TCP_CLEAR			2
#define	PW_PORTMASTER			3
#define PW_AUTHENTICATE_ONLY            8

/*	AUTHENTICATION LEVEL	*/

#define PW_AUTH_NONE			0
#define PW_AUTH_RADIUS			1
#define PW_AUTH_LOCAL			2

/*	STATUS TYPES	*/

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2
#define PW_STATUS_ALIVE			3

/* Default Database File Names */

#define RADIUS_DIR		"/etc/raddb"
#define RADACCT_DIR		"/usr/adm/radacct"

#define RADIUS_DICTIONARY	"dictionary"
#define RADIUS_CLIENTS		"clients"
#define RADIUS_USERS		"users"
#define RADIUS_HOLD		"holdusers"
#define RADIUS_LOG		"logfile"

/* Server data structures */

typedef struct dict_attr {
	char			name[32];
	int			value;
	int			type;
	struct dict_attr	*next;
} DICT_ATTR;

typedef struct dict_value {
	char			attrname[32];
	char			name[32];
	int			value;
	struct dict_value	*next;
} DICT_VALUE;

typedef struct value_pair {
	char			name[32];
	int			attribute;
	int			type;
	uint32_t		lvalue;
	char			strvalue[AUTH_STRING_LEN];
	struct value_pair	*next;
} VALUE_PAIR;

typedef struct auth_req {
	uint32_t		ipaddr;
	uint16_t		udp_port;
	uint8_t			id;
	uint8_t			code;
	uint8_t			vector[16];
	uint8_t			secret[16];
	VALUE_PAIR		*request;
	int			child_pid;	/* Process ID of child */
	uint32_t		timestamp;
	struct auth_req		*next;		/* Next active request */
} AUTH_REQ;

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		100

#endif /* RADIUS_H */
