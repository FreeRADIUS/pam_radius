#ifndef PAM_RADIUS_H
#define PAM_RADIUS_H

#include "config.h"

#include <limits.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdint.h>

#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#else
#define IFNAMSIZ 16 /* fallback to current value */
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#if defined(HAVE_SECURITY_PAM_APPL_H)
#  include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#  include <pam/pam_appl.h>
#endif

#if defined(HAVE_SECURITY_PAM_MODULES_H)
#  include <security/pam_modules.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#  include <pam/pam_modules.h>
#else
#  error security/pam_modules.h or pam/pam_modules.h required
#endif


#include "radius.h"
#include "md5.h"

/* Defaults for the prompt option */
#define MAXPROMPT 33               /* max prompt length, including '\0' */
#define DEFAULT_PROMPT "Password"  /* default prompt, without the ': '  */


/*************************************************************************
 * Platform specific defines
 *************************************************************************/

#ifndef CONST
#  if defined(__sun) || defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
/*
 *  On older versions of Solaris, you may have to change this to:
 *  #define CONST
 */
#    define CONST const
#  else
#    define CONST
#  endif
#endif

#ifndef PAM_EXTERN
#  ifdef __sun
#    define PAM_EXTERN extern
#  else
#    define PAM_EXTERN
#  endif
#endif


/*************************************************************************
 * Useful macros and defines
 *************************************************************************/

#define _pam_forget(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}
#ifndef _pam_drop
#define _pam_drop(X) if (X) {free(X);X = NULL;}
#endif

#define PAM_DEBUG_ARG      1
#define PAM_SKIP_PASSWD    2
#define PAM_USE_FIRST_PASS 4
#define PAM_TRY_FIRST_PASS 8
#define PAM_RUSER_ARG      16


/* buffer size for IP address in string form */
#define MAX_IP_LEN 16

/* Module defines */
#ifndef BUFFER_SIZE
#define BUFFER_SIZE      1024
#endif /* BUFFER_SIZE */
#define MAXPWNAM 253    /* maximum user name length. Server dependent,
                         * this is the default value
                         */
#define MAXPASS 128     /* max password length. Again, depends on server
                         * compiled in. This is the default.
                         */
#ifndef CONF_FILE       /* the configuration file holding the server secret */
#define CONF_FILE       "/etc/pam_radius_auth.conf"
#endif /* CONF_FILE */

#ifndef FALSE
#define FALSE 0
#undef TRUE
#define TRUE !FALSE
#endif

/** Should be placed before the function return type
 *
 */
#define NEVER_RETURNS		_Noreturn
#define UNUSED			CC_HINT(unused)

/*
 *	Only use GCC __attribute__ if were building with a GCClike
 *	compiler.
 */
#ifdef __GNUC__
#  define CC_HINT(...)	__attribute__ ((__VA_ARGS__))
#  define likely(_x)	__builtin_expect((_x), 1)
#  define unlikely(_x)	__builtin_expect((_x), 0)
#else
#  define CC_HINT(...)
#  define likely(_x)	_x
#  define unlikely(_x)	_x
#endif

/** Should be placed before the function return type
 *
 */
#define UNUSED			CC_HINT(unused)

/*************************************************************************
 * Additional RADIUS definitions
 *************************************************************************/

/* Per-attribute structure */
typedef struct attribute_t {
	unsigned char attribute;
	unsigned char length;
	unsigned char data[1];
} attribute_t;

typedef struct radius_server_t {
	struct radius_server_t *next;
	struct sockaddr_storage ip_storage;
	struct sockaddr *ip;
	char *hostname;
	char *secret;
	int timeout;
	int accounting;
	int sockfd;
	int sockfd6;
	char vrf[IFNAMSIZ];
} radius_server_t;

typedef struct radius_conf_t {
	radius_server_t *server;
	int retries;
	int use_ipv4;
	int use_ipv6;
	int localifdown;
	CONST char *client_id;
	int force_prompt;
	int max_challenge;
	int sockfd;
	int sockfd6;
	int debug;
	CONST char *conf_file;
	char prompt[MAXPROMPT];
	int prompt_attribute;
	int privilege_level;
	int require_message_authenticator;
	uint8_t *message_authenticator;
	char hostname[MAXHOSTNAMELEN + 1];
} radius_conf_t;

#endif /* PAM_RADIUS_H */
