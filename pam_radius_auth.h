#ifndef PAM_RADIUS_H
#define PAM_RADIUS_H

#include <sys/types.h>
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
#include <utmp.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#include "radius.h"
#include "md5.h"


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
  struct in_addr ip;
  u_short port;
  char *hostname;
  char *secret;
  int timeout;
  int accounting;
} radius_server_t;

typedef struct radius_conf_t {
  radius_server_t *server;
  int retries;
  int localifdown;
  char *client_id;
  int accounting_bug;
  int sockfd;
  int debug;
} radius_conf_t;


/*************************************************************************
 * Platform specific defines
 *************************************************************************/

#ifdef sun
#define PAM_EXTERN extern
/*
 *  On older versions of Solaris, you may have to change this to:
 *  #define CONST
 */
#define CONST const
#else
#define CONST const
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
#define CONF_FILE       "/etc/raddb/server"
#endif /* CONF_FILE */

#ifndef FALSE
#define FALSE 0
#undef TRUE
#define TRUE !FALSE
#endif

#endif /* PAM_RADIUS_H */
