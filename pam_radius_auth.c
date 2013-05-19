/*
 * $Id: pam_radius_auth.c,v 1.39 2007/03/26 05:35:31 fcusack Exp $
 * pam_radius_auth
 *      Authenticate a user via a RADIUS session
 *
 * 0.9.0 - Didn't compile quite right.
 * 0.9.1 - Hands off passwords properly.  Solaris still isn't completely happy
 * 0.9.2 - Solaris now does challenge-response.  Added configuration file
 *         handling, and skip_passwd field
 * 1.0.0 - Added handling of port name/number, and continue on select
 * 1.1.0 - more options, password change requests work now, too.
 * 1.1.1 - Added client_id=foo (NAS-Identifier), defaulting to PAM_SERVICE
 * 1.1.2 - multi-server capability.
 * 1.2.0 - ugly merger of pam_radius.c to get full RADIUS capability
 * 1.3.0 - added my own accounting code.  Simple, clean, and neat.
 * 1.3.1 - Supports accounting port (oops!), and do accounting authentication
 * 1.3.2 - added support again for 'skip_passwd' control flag.
 * 1.3.10 - ALWAYS add Password attribute, to make packets RFC compliant.
 * 1.3.11 - Bug fixes by Jon Nelson <jnelson@securepipe.com>
 * 1.3.12 - miscellanous bug fixes.  Don't add password to accounting
 *          requests; log more errors; add NAS-Port and NAS-Port-Type
 *          attributes to ALL packets.  Some patches based on input from 
 *          Grzegorz Paszka <Grzegorz.Paszka@pik-net.pl>
 * 1.3.13 - Always update the configuration file, even if we're given
 *          no options.  Patch from Jon Nelson <jnelson@securepipe.com>
 * 1.3.14 - Don't use PATH_MAX, so it builds on GNU Hurd.
 * 1.3.15 - Implement retry option, miscellanous bug fixes.
 * 1.3.16 - Miscellaneous fixes (see CVS for history)
 * 1.3.17 - Security fixes
 * 1.3.18 - Added IPv6 support. Servers can be IPv4 or IPv6 addresses. In 
 *          server config file, IPv6 addresses require brackets. Based on
 *          patch from Alan Carwile.
 *
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * The original pam_radius.c code is copyright (c) Cristian Gafton, 1996,
 *                                             <gafton@redhat.com>
 *
 * Some challenge-response code is copyright (c) CRYPTOCard Inc, 1998.
 *                                              All rights reserved.
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <limits.h>
#include <errno.h>

#ifdef sun
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_radius_auth.h"

#define DPRINT if (ctrl & PAM_DEBUG_ARG) _pam_log

/* TRACEPRINT macro can be used to produce developer-focused trace
 * output showing more information than what is printed with the config-
 * file requested DEBUG option. Added while extending to support IPv6.
 * Compile with "-DTRACEON" to enable trace output.
 */
#ifdef TRACEON
#define TRACEPRINT _pam_log
#else
#define TRACEPRINT if (0) _pam_log
#endif

/* internal data */
static CONST char *pam_module_name = "pam_radius_auth";
static char conf_file[BUFFER_SIZE]; /* configuration file */

/* we need to save these from open_session to close_session, since
 * when close_session will be called we won't be root anymore and
 * won't be able to access again the radius server configuration file
 * -- cristiang */
static radius_server_t *live_server = NULL;
static time_t session_time;

/* logging */
static void _pam_log(int err, CONST char *format, ...)
{
    va_list args;
    char buffer[BUFFER_SIZE];

    va_start(args, format);
    vsprintf(buffer, format, args);
    /* don't do openlog or closelog, but put our name in to be friendly */
    syslog(err, "%s: %s", pam_module_name, buffer);
    va_end(args);
}

/* argument parsing */
static int _pam_parse(int argc, CONST char **argv, radius_conf_t *conf)
{
  int ctrl=0;

  memset(conf, 0, sizeof(radius_conf_t)); /* ensure it's initialized */

  strcpy(conf_file, CONF_FILE);
  
  /*
   *  If either is not there, then we can't parse anything.
   */
  if ((argc == 0) || (argv == NULL)) {
    return ctrl;
  }
  
  /* step through arguments */
  for (ctrl=0; argc-- > 0; ++argv) {
    
    /* generic options */
    if (!strncmp(*argv,"conf=",5)) {
      strcpy(conf_file,*argv+5);

    } else if (!strcmp(*argv, "use_first_pass")) {
      ctrl |= PAM_USE_FIRST_PASS;

    } else if (!strcmp(*argv, "try_first_pass")) {
      ctrl |= PAM_TRY_FIRST_PASS;

    } else if (!strcmp(*argv, "skip_passwd")) {
      ctrl |= PAM_SKIP_PASSWD;

    } else if (!strncmp(*argv, "retry=", 6)) {
      conf->retries = atoi(*argv+6);

    } else if (!strcmp(*argv, "localifdown")) {
      conf->localifdown = 1;

    } else if (!strncmp(*argv, "client_id=", 10)) {
      if (conf->client_id) {
        _pam_log(LOG_WARNING, "ignoring duplicate '%s'", *argv);
      } else {
        conf->client_id = (char *) *argv+10; /* point to the client-id */
      }
    } else if (!strcmp(*argv, "accounting_bug")) {
      conf->accounting_bug = TRUE;

    } else if (!strcmp(*argv, "ruser")) {
      ctrl |= PAM_RUSER_ARG;

    } else if (!strcmp(*argv, "debug")) {
      ctrl |= PAM_DEBUG_ARG;
      conf->debug = 1;
      
    } else {
      _pam_log(LOG_WARNING, "unrecognized option '%s'", *argv);
    }
  }
  
  return ctrl;
}

/* Callback function used to free the saved return value for pam_setcred. */
void _int_free( pam_handle_t * pamh, void *x, int error_status )
{
    free(x);
}

/*
 * Removed ipstr2long and good_ipaddr helper functions which are IPv4 specific
 * and no longer needed since getaddrinfo() performs validation of IP addresses.
 * From the man page, getaddrinfo's first parameter "specifies either a numerical
 * network address (for IPv4, numbers-and-dots notation as supported by inet_aton(3);
 * for IPv6, hexadecimal string format as supported by inet_pton(3)), or a network
 * hostname."  The call to getaddrinfo performs a lookup and returns a list of
 * addrinfo structures, where each member has a sockaddr_storage structure, which
 * contains a generic form of an IP address, supporting both IPv4 and IPv6.
 *
 * Note that inet_aton(3) format allows some older-style IPv4 address, such as:
 *     10            which maps to  0.0.0.10
 *     10.1          which maps to 10.0.0.1
 *     10.1.1        which maps to 10.1.0.1
 */

/*
 * Return a pointer to an IP address in sockaddr_storage form when given a
 * host name, IPv4 address or IPv6 address, plus optional portstring.  Result is
 * placed in a static structure (ssip), so the caller must copy the value
 * out before this function gets called again.
 */
static struct sockaddr_storage * get_ipaddr(char *host, char *portstring) {
  static struct sockaddr_storage ssip;
  struct addrinfo hintsaddr;
  struct addrinfo *hostaddrs;
  int rc;
  int ctrl = 1; /* for DPRINT */
  
  if (!host) {
    DPRINT(LOG_DEBUG, "DEBUG: get_ipaddr() called with NULL host pointer.\n");
    return ((struct sockaddr_storage *) NULL);
  }

  TRACEPRINT(LOG_DEBUG, "Trace: in get_ipaddr('%s', '%s')\n", host, portstring);

  /* Resolve hostname into a valid IPv4 or IPv6 address.  Uses first address
     returned per discussion with Alan DeKok. */
  memset(&hintsaddr, 0, sizeof(struct addrinfo));
  hintsaddr.ai_family = AF_UNSPEC;
  hintsaddr.ai_socktype = SOCK_DGRAM;
  /* Considering whether AI_ADDRCONFIG should be set to scope addresses
   * to one IPv4 only or IPv6 only, or both, depending on whether this code
   * is running on a server with only IPv4 address, only IPv6 addresses, or
   * a mix of both.  Also considering whether AI_V4MAPPED should be set.
   * Neither is needed in testing thus far.  A future consideration.
   */
  /* hintsaddr.ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG); */

  if ((rc = getaddrinfo(host, portstring, &hintsaddr, &hostaddrs)) != 0) {
    /* non-zero return code is error. */
    DPRINT(LOG_DEBUG, "DEBUG: getaddrinfo('%s', '%s') returned %s.\n",
        host, portstring, gai_strerror(rc));
    return ((struct sockaddr_storage *) NULL);
  }

  /* Format the address (numeric host) and port (numeric service) for debug */
  char numHost[NI_MAXHOST], numService[NI_MAXSERV];
  rc = getnameinfo((struct sockaddr *) hostaddrs->ai_addr, hostaddrs->ai_addrlen,
                  numHost, NI_MAXHOST, numService, NI_MAXSERV,
                  NI_NUMERICHOST | NI_NUMERICSERV);
  if (rc == 0) {
    DPRINT(LOG_DEBUG, "DEBUG: getaddrinfo('%s', '%s') resolved to '%s:%s'\n", host, portstring,
           numHost, numService);
  } else {
    DPRINT(LOG_DEBUG, "DEBUG: getnameinfo: %s\n", gai_strerror(rc));
  }

  /* Save result to local static variable, free getaddrinfo results, and return result */
  memcpy(&ssip, hostaddrs->ai_addr, sizeof(struct sockaddr_storage));
  freeaddrinfo(hostaddrs);
  return (&ssip);
}

/*
 * host2server:  Convert server->hostname to server->ssip and server->port
 *
 * Given a pointer to a server structure which was created from a line in the
 * server config file, parse the server's "hostname" string, which might be a
 * "hostname:port" but is more likely an IPv4 or IPv6 address followed by a port.
 * Parse apart the information and perform address resolution, using
 * getaddrinfo().  The result is a sockaddr_storage structure that handles IPv4
 * or IPv6.  The sockaddr_storage structure gets written back to the server's
 * server->ssip field.  The server's port string is also converted into a port number
 * and written back to the server's server->port field.
 *
 * IPv6 addresses have a variable number of colons, up to seven.
 * The port string can be a name or value, but the port string is also optional.
 * Instead of requiring that IPv6 addresses be written in the longer form that
 * requires all seven colons (with intervening zeros), and instead of requiring
 * that the port string always be provided, we chose a different rule.  IPv6
 * addresses must be placed in square brackets.
 *
 * From /etc/raddb/server sample:
 *   # Server can be a hostname string or an IP address.  The :port portion is optional.
 *   # IPv6 addresses must be enclosed in square brackets [fdca:1:2::3:4].
 *   #
 *   # server{:port}                   shared_secret    timeout (seconds)
 *   vm-ac-radius-ipv6:1812             testing123          4
 *   192.168.42.63:1812                 testing123          3
 *   [1111:2222:3333:4444::1:3]:1812    testing123          3

 */
static int
host2server(radius_server_t *server)
{
  char *p;
  int ctrl = 1; /* for DPRINT */
  struct sockaddr_storage * ssipptr;
  int PORTSTRING_LEN = 256;
  char portstring[PORTSTRING_LEN];
  
  TRACEPRINT(LOG_DEBUG, "Trace: in host2server\n");

  /*
   * Break down server->hostname into component parts: the hostname/ipaddress
   * and the port string, noting that ipv6 addresses must be surrounded by 
   * brackets to "escape/protect" the colons inside vs. the :port (optional)
   * at the right end.
   */
  char *phost = server->hostname; /* start of unencumbered ipaddress or host. */
  char *ppast = server->hostname; /* past protected [<ipv6-address>], if any. */
  if (phost[0] == '[') {
    *(phost++) = ' ';  /* space intentially. */
    if ((ppast = strchr(phost, ']')) != NULL) {
      *(ppast++) = '\0';
    } else {
        /* Nothing after the left-bracket - return early */
        DPRINT(LOG_DEBUG, "DEBUG: host2server invalid server '%s'.\n", server->hostname);
        return PAM_AUTHINFO_UNAVAIL;
    }
  }

  /* Find and split off ':port' string. */
  p = NULL;
  if (ppast) {
      if ((p = strchr(ppast, ':')) != NULL) {
        *(p++) = '\0';              /* split the port off from the host name */
      }
  }

  /*
   * The code above transforms the server->hostname buffer in place, and gives
   * us two pointers to null-terminated strings in the buffer.  Below are two
   * examples:
   *
   * For IPv4 or a name, from    192.168.42.63:1812 into 192.168.42.63\01812
   * For IPv6,           from    [fdca:2::8]:1812   into  fdca:2::8\0\01812
   *
   * where  phost  points into it to the null-terminated host string,
   * and    p      points into it to the null-terminated port string, 1812
   */

  /*
   *  If the server port hasn't already been defined, go get it.
   */
  if (!server->port) {
    if (p && isdigit(*p)) {     /* port string looks like it's a number */
      unsigned int i = atoi(p) & 0xffff;
      
      if (!server->accounting) {
        server->port = htons((u_short) i);
      } else {
        server->port = htons((u_short) (i + 1));
      }
    } else {     /* port string might be missing or might be a service name */
      struct servent *svp = NULL;
      
      if (p) {   /* port string is not missing, look it up, might not be "radius" */
        TRACEPRINT(LOG_DEBUG, "DEBUG: calling getservbyname ('%s', 'udp').\n", p);
        if ((svp = getservbyname (p, "udp")) == NULL) {
            return PAM_AUTHINFO_UNAVAIL;
        }
        /* if it's the accounting stage, need to adjust to accounting port. */
        if (server->accounting) {
            /* convert to host order, add one, convert back to network order */
            svp->s_port = htons(ntohs(svp->s_port) + 1);
        }
      } else {   /* port string is missing, so look up radius or radacct */
        if (!server->accounting) {
          TRACEPRINT(LOG_DEBUG, "DEBUG: calling getservbyname ('radius', 'udp').\n");
          if ((svp = getservbyname ("radius", "udp")) == NULL) {
            return PAM_AUTHINFO_UNAVAIL;
          }
        } else {
          TRACEPRINT(LOG_DEBUG, "DEBUG: calling getservbyname ('radacct', 'udp').\n");
          if ((svp = getservbyname ("radacct", "udp")) == NULL) {
            return PAM_AUTHINFO_UNAVAIL;
          }
        }
      }
      
      server->port = svp->s_port;
    }
  }

  /* Convert port back to a string for get_ipaddr / getaddrinfo calls. */
  snprintf(portstring, PORTSTRING_LEN, "%hu", ntohs(server->port));
  TRACEPRINT(LOG_DEBUG, "DEBUG: in host2server, port after parsing/lookup is: %s\n",
      portstring);

  /* phost is the hostname or ipaddress string without optional :port, and with ipv6
   * brackets, if any, removed.
   */
  if ((ssipptr = get_ipaddr(phost, portstring)) == NULL) {
    DPRINT(LOG_DEBUG, "DEBUG: get_ipaddr('%s', '%s') returned 0.\n", server->hostname, portstring);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Save resolved address as sockaddr_storage into server's ssip field */
  memcpy(&(server->ssip), ssipptr, sizeof(struct sockaddr_storage));
  return PAM_SUCCESS;
}

/*
 * Do XOR of two buffers.
 */
static unsigned char *
xor(unsigned char *p, unsigned char *q, int length)
{
  int i;
  unsigned char *retval = p;
  
  for (i = 0; i < length; i++) {
    *(p++) ^= *(q++);
  }
  return retval;
}

/**************************************************************************
 * MID-LEVEL RADIUS CODE
 **************************************************************************/

/*
 * get a pseudo-random vector.
 */
static void
get_random_vector(unsigned char *vector)
{
#ifdef linux
  int fd = open("/dev/urandom",O_RDONLY); /* Linux: get *real* random numbers */
  int total = 0;
  if (fd >= 0) {
    while (total < AUTH_VECTOR_LEN) {
      int bytes = read(fd, vector + total, AUTH_VECTOR_LEN - total);
      if (bytes <= 0)
        break;                  /* oops! Error */
      total += bytes;
    }
    close(fd);
  }

  if (total != AUTH_VECTOR_LEN)
#endif
    {                           /* do this *always* on other platforms */
      MD5_CTX my_md5;
      struct timeval tv;
      struct timezone tz;
      static unsigned int session = 0; /* make the number harder to guess */
      
      /* Use the time of day with the best resolution the system can
         give us -- often close to microsecond accuracy. */
      gettimeofday(&tv,&tz);
      
      if (session == 0) {
        session = getppid();    /* (possibly) hard to guess information */
      }
      
      tv.tv_sec ^= getpid() * session++;
      
      /* Hash things to get maybe cryptographically strong pseudo-random numbers */
      MD5Init(&my_md5);
      MD5Update(&my_md5, (unsigned char *) &tv, sizeof(tv));
      MD5Update(&my_md5, (unsigned char *) &tz, sizeof(tz));
      MD5Final(vector, &my_md5);              /* set the final vector */
    }
}

/*
 * RFC 2139 says to do generate the accounting request vector this way.
 * However, the Livingston 1.16 server doesn't check it.  The Cistron
 * server (http://home.cistron.nl/~miquels/radius/) does, and this code
 * seems to work with it.  It also works with Funk's Steel-Belted RADIUS.
 */
static void
get_accounting_vector(AUTH_HDR *request, radius_server_t *server)
{
  MD5_CTX my_md5;
  int secretlen = strlen(server->secret);
  int len = ntohs(request->length);
  
  memset(request->vector, 0, AUTH_VECTOR_LEN);
  MD5Init(&my_md5);
  memcpy(((char *)request) + len, server->secret, secretlen);

  MD5Update(&my_md5, (unsigned char *)request, len + secretlen);
  MD5Final(request->vector, &my_md5);      /* set the final vector */
}

/*
 * Verify the response from the server
 */
static int
verify_packet(char *secret, AUTH_HDR *response, AUTH_HDR *request)
{
  MD5_CTX my_md5;
  unsigned char calculated[AUTH_VECTOR_LEN];
  unsigned char reply[AUTH_VECTOR_LEN];

  /*
   * We could dispense with the memcpy, and do MD5's of the packet
   * + vector piece by piece.  This is easier understand, and maybe faster.
   */
  memcpy(reply, response->vector, AUTH_VECTOR_LEN); /* save the reply */
  memcpy(response->vector, request->vector, AUTH_VECTOR_LEN); /* sent vector */
  
  /* MD5(response packet header + vector + response packet data + secret) */
  MD5Init(&my_md5);
  MD5Update(&my_md5, (unsigned char *) response, ntohs(response->length));

  /* 
   * This next bit is necessary because of a bug in the original Livingston
   * RADIUS server.  The authentication vector is *supposed* to be MD5'd
   * with the old password (as the secret) for password changes.
   * However, the old password isn't used.  The "authentication" vector
   * for the server reply packet is simply the MD5 of the reply packet.
   * Odd, the code is 99% there, but the old password is never copied
   * to the secret!
   */
  if (*secret) {
    MD5Update(&my_md5, (unsigned char *) secret, strlen(secret));
  }

  MD5Final(calculated, &my_md5);      /* set the final vector */

  /* Did he use the same random vector + shared secret? */
  if (memcmp(calculated, reply, AUTH_VECTOR_LEN) != 0) {
    return FALSE;
  }
  return TRUE;
}

/*
 * Find an attribute in a RADIUS packet.  Note that the packet length
 * is *always* kept in network byte order.
 */
static attribute_t *
find_attribute(AUTH_HDR *response, unsigned char type)
{
  attribute_t *attr = (attribute_t *) &response->data;

  int len = ntohs(response->length) - AUTH_HDR_LEN;

  while (attr->attribute != type) {
    if ((len -= attr->length) <= 0) {
      return NULL;              /* not found */
    }
    attr = (attribute_t *) ((char *) attr + attr->length);
  }

  return attr;
}

/*
 * Add an attribute to a RADIUS packet.
 */
static void
add_attribute(AUTH_HDR *request, unsigned char type, CONST unsigned char *data, int length)
{
  attribute_t *p;

  p = (attribute_t *) ((unsigned char *)request + ntohs(request->length));
  p->attribute = type;
  p->length = length + 2;               /* the total size of the attribute */
  request->length = htons(ntohs(request->length) + p->length);
  memcpy(p->data, data, length);
}

/*
 * Add an integer attribute to a RADIUS packet.
 */
static void
add_int_attribute(AUTH_HDR *request, unsigned char type, int data)
{
  int value = htonl(data);
  
  add_attribute(request, type, (unsigned char *) &value, sizeof(int));
}

/* 
 * Add a RADIUS password attribute to the packet.  Some magic is done here.
 *
 * If it's an PW_OLD_PASSWORD attribute, it's encrypted using the encrypted
 * PW_PASSWORD attribute as the initialization vector.
 *
 * If the password attribute already exists, it's over-written.  This allows
 * us to simply call add_password to update the password for different
 * servers.
 */
static void
add_password(AUTH_HDR *request, unsigned char type, CONST char *password, char *secret)
{
  MD5_CTX md5_secret, my_md5;
  unsigned char misc[AUTH_VECTOR_LEN];
  int i;
  int length = strlen(password);
  unsigned char hashed[256 + AUTH_PASS_LEN]; /* can't be longer than this */
  unsigned char *vector;
  attribute_t *attr;

  if (length > MAXPASS) {       /* shorten the password for now */
    length = MAXPASS;
  }

  if (length == 0) {
    length = AUTH_PASS_LEN;     /* 0 maps to 16 */
  } if ((length & (AUTH_PASS_LEN - 1)) != 0) {
    length += (AUTH_PASS_LEN - 1); /* round it up */
    length &= ~(AUTH_PASS_LEN - 1); /* chop it off */
  }                             /* 16*N maps to itself */

  memset(hashed, 0, length);
  memcpy(hashed, password, strlen(password));

  attr = find_attribute(request, PW_PASSWORD);

  if (type == PW_PASSWORD) {
    vector = request->vector;
  } else {
    vector = attr->data;        /* attr CANNOT be NULL here. */
  }

  /* ************************************************************ */
  /* encrypt the password */
  /* password : e[0] = p[0] ^ MD5(secret + vector) */
  MD5Init(&md5_secret);
  MD5Update(&md5_secret, (unsigned char *) secret, strlen(secret));
  my_md5 = md5_secret;          /* so we won't re-do the hash later */
  MD5Update(&my_md5, vector, AUTH_VECTOR_LEN);
  MD5Final(misc, &my_md5);      /* set the final vector */
  xor(hashed, misc, AUTH_PASS_LEN);
  
  /* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
  for (i = 1; i < (length >> 4); i++) {
    my_md5 = md5_secret;        /* grab old value of the hash */
    MD5Update(&my_md5, &hashed[(i-1) * AUTH_PASS_LEN], AUTH_PASS_LEN);
    MD5Final(misc, &my_md5);      /* set the final vector */
    xor(&hashed[i * AUTH_PASS_LEN], misc, AUTH_PASS_LEN);
  }

  if (type == PW_OLD_PASSWORD) {
    attr = find_attribute(request, PW_OLD_PASSWORD);
  }
  
  if (!attr) {
    add_attribute(request, type, hashed, length);
  } else {
    memcpy(attr->data, hashed, length); /* overwrite the packet */
  }
}

static void
cleanup(radius_server_t *server)
{
  radius_server_t *next;

  TRACEPRINT(LOG_DEBUG, "Trace: in cleanup\n");
  
  while (server) {
    next = server->next;
    _pam_drop(server->hostname);
    _pam_forget(server->secret);
    _pam_drop(server);
    server = next;
  }
}

/*
 * allocate and open a local port for communication with the RADIUS
 * server
 */
static int
initialize(radius_conf_t *conf, int accounting)
{
  struct sockaddr_in6 salocal6;
  u_short local_port;
  char hostname[BUFFER_SIZE];
  char secret[BUFFER_SIZE];
  
  char buffer[BUFFER_SIZE];
  char *p;
  FILE *fserver;
  radius_server_t *server = NULL;
  int timeout;
  int line = 0;

  TRACEPRINT(LOG_DEBUG, "Trace: in initialize, reading servers from file\n");

  /* the first time around, read the configuration file */
  if ((fserver = fopen (conf_file, "r")) == (FILE*)NULL) {
    _pam_log(LOG_ERR, "Could not open configuration file %s: %s\n",
            conf_file, strerror(errno));
    return PAM_ABORT;
  }
  
  while (!feof(fserver) &&
         (fgets (buffer, sizeof(buffer), fserver) != (char*) NULL) &&
         (!ferror(fserver))) {
    line++;
    p = buffer;

    /*
     *  Skip blank lines and whitespace
     */
    while (*p &&
           ((*p == ' ') || (*p == '\t') ||
            (*p == '\r') || (*p == '\n'))) p++;
    
    /*
     *  Nothing, or just a comment.  Ignore the line.
     */
    if ((!*p) || (*p == '#')) {
      continue;
    }
    
    timeout = 3;
    if (sscanf(p, "%s %s %d", hostname, secret, &timeout) < 2) {
      _pam_log(LOG_ERR, "ERROR reading %s, line %d: Could not read hostname or secret\n",
               conf_file, line);
      continue; /* invalid line */
    } else {                    /* read it in and save the data */
      radius_server_t *tmp;
      
      TRACEPRINT(LOG_DEBUG, "Trace: in initialize, read server: %s %s %d\n", hostname, secret, timeout);

      tmp = malloc(sizeof(radius_server_t));
      if (server) {
        server->next = tmp;
        server = server->next;
      } else {
        conf->server = tmp;
        server= tmp;            /* first time */
      }
      
      /* sometime later do memory checks here */
      server->hostname = strdup(hostname);
      server->secret = strdup(secret);
      server->accounting = accounting;
      server->port = 0;

      if ((timeout < 1) || (timeout > 60)) {
        server->timeout = 3;
      } else {
        server->timeout = timeout;
      }
      server->next = NULL;
    }
  }
  fclose(fserver);
  
  if (!server) {                /* no server found, die a horrible death */
    _pam_log(LOG_ERR, "No RADIUS server found in configuration file %s\n",
             conf_file);
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  TRACEPRINT(LOG_DEBUG, "Trace: in initialize, creating socket conf->sockfd\n");

  /* open a socket.  Dies if it fails */
  conf->sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (conf->sockfd <= 0) {
    _pam_log(LOG_ERR, "Failed to open RADIUS socket: %s\n", strerror(errno));
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Set option to allow socket to do both IPv4 and IPv6 communications. Some
   * OS's default this option to on, and some to off. It may vary depending
   * on the particular release number of an operating system.  Use the command
   *   $ sysctl  -a | grep ipv6.bindv6only
   *   net.ipv6.bindv6only = 0
   * to find a system's default value. However, we still force the setting.
   */
  int no = 0;
  if ((setsockopt(conf->sockfd, SOL_IPV6, IPV6_V6ONLY, &no, sizeof(no))) < 0) {
    _pam_log(LOG_ERR, "Failure turning off IPV6_V6ONLY. setsockopt error: %s.", strerror(errno));
    return PAM_AUTHINFO_UNAVAIL;
  }
                                             
  /* set up the local end of the socket communications */
  memset ((char *) &salocal6, '\0', sizeof(struct sockaddr_in6));
  salocal6.sin6_family = AF_INET6;
  salocal6.sin6_addr = in6addr_any;

  /*
   *  Previous versions looped to try different local ports based from process's pid,
   *  but we now let the stack pick the local port by specifying zero as port.
   */
  local_port = 0;
  salocal6.sin6_port = htons(local_port);

  TRACEPRINT(LOG_DEBUG, "Trace: binding conf->sockfd\n");
  if (bind(conf->sockfd, (struct sockaddr *) &salocal6, sizeof (struct sockaddr_in6)) < 0) {
    int errsave = errno;
    close(conf->sockfd);
    _pam_log(LOG_ERR, "No open port we could bind to.  bind error: %s.", strerror(errsave));
    return PAM_AUTHINFO_UNAVAIL;
  }
      
  return PAM_SUCCESS;
}

/*
 * The IP address for the client is placed in the RADIUS packet and tagged
 * according to the type (IP for AF_INET, IPV6 for AF_INET6).
 */
static void
add_ssip_attribute(AUTH_HDR *request, struct sockaddr_storage * ssipptr)
{
  switch (ssipptr->ss_family) {
  case AF_INET:
      add_attribute(request, PW_NAS_IP_ADDRESS,
          (unsigned char *)&((struct sockaddr_in *)ssipptr)->sin_addr, 4);
      break;
  case AF_INET6:
      add_attribute(request, PW_NAS_IPV6_ADDRESS,
          (unsigned char *)&((struct sockaddr_in6 *)ssipptr)->sin6_addr, 16);
      break;
  default:
      break;
  }
}

/*
 * Helper function for building a radius packet.
 * It initializes *some* of the header, and adds common attributes.
 */
static void
build_radius_packet(AUTH_HDR *request, CONST char *user, CONST char *password, radius_conf_t *conf)
{
  char hostname[HOST_NAME_MAX+1];
  struct sockaddr_storage * ssipptr;
  int rc;
  
  TRACEPRINT(LOG_DEBUG, "Trace: in build_radius_packet\n");

  /* Use IPv4 loopback if we cannot determine hostname of this system */
  hostname[0] = '\0';
  if ((rc = gethostname(hostname, HOST_NAME_MAX)) < 0) {
    int errsave = errno;
    _pam_log(LOG_ERR, "Attempt to gethostname failed with error: %s.", strerror(errsave));
    strcpy(hostname, "127.0.0.1");
  }
  /* With very long names, some systems don't make sure result is null-terminated. */
  hostname[HOST_NAME_MAX] = '\0';
  /* If name could not be retrieved, use the loopback address. */
  if (!(hostname[0])) strcpy(hostname, "127.0.0.1");

  request->length = htons(AUTH_HDR_LEN);

  if (password) {               /* make a random authentication req vector */
    get_random_vector(request->vector);
  }
  
  add_attribute(request, PW_USER_NAME, (unsigned char *) user, strlen(user));

  /*
   *  Add a password, if given.
   */
  if (password) {
    add_password(request, PW_PASSWORD, password, conf->server->secret);

    /*
     *  Add a NULL password to non-accounting requests.
     */
  } else if (request->code != PW_ACCOUNTING_REQUEST) {
    add_password(request, PW_PASSWORD, "", conf->server->secret);
  }

  /*
   * Convert this host's hostname into an ip address if possible.
   * When looking up this host's ip address, note that the port is not meaningful, hence "".
   * If we can't determine an IP address, then don't add one.
   */
  if ((ssipptr = get_ipaddr(hostname, "")) != NULL) {
    add_ssip_attribute(request, ssipptr);
  }

  /* There's always a NAS identifier */
  if (conf->client_id && *conf->client_id) {
    add_attribute(request, PW_NAS_IDENTIFIER, (unsigned char *) conf->client_id,
                  strlen(conf->client_id));
  }

  /*
   *  Add in the port (pid) and port type (virtual).
   *
   *  We might want to give the TTY name here, too.
   */
  add_int_attribute(request, PW_NAS_PORT_ID, getpid());
  add_int_attribute(request, PW_NAS_PORT_TYPE, PW_NAS_PORT_TYPE_VIRTUAL);
}

/*
 * Talk RADIUS to a server.
 * Send a packet and get the response
 */
static int
talk_radius(radius_conf_t *conf, AUTH_HDR *request, AUTH_HDR *response,
            char *password, char *old_password, int tries)
{
  socklen_t salen;
  int total_length;
  fd_set set;
  struct timeval tv;
  time_t now, end;
  int rcode;
  struct sockaddr_storage saremote;
  radius_server_t *server = conf->server;
  int ok;
  int server_tries;
  int retval;

  TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius\n");

  /* ************************************************************ */
  /* Now that we're done building the request, we can send it */

  /*
    Hmm... on password change requests, all of the found server information
    could be saved with a pam_set_data(), which means even the radius_conf_t
    information will have to be malloc'd at some point

    On the other hand, we could just try all of the servers again in
    sequence, on the off chance that one may have ended up fixing itself.
    
    */
  
  /* loop over all available servers */
  while (server != NULL) {

    /* only look up IP information as necessary */
    if ((retval = host2server(server)) != PAM_SUCCESS) {
      _pam_log(LOG_ERR,
               "Failed looking up IP address for RADIUS server %s (errcode=%d)",
               server->hostname, retval);
      ok = FALSE;
      goto next;                /* skip to the next server */
    }

    total_length = ntohs(request->length);
    
    if (!password) {            /* make an RFC 2139 p6 request authenticator */
      get_accounting_vector(request, server);
    }

    server_tries = tries;
send:

    if (server->ssip.ss_family == AF_INET) {
        salen = sizeof (struct sockaddr_in);
    } else {
        salen = sizeof (struct sockaddr_in6);
    }

    TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius, sending on conf->sockfd\n");

    /* send the packet */
    if (sendto(conf->sockfd, (char *) request, total_length, 0,
               ((struct sockaddr *)&(server->ssip)), salen) < 0) {
      _pam_log(LOG_ERR, "Error sending RADIUS packet to server %s: %s",
               server->hostname, strerror(errno));
      ok = FALSE;
      goto next;                /* skip to the next server */
    }

    /* ************************************************************ */
    /* Wait for the response, and verify it. */
    tv.tv_sec = server->timeout; /* wait for the specified time */
    tv.tv_usec = 0;
    FD_ZERO(&set);              /* clear out the set */
    FD_SET(conf->sockfd, &set); /* wait only for the RADIUS UDP socket */
    
    time(&now);
    end = now + tv.tv_sec;
    
    /* loop, waiting for the select to return data */
    ok = TRUE;
    while (ok) {

      TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius, at select call\n");

      rcode = select(conf->sockfd + 1, &set, NULL, NULL, &tv);

      /* select timed out */
      if (rcode == 0) {
        _pam_log(LOG_ERR, "RADIUS server %s failed to respond, time out",
                 server->hostname);
        if (--server_tries)
          goto send;
        ok = FALSE;
        break;                  /* exit from the select loop */
      } else if (rcode < 0) {

        /* select had an error */
        if (errno == EINTR) {   /* we were interrupted */
          time(&now);
          
          if (now > end) {
            _pam_log(LOG_ERR, "RADIUS server %s failed to respond, interrupted",
                     server->hostname);
            if (--server_tries)
              goto send;
            ok = FALSE;
            break;                      /* exit from the select loop */
          }
          
          tv.tv_sec = end - now;
          if (tv.tv_sec == 0) { /* keep waiting */
            tv.tv_sec = 1;
          }

        } else {                /* not an interrupt, it was a real error */
          _pam_log(LOG_ERR, "Error waiting for response from RADIUS server %s: %s",
                   server->hostname, strerror(errno));
          ok = FALSE;
          break;
        }

        /* the select returned OK */
      } else if (FD_ISSET(conf->sockfd, &set)) {

        TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius, calling recvfrom on conf-sockfd\n");
        
        /* try to receive some data */
        salen = sizeof(struct sockaddr_storage); /* init large enough for ipv4 or ipv6 */
        if ((total_length = recvfrom(conf->sockfd, (void *) response,
                                     BUFFER_SIZE,
                                     0, (struct sockaddr *)&saremote, &salen)) < 0) {
          _pam_log(LOG_ERR, "error reading RADIUS packet from server %s: %s",
                   server->hostname, strerror(errno));
          ok = FALSE;
          break;

        } else {
          /* there's data, see if it's valid */
          char *p = server->secret;
          
          if ((ntohs(response->length) != total_length) ||
              (ntohs(response->length) > BUFFER_SIZE)) {
            _pam_log(LOG_ERR, "RADIUS packet from server %s is corrupted",
                     server->hostname);
            ok = FALSE;
            break;
          }

          /* Check if we have the data OK.  We should also check request->id */

          if (password) {
            if (old_password) {
#ifdef LIVINGSTON_PASSWORD_VERIFY_BUG_FIXED
              p = old_password; /* what it should be */
#else
              p = "";           /* what it really is */
#endif
            }
            /* 
             * RFC 2139 p.6 says not do do this, but the Livingston 1.16
             * server disagrees.  If the user says he wants the bug, give in.
             */
          } else {              /* authentication request */
            if (conf->accounting_bug) {
              p = "";
            }
          }
            
          if (!verify_packet(p, response, request)) {
            _pam_log(LOG_ERR, "packet from RADIUS server %s fails verification: The shared secret is probably incorrect.",
                     server->hostname);
            ok = FALSE;
            break;
          }

          /*
           * Check that the response ID matches the request ID.
           */
          if (response->id != request->id) {
            _pam_log(LOG_WARNING, "Response packet ID %d does not match the request packet ID %d: verification of packet fails", response->id, request->id);
              ok = FALSE;
            break;
          }
        }
        
        /*
         * Whew!  The select is done.  It hasn't timed out, or errored out.
         * It's our descriptor.  We've got some data.  It's the right size.
         * The packet is valid.
         * NOW, we can skip out of the select loop, and process the packet
         */
        break;
      }
      /* otherwise, we've got data on another descriptor, keep select'ing */
    }

    /* go to the next server if this one didn't respond */
  next:
    if (!ok) {
      radius_server_t *old;     /* forget about this server */
      
      old = server;
      server = server->next;
      conf->server = server;

      _pam_forget(old->secret);
      free(old->hostname);
      free(old);

      if (server) {             /* if there's more servers to check */

        TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius, proceeding to next server\n");

        /* get a new authentication vector, and update the passwords */
        get_random_vector(request->vector);
        request->id = request->vector[0];
        
        /* update passwords, as appropriate */
        if (password) {
          get_random_vector(request->vector);
          if (old_password) {   /* password change request */
            add_password(request, PW_PASSWORD, password, old_password);
            add_password(request, PW_OLD_PASSWORD, old_password, old_password);
          } else {              /* authentication request */
            add_password(request, PW_PASSWORD, password, server->secret);
          }
        }
      }
      continue;

    } else {
      /* we've found one that does respond, forget about the other servers */

      TRACEPRINT(LOG_DEBUG, "Trace: in talk_radius, found server that does respond\n");

      cleanup(server->next);
      server->next = NULL;
      live_server = server;     /* we've got a live one! */
      break;
    }
  }

  if (!server) {
    _pam_log(LOG_ERR, "All RADIUS servers failed to respond.");
    if (conf->localifdown)
      retval = PAM_IGNORE;
    else
      retval = PAM_AUTHINFO_UNAVAIL;
  } else {
    retval = PAM_SUCCESS;
  }

  return retval;
}

/**************************************************************************
 * MIDLEVEL PAM CODE
 **************************************************************************/

/* this is our front-end for module-application conversations */

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return retval; }

static int rad_converse(pam_handle_t *pamh, int msg_style, char *message, char **password)
{
  CONST struct pam_conv *conv;
  struct pam_message resp_msg;
  CONST struct pam_message *msg[1];
  struct pam_response *resp = NULL;
  int retval;
  
  TRACEPRINT(LOG_DEBUG, "Trace: in rad_converse\n");

  resp_msg.msg_style = msg_style;
  resp_msg.msg = message;
  msg[0] = &resp_msg;
  
  /* grab the password */
  retval = pam_get_item(pamh, PAM_CONV, (CONST void **) &conv);
  PAM_FAIL_CHECK;
  
  retval = conv->conv(1, msg, &resp,conv->appdata_ptr);
  PAM_FAIL_CHECK;
  
  if (password) {               /* assume msg.type needs a response */
    /* I'm not sure if this next bit is necessary on Linux */
#ifdef sun
    /* NULL response, fail authentication */
    if ((resp == NULL) || (resp->resp == NULL)) {
      return PAM_SYSTEM_ERR;
    }
#endif
    
    *password = resp->resp;
    free(resp);
  }
  
  return PAM_SUCCESS;
}

/**************************************************************************
 * GENERAL CODE
 **************************************************************************/

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {     \
        int *pret = malloc( sizeof(int) );              \
        *pret = retval;                                 \
        pam_set_data( pamh, "rad_setcred_return"        \
                      , (void *) pret, _int_free );     \
        return retval; }

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  CONST char *user;
  CONST char *userinfo;
  char *password = NULL;
  CONST char *rhost;
  char *resp2challenge = NULL;
  int ctrl;
  int retval = PAM_AUTH_ERR;

  char recv_buffer[4096];
  char send_buffer[4096];
  AUTH_HDR *request = (AUTH_HDR *) send_buffer;
  AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
  radius_conf_t config;

  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_authenticate\n");

  ctrl = _pam_parse(argc, argv, &config);

  /* grab the user name */
  retval = pam_get_user(pamh, &user, NULL);
  PAM_FAIL_CHECK;

  /* check that they've entered something, and not too long, either */
  if ((user == NULL) ||
      (strlen(user) > MAXPWNAM)) {
    int *pret = malloc( sizeof(int) );
    *pret = PAM_USER_UNKNOWN;
    pam_set_data( pamh, "rad_setcred_return", (void *) pret, _int_free );

    DPRINT(LOG_DEBUG, "User name was NULL, or too long");
    return PAM_USER_UNKNOWN;
  }
  DPRINT(LOG_DEBUG, "Got user name %s", user);

  if (ctrl & PAM_RUSER_ARG) {
    retval = pam_get_item(pamh, PAM_RUSER, (CONST void **) &userinfo);
    PAM_FAIL_CHECK;
    DPRINT(LOG_DEBUG, "Got PAM_RUSER name %s", userinfo);

    if (!strcmp("root", user)) {
      user = userinfo;
      DPRINT(LOG_DEBUG, "Username now %s from ruser", user);
    } else {
      DPRINT(LOG_DEBUG, "Skipping ruser for non-root auth");
    };
  };

  /*
   * Get the IP address of the authentication server
   * Then, open a socket, and bind it to a port
   */
  retval = initialize(&config, FALSE);
  PAM_FAIL_CHECK;

  /* 
   * If there's no client id specified, use the service type, to help
   * keep track of which service is doing the authentication.
   */
  if (!config.client_id) {
    retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) &config.client_id);
    PAM_FAIL_CHECK;
  }

  /* now we've got a socket open, so we've got to clean it up on error */
#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

  /* build and initialize the RADIUS packet */
  request->code = PW_AUTHENTICATION_REQUEST;
  get_random_vector(request->vector);
  request->id = request->vector[0]; /* this should be evenly distributed */
  
  /* grab the password (if any) from the previous authentication layer */
  retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &password);
  PAM_FAIL_CHECK;

  if(password) {
    password = strdup(password);
    DPRINT(LOG_DEBUG, "Got password %s", password);
  }

  /* no previous password: maybe get one from the user */
  if (!password) {
    if (ctrl & PAM_USE_FIRST_PASS) {
      retval = PAM_AUTH_ERR;    /* use one pass only, stopping if it fails */
      goto error;
    }
    
    /* check to see if we send a NULL password the first time around */
    if (!(ctrl & PAM_SKIP_PASSWD)) {
      retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
      TRACEPRINT(LOG_DEBUG, "Trace: Back in pam_sm_authenticate (1), after rad_converse\n");
      PAM_FAIL_CHECK;

    }
  } /* end of password == NULL */

  build_radius_packet(request, user, password, &config);
  /* not all servers understand this service type, but some do */
  add_int_attribute(request, PW_USER_SERVICE_TYPE, PW_AUTHENTICATE_ONLY);

  /*
   *  Tell the server which host the user is coming from.
   *
   *  Note that this is NOT the IP address of the machine running PAM!
   *  It's the IP address of the client.
   */
  retval = pam_get_item(pamh, PAM_RHOST, (CONST void **) &rhost);
  PAM_FAIL_CHECK;
  if (rhost) {
    add_attribute(request, PW_CALLING_STATION_ID, (unsigned char *) rhost,
                  strlen(rhost));
  }

  DPRINT(LOG_DEBUG, "Sending RADIUS request code %d", request->code);

  retval = talk_radius(&config, request, response, password,
                       NULL, config.retries + 1);
  PAM_FAIL_CHECK;

  DPRINT(LOG_DEBUG, "Got RADIUS response code %d", response->code);

  /*
   *  If we get an authentication failure, and we sent a NULL password,
   *  ask the user for one and continue.
   *
   *  If we get an access challenge, then do a response, for as many
   *  challenges as we receive.
   */
  while (response->code == PW_ACCESS_CHALLENGE) {
    attribute_t *a_state, *a_reply;
    char challenge[BUFFER_SIZE];

    /* Now we do a bit more work: challenge the user, and get a response */
    if (((a_state = find_attribute(response, PW_STATE)) == NULL) ||
        ((a_reply = find_attribute(response, PW_REPLY_MESSAGE)) == NULL)) {
      /* Actually, State isn't required. */
      _pam_log(LOG_ERR, "RADIUS Access-Challenge received with State or Reply-Message missing");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto error;
    }

    /*
     *  Security fixes.
     */
    if ((a_state->length <= 2) || (a_reply->length <= 2)) {
      _pam_log(LOG_ERR, "RADIUS Access-Challenge received with invalid State or Reply-Message");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto error;
    }

    memcpy(challenge, a_reply->data, a_reply->length - 2);
    challenge[a_reply->length - 2] = 0;

    /* It's full challenge-response, we should have echo on */
    retval = rad_converse(pamh, PAM_PROMPT_ECHO_ON, challenge, &resp2challenge);
    TRACEPRINT(LOG_DEBUG, "Trace: Back in pam_sm_authenticate (2), after rad_converse\n");

    /* now that we've got a response, build a new radius packet */
    build_radius_packet(request, user, resp2challenge, &config);
    /* request->code is already PW_AUTHENTICATION_REQUEST */
    request->id++;              /* one up from the request */

    /* copy the state over from the servers response */
    add_attribute(request, PW_STATE, a_state->data, a_state->length - 2);

    retval = talk_radius(&config, request, response, resp2challenge, NULL, 1);
    PAM_FAIL_CHECK;

    DPRINT(LOG_DEBUG, "Got response to challenge code %d", response->code);
  }

  /* Whew! Done the pasword checks, look for an authentication acknowledge */
  if (response->code == PW_AUTHENTICATION_ACK) {
    retval = PAM_SUCCESS;
  } else {
    retval = PAM_AUTH_ERR;      /* authentication failure */

error:
    /* If there was a password pass it to the next layer */
    if (password && *password) {
      pam_set_item(pamh, PAM_AUTHTOK, password);
    }
  }

  if (ctrl & PAM_DEBUG_ARG) {
    _pam_log(LOG_DEBUG, "authentication %s"
             , retval==PAM_SUCCESS ? "succeeded":"failed" );
  }
  
  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_authenticate, closing config.sockfd and cleanup server list\n");

  close(config.sockfd);
  cleanup(config.server);
  _pam_forget(password);
  _pam_forget(resp2challenge);
  {
    int *pret = malloc( sizeof(int) );
    *pret = retval;
    pam_set_data( pamh, "rad_setcred_return", (void *) pret, _int_free );
  }
  return retval;
}

/*
 * Return a value matching the return value of pam_sm_authenticate, for
 * greatest compatibility. 
 * (Always returning PAM_SUCCESS breaks other authentication modules;
 * always returning PAM_IGNORE breaks PAM when we're the only module.)
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  int retval, *pret;

  retval = PAM_SUCCESS;
  pret = &retval;
  pam_get_data( pamh, "rad_setcred_return", (CONST void **) &pret );
  return *pret;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return PAM_SESSION_ERR; }

static int
pam_private_session(pam_handle_t *pamh, int flags,
                    int argc, CONST char **argv,
                    int status)
{
  CONST char *user;
  int ctrl;
  int retval = PAM_AUTH_ERR;

  char recv_buffer[4096];
  char send_buffer[4096];
  AUTH_HDR *request = (AUTH_HDR *) send_buffer;
  AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
  radius_conf_t config;

  ctrl = _pam_parse(argc, argv, &config);

  TRACEPRINT(LOG_DEBUG, "Trace: in pam_private_session\n");

  /* grab the user name */
  retval = pam_get_user(pamh, &user, NULL);
  PAM_FAIL_CHECK;

  /* check that they've entered something, and not too long, either */
  if ((user == NULL) ||
      (strlen(user) > MAXPWNAM)) {
    return PAM_USER_UNKNOWN;
  }

  /*
   * Get the IP address of the authentication server
   * Then, open a socket, and bind it to a port
   */
  retval = initialize(&config, TRUE);
  PAM_FAIL_CHECK;

  /* 
   * If there's no client id specified, use the service type, to help
   * keep track of which service is doing the authentication.
   */
  if (!config.client_id) {
    retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) &config.client_id);
    PAM_FAIL_CHECK;
  }

  /* now we've got a socket open, so we've got to clean it up on error */
#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

  /* build and initialize the RADIUS packet */
  request->code = PW_ACCOUNTING_REQUEST;
  get_random_vector(request->vector);
  request->id = request->vector[0]; /* this should be evenly distributed */

  build_radius_packet(request, user, NULL, &config);

  add_int_attribute(request, PW_ACCT_STATUS_TYPE, status);

  sprintf(recv_buffer, "%08d", (int) getpid());
  add_attribute(request, PW_ACCT_SESSION_ID, (unsigned char *) recv_buffer,
                strlen(recv_buffer));

  add_int_attribute(request, PW_ACCT_AUTHENTIC, PW_AUTH_RADIUS);

  if (status == PW_STATUS_START) {
    session_time = time(NULL);
  } else {
    add_int_attribute(request, PW_ACCT_SESSION_TIME, time(NULL) - session_time);
  }

  retval = talk_radius(&config, request, response, NULL, NULL, 1);
  PAM_FAIL_CHECK;

  /* oops! They don't have the right password.  Complain and die. */
  if (response->code != PW_ACCOUNTING_RESPONSE) {
    retval = PAM_PERM_DENIED;
    goto error;
  }

  retval = PAM_SUCCESS;

error:

  TRACEPRINT(LOG_DEBUG, "Trace: in pam_private_session, close config.sockfd and cleanup server list\n");

  close(config.sockfd);
  cleanup(config.server);

  return retval;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
                    int argc, CONST char **argv)
{
  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_open_session\n");
  return pam_private_session(pamh, flags, argc, argv, PW_STATUS_START);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
                     int argc, CONST char **argv)
{
  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_close_session\n");
  return pam_private_session(pamh, flags, argc, argv, PW_STATUS_STOP);
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {return retval; }
#define MAX_PASSWD_TRIES 3

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, CONST char **argv)
{
  CONST char *user;
  char *password = NULL;
  char *new_password = NULL;
  char *check_password = NULL;
  int ctrl;
  int retval = PAM_AUTHTOK_ERR;
  int attempts;

  char recv_buffer[4096];
  char send_buffer[4096];
  AUTH_HDR *request = (AUTH_HDR *) send_buffer;
  AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
  radius_conf_t config;

  ctrl = _pam_parse(argc, argv, &config);

  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_chauthtok\n");

  /* grab the user name */
  retval = pam_get_user(pamh, &user, NULL);
  PAM_FAIL_CHECK;

  /* check that they've entered something, and not too long, either */
  if ((user == NULL) ||
      (strlen(user) > MAXPWNAM)) {
    return PAM_USER_UNKNOWN;
  }

  /*
   * Get the IP address of the authentication server
   * Then, open a socket, and bind it to a port
   */
  retval = initialize(&config, FALSE);
  PAM_FAIL_CHECK;

  /* 
   * If there's no client id specified, use the service type, to help
   * keep track of which service is doing the authentication.
   */
  if (!config.client_id) {
    retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) &config.client_id);
    PAM_FAIL_CHECK;
  }

  /* now we've got a socket open, so we've got to clean it up on error */
#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

  /* grab the old password (if any) from the previous password layer */
  retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (CONST void **) &password);
  PAM_FAIL_CHECK;
  if(password) password = strdup(password);

  /* grab the new password (if any) from the previous password layer */
  retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &new_password);
  PAM_FAIL_CHECK;
  if(new_password) new_password = strdup(new_password);

  /* preliminary password change checks. */
  if (flags & PAM_PRELIM_CHECK) {
    if (!password) {            /* no previous password: ask for one */
      retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
      TRACEPRINT(LOG_DEBUG, "Trace: Back in pam_sm_chauthtok, after rad_converse\n");
      PAM_FAIL_CHECK;
    }
    
    /*
     * We now check the password to see if it's the right one.
     * If it isn't, we let the user try again.
     * Note that RADIUS doesn't have any concept of 'root'.  The only way
     * that root can change someone's password is to log into the RADIUS
     * server, and and change it there.
     */
    
    /* build and initialize the access request RADIUS packet */
    request->code = PW_AUTHENTICATION_REQUEST;
    get_random_vector(request->vector);
    request->id = request->vector[0]; /* this should be evenly distributed */
    
    build_radius_packet(request, user, password, &config);
    add_int_attribute(request, PW_USER_SERVICE_TYPE, PW_AUTHENTICATE_ONLY);
    
    retval = talk_radius(&config, request, response, password, NULL, 1);
    PAM_FAIL_CHECK;

    /* oops! They don't have the right password.  Complain and die. */
    if (response->code != PW_AUTHENTICATION_ACK) {
      _pam_forget(password);
      retval = PAM_PERM_DENIED;
      goto error;
    }

    /*
     * We're now sure it's the right user.
     * Ask for their new password, if appropriate
     */
    TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_chauthtok, at new password logic\n");
    
    if (!new_password) {        /* not found yet: ask for it */
      int new_attempts;
      attempts = 0;

      /* loop, trying to get matching new passwords */
      while (attempts++ < 3) {

        /* loop, trying to get a new password */
        new_attempts = 0;
        while (new_attempts++ < 3) {
          retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF,
                                "New password: ", &new_password);
          PAM_FAIL_CHECK;
          
          /* the old password may be short.  Check it, first. */
          if (strcmp(password, new_password) == 0) { /* are they the same? */
            rad_converse(pamh, PAM_ERROR_MSG,
                         "You must choose a new password.", NULL);
            _pam_forget(new_password);
            continue;
          } else if (strlen(new_password) < 6) {
            rad_converse(pamh, PAM_ERROR_MSG, "it's WAY too short", NULL);
            _pam_forget(new_password);
            continue;
          }

          /* insert crypt password checking here */
          
          break;                /* the new password is OK */
        }
        
        if (new_attempts >= 3) { /* too many new password attempts: die */
          retval = PAM_AUTHTOK_ERR;
          goto error;
        }
        
        /* make sure of the password by asking for verification */
        retval =  rad_converse(pamh, PAM_PROMPT_ECHO_OFF,
                               "New password (again): ", &check_password);
        PAM_FAIL_CHECK;
        
        retval = strcmp(new_password, check_password);
        _pam_forget(check_password);
        
        /* if they don't match, don't pass them to the next module */
        if (retval != 0) {
          _pam_forget(new_password);
          rad_converse(pamh, PAM_ERROR_MSG,
                       "You must enter the same password twice.", NULL);
          retval = PAM_AUTHTOK_ERR;
          goto error;           /* ??? maybe this should be a 'continue' ??? */
        }

        break;                  /* everything's fine */
      } /* loop, trying to get matching new passwords */

      if (attempts >= 3) { /* too many new password attempts: die */
        retval = PAM_AUTHTOK_ERR;
        goto error;
      }
    } /* now we have a new password which passes all of our tests */

    TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_chauthtok, after new password logic\n");

    /*
     * Solaris 2.6 calls pam_sm_chauthtok only ONCE, with PAM_PRELIM_CHECK
     * set.
     */
#ifndef sun
    /* If told to update the authentication token, do so. */
  } else if (flags & PAM_UPDATE_AUTHTOK) {
#endif

    if (!password || !new_password) { /* ensure we've got passwords */
      retval = PAM_AUTHTOK_ERR;
      goto error;
    }
    
    /* build and initialize the password change request RADIUS packet */
    request->code = PW_PASSWORD_REQUEST;
    get_random_vector(request->vector);
    request->id = request->vector[0]; /* this should be evenly distributed */

    /* the secret here can not be know to the user, so it's the new password */
    _pam_forget(config.server->secret);
    config.server->secret = strdup(password); /* it's free'd later */

    build_radius_packet(request, user, new_password, &config);
    add_password(request, PW_OLD_PASSWORD, password, password);
    
    retval = talk_radius(&config, request, response, new_password, password, 1);
    PAM_FAIL_CHECK;

    /* Whew! Done password changing, check for password acknowledge */
    if (response->code != PW_PASSWORD_ACK) {
      retval = PAM_AUTHTOK_ERR;
      goto error;
    }
  }
  
  /*
   * Send the passwords to the next stage if preliminary checks fail,
   * or if the password change request fails.
   */
  if ((flags & PAM_PRELIM_CHECK) || (retval != PAM_SUCCESS)) {
  error:
    
    /* If there was a password pass it to the next layer */
    if (password && *password) {
      pam_set_item(pamh, PAM_OLDAUTHTOK, password);
    }
    
    if (new_password && *new_password) {
      pam_set_item(pamh, PAM_AUTHTOK, new_password);
    }
  }
  
  if (ctrl & PAM_DEBUG_ARG) {
    _pam_log(LOG_DEBUG, "password change %s"
             , retval==PAM_SUCCESS ? "succeeded":"failed" );
  }
  
  TRACEPRINT(LOG_DEBUG, "Trace: in pam_sm_chauthtok, close config.sockfd and cleanup server list\n");

  close(config.sockfd);
  cleanup(config.server);

  _pam_forget(password);
  _pam_forget(new_password);
  return retval;
}

/*
 *  Do nothing for account management.  This is apparently needed by
 *  some programs.
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  int retval;
  retval = PAM_SUCCESS;
  return retval;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_radius_modstruct = {
  "pam_radius_auth",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};
#endif

