#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
//#include <pcreposix.h>
#include <regex.h>



#ifdef sun
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_radius_auth.h"
#include <stdio.h>
#include <mysql.h>


//if ( SET_STATIC_PARAM )
//  {
    char var_RADIUS_SERVER[64] = STATIC_PARAM_RADIUS_SERVER;
    //strcpy(var_RADIUS_SERVER, STATIC_PARAM_RADIUS_SERVER);
    char var_RADIUS_SECRET[128] = STATIC_PARAM_RADIUS_SECRET;
    //strcpy(var_RADIUS_SECRET, STATIC_PARAM_RADIUS_SECRET);
    int var_RADIUS_TIMEOUT = STATIC_PARAM_RADIUS_TIMEOUT;
    char var_MYSQL_SERVER[64] = STATIC_PARAM_MYSQL_SERVER;
    //strcpy(var_MYSQL_SERVER, STATIC_PARAM_MYSQL_SERVER);
    char var_MYSQL_PORT[8] = STATIC_PARAM_MYSQL_PORT;
    //strcpy(var_MYSQL_PORT, STATIC_PARAM_MYSQL_PORT);
    char var_MYSQL_USER[64] = STATIC_PARAM_MYSQL_USER;
    //strcpy(var_MYSQL_USER, STATIC_PARAM_MYSQL_USER);
    char var_MYSQL_PASS[64] = STATIC_PARAM_MYSQL_PASS;
    //strcpy(var_MYSQL_PASS, STATIC_PARAM_MYSQL_PASS);
    char var_MYSQL_DB[64] = STATIC_PARAM_MYSQL_DB;
    //strcpy(var_MYSQL_DB, STATIC_PARAM_MYSQL_DB);
    char var_USERS_PATTERN[256] = STATIC_PARAM_USERS_PATTERN;
    //strcpy(var_USERS_PATTERN, STATIC_PARAM_USERS_PATTERN);
    char var_MYSQL_TABLE[64] = STATIC_PARAM_MYSQL_TABLE;
    char var_MYSQL_FIELD[64] = STATIC_PARAM_MYSQL_FIELD;
    int var_DEBUG_MODE = 0;
//  }


//#define NULL 0
#define DPRINT if (ctrl & PAM_DEBUG_ARG) _pam_log



/* @var string pam_module_name - module name */
static CONST char *pam_module_name = "pam_radius_auth";
/* @var string conf_file - file name and path to configure */
static char conf_file[BUFFER_SIZE]; /* configuration file */

/* we need to save these from open_session to close_session, since
 * when close_session will be called we won't be root anymore and
 * won't be able to access again the radius server configuration file
 * -- cristiang */
static radius_server_t *live_server = NULL;
static time_t session_time;

/**
  * save log to syslog system
  * @param int pam_module_line - line where event was raised
  * @param int err - type event (LOG_WARNING, LOG_ERR, LOG_DEBUG)
  * @param string format - 
  */
static void _pam_log(int pam_module_line, int err, CONST char *format, ...)
{
    va_list args;
    char buffer[BUFFER_SIZE];

    va_start(args, format);
    vsprintf(buffer, format, args);
    /* don't do openlog or closelog, but put our name in to be friendly */
    if ( var_DEBUG_MODE ) { syslog(err, "%s[%d]: %s", pam_module_name, pam_module_line, buffer); }
    va_end(args);
}

/* argument parsing */
static int _pam_parse(int argc, CONST char **argv, radius_conf_t *conf)
{
  _pam_log(__LINE__, LOG_DEBUG, "run function %s([%d], argv, conf)", __FUNCTION__, argc);
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
        _pam_log(__LINE__, LOG_WARNING, "ignoring duplicate '%s'", *argv);
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
      var_DEBUG_MODE = PAM_DEBUG_ARG;

    } else {
      _pam_log(__LINE__, LOG_WARNING, "unrecognized option '%s'", *argv);
    }
  }
  
  return ctrl;
}

/* Callback function used to free the saved return value for pam_setcred. */
void _int_free( pam_handle_t * pamh, void *x, int error_status )
{
    free(x);
}

/*************************************************************************
 * SMALL HELPER FUNCTIONS
 *************************************************************************/

/*
 * Return an IP address in host long notation from
 * one supplied in standard dot notation.
 */
static UINT4 ipstr2long(char *ip_str) {
  char	buf[6];
  char	*ptr;
  int	i;
  int	count;
  UINT4	ipaddr;
  int	cur_byte;
  
  ipaddr = (UINT4)0;

  for(i = 0;i < 4;i++) {
    ptr = buf;
    count = 0;
    *ptr = '\0';

    while(*ip_str != '.' && *ip_str != '\0' && count < 4) {
      if(!isdigit(*ip_str)) {
	return((UINT4)0);
      }
      *ptr++ = *ip_str++;
      count++;
    }

    if(count >= 4 || count == 0) {
      return((UINT4)0);
    }

    *ptr = '\0';
    cur_byte = atoi(buf);
    if(cur_byte < 0 || cur_byte > 255) {
      return ((UINT4)0);
    }

    ip_str++;
    ipaddr = ipaddr << 8 | (UINT4)cur_byte;
  }
  return(ipaddr);
}

/*
 * Check for valid IP address in standard dot notation.
 */
static int good_ipaddr(char *addr) {
  int	dot_count;
  int	digit_count;
  
  dot_count = 0;
  digit_count = 0;
  while(*addr != '\0' && *addr != ' ') {
    if(*addr == '.') {
      dot_count++;
      digit_count = 0;
    } else if(!isdigit(*addr)) {
      dot_count = 5;
    } else {
      digit_count++;
      if(digit_count > 3) {
	dot_count = 5;
      }
    }
    addr++;
  }
  if(dot_count != 3) {
    return(-1);
  } else {
    return(0);
  }
}

/*
 * Return an IP address in host long notation from a host
 * name or address in dot notation.
 */
static UINT4 get_ipaddr(char *host) {
  struct hostent *hp;
  
  if(good_ipaddr(host) == 0) {
    return(ipstr2long(host));

  } else if((hp = gethostbyname(host)) == (struct hostent *)NULL) {
    return((UINT4)0);
  }

  return(ntohl(*(UINT4 *)hp->h_addr));
}

/*
 * take server->hostname, and convert it to server->ip and server->port
 */
static int
host2server(radius_server_t *server)
{
  char *p;
  int ctrl = 1; /* for DPRINT */
  
  if ((p = strchr(server->hostname, ':')) != NULL) {
    *(p++) = '\0';		/* split the port off from the host name */
  }
  
  if ((server->ip.s_addr = get_ipaddr(server->hostname)) == ((UINT4)0)) {
    DPRINT(__LINE__, LOG_DEBUG, "get_ipaddr(%s) returned 0.\n", server->hostname);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /*
   *  If the server port hasn't already been defined, go get it.
   */
  if (!server->port) {
    if (p && isdigit(*p)) {	/* the port looks like it's a number */
      unsigned int i = atoi(p) & 0xffff;
      
      if (!server->accounting) {
	server->port = htons((u_short) i);
      } else {
	server->port = htons((u_short) (i + 1));
      }
    } else {			/* the port looks like it's a name */
      struct servent *svp;
      
      if (p) {			/* maybe it's not "radius" */
	svp = getservbyname (p, "udp");
	/* quotes allow distinction from above, lest p be radius or radacct */
	DPRINT(__LINE__, LOG_DEBUG, "getservbyname('%s', udp) returned %d.\n", p, svp);
	*(--p) = ':';		/* be sure to put the delimiter back */
      } else {
	if (!server->accounting) {
	  svp = getservbyname ("radius", "udp");
	  DPRINT(__LINE__, LOG_DEBUG, "getservbyname(radius, udp) returned %d.\n", svp);
	} else {
	  svp = getservbyname ("radacct", "udp");
	  DPRINT(__LINE__, LOG_DEBUG, "getservbyname(radacct, udp) returned %d.\n", svp);
	}
      }
      
      if (svp == (struct servent *) 0) {
	/* debugging above... */
	return PAM_AUTHINFO_UNAVAIL;
      }
      
      server->port = svp->s_port;
    }
  }

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
	break;			/* oops! Error */
      total += bytes;
    }
    close(fd);
  }

  if (total != AUTH_VECTOR_LEN)
#endif
    {				/* do this *always* on other platforms */
      MD5_CTX my_md5;
      struct timeval tv;
      struct timezone tz;
      static unsigned int session = 0; /* make the number harder to guess */
      
      /* Use the time of day with the best resolution the system can
	 give us -- often close to microsecond accuracy. */
      gettimeofday(&tv,&tz);
      
      if (session == 0) {
	session = getppid();	/* (possibly) hard to guess information */
      }
      
      tv.tv_sec ^= getpid() * session++;
      
      /* Hash things to get maybe cryptographically strong pseudo-random numbers */
      MD5Init(&my_md5);
      MD5Update(&my_md5, (unsigned char *) &tv, sizeof(tv));
      MD5Update(&my_md5, (unsigned char *) &tz, sizeof(tz));
      MD5Final(vector, &my_md5);	      /* set the final vector */
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
  unsigned char	calculated[AUTH_VECTOR_LEN];
  unsigned char	reply[AUTH_VECTOR_LEN];

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
      return NULL;		/* not found */
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
  p->length = length + 2;		/* the total size of the attribute */
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

  if (length > MAXPASS) {	/* shorten the password for now */
    length = MAXPASS;
  }

  if (length == 0) {
    length = AUTH_PASS_LEN;	/* 0 maps to 16 */
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
    vector = attr->data;	/* attr CANNOT be NULL here. */
  }

  /* ************************************************************ */
  /* encrypt the password */
  /* password : e[0] = p[0] ^ MD5(secret + vector) */
  MD5Init(&md5_secret);
  MD5Update(&md5_secret, (unsigned char *) secret, strlen(secret));
  my_md5 = md5_secret;		/* so we won't re-do the hash later */
  MD5Update(&my_md5, vector, AUTH_VECTOR_LEN);
  MD5Final(misc, &my_md5);      /* set the final vector */
  xor(hashed, misc, AUTH_PASS_LEN);
  
  /* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
  for (i = 1; i < (length >> 4); i++) {
    my_md5 = md5_secret;	/* grab old value of the hash */
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

  _pam_log(__LINE__, LOG_ERR, "run function %s(conf, [%d])", __FUNCTION__, accounting);
  struct sockaddr salocal;
  u_short local_port;
  char hostname[BUFFER_SIZE];
  char secret[BUFFER_SIZE];
  char param[BUFFER_SIZE];
  char value[BUFFER_SIZE];

  int bRadiusConf = 0; /* 0, 1 - config for coinnect Radius server; 2 - config for MySQL server */

  char buffer[BUFFER_SIZE];
  char *p;
  FILE *fserver;
  radius_server_t *server = NULL;
  struct sockaddr_in * s_in;
  int timeout;
  int line = 0;


  if ( SET_STATIC_PARAM )
    {
      _pam_log(__LINE__, LOG_DEBUG, " set all option default (precompile)");
	  radius_server_t *tmp;
	  tmp = malloc(sizeof(radius_server_t));
	  conf->server = tmp;
	  server= tmp;      /* first time */
	  server->hostname = strdup(var_RADIUS_SERVER);
      server->secret = strdup(var_RADIUS_SECRET);
      server->accounting = accounting;
      server->port = 0;
      if ( (var_RADIUS_TIMEOUT < 1) || (var_RADIUS_TIMEOUT > 60) )
          { server->timeout = 3; }
        else
          { server->timeout = var_RADIUS_TIMEOUT; }
      server->next = NULL;
    }
    else
    {
      /* the first time around, read the configuration file */
  if ((fserver = fopen (conf_file, "r")) == (FILE*)NULL) {
    _pam_log(__LINE__, LOG_ERR, "Could not open configuration file %s: %s\n",
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
    
    if ( strncmp(p, "[server_radius]", 15) == 0 )
      {
        bRadiusConf = 1;
        continue;
        //strcpy(conf_file,*argv+5); 
      }
    if ( strncmp(p, "[server_mysql]", 14) == 0 )
      {
        bRadiusConf = 2;
        continue;
      }
    /* @TODO проверить работу данной схемы */
    if ( (0 == bRadiusConf) || (1 == bRadiusConf) )
      {
        timeout = 3;
        if ( sscanf(p, "%s %s %d", hostname, secret, &timeout) < 2)
          {
            _pam_log(__LINE__, LOG_ERR, "ERROR reading %s, line %d: Could not read hostname or secret", conf_file, line);
            continue; /* invalid line */
          } 
         else 
           {			/* read it in and save the data */
            _pam_log(__LINE__, LOG_DEBUG, " set option for Radius server : %s ******* %d", hostname, timeout);
            radius_server_t *tmp;
            tmp = malloc(sizeof(radius_server_t));
            if (server) {
              server->next = tmp;
              server = server->next;
            } else {
              conf->server = tmp;
              server= tmp;		/* first time */
            }
            /* sometime later do memory checks here */
            server->hostname = strdup(hostname);
            server->secret = strdup(secret);
            server->accounting = accounting;
            server->port = 0;
            if ((timeout < 1) || (timeout > 60)) 
                { server->timeout = 3; } 
              else
                { server->timeout = timeout; }
            server->next = NULL;
          }
     } // END if ( (0 == bRadiusConf) || (1 == bRadiusConf) ).
     else
       {
         //if ( sscanf(p, "%s=%s", param, value) < 2 )
           if ( sscanf(p, "%[^=]=%[^\"\n]", param, value) < 2 )
             {
               _pam_log(__LINE__, LOG_ERR, "reading %s, line %d: Could not read [%s] param for MySQL server : [%s]=[%s]", conf_file, line, p, param, value);
               continue;
             }
           else
		     {
			   _pam_log(__LINE__, LOG_DEBUG, "reading %s[%d]: [%s] : [%s]=[%s]", conf_file, line, p, param, value);
			   if ( !strcmp(param, "MYSQL_SERVER") )
			     {
				strcpy(var_MYSQL_SERVER, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_SERVER=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_PORT") )
			     {
				strcpy(var_MYSQL_PORT, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_PORT=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_USER") )
			     {
				strcpy(var_MYSQL_USER, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_USER=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_PASS") )
			     {
				strcpy(var_MYSQL_PASS, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_PASS=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_DB") )
			     {
				strcpy(var_MYSQL_DB, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_DB=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_TABLE") )
			     {
				strcpy(var_MYSQL_TABLE, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_TABLE=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "MYSQL_FIELD") )
			     {
				strcpy(var_MYSQL_FIELD, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file MYSQL_FIELD=[%s]", value);
				continue;
			     }
			   if ( !strcmp(param, "USERS_PATTERN") )
			     {
				strcpy(var_USERS_PATTERN, value);
				_pam_log(__LINE__, LOG_DEBUG, " set option from file USERS_PATTERN=[%s]", value);
				continue;
			     }
			 }
       }
  }
  fclose(fserver);
  } // END if ( SET_STATIC_PARAM )
  
  if (!server) {		/* no server found, die a horrible death */
    _pam_log(__LINE__, LOG_ERR, "No RADIUS server found in configuration file %s\n",
	     conf_file);
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* open a socket.  Dies if it fails */
  conf->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (conf->sockfd < 0) {
    _pam_log(__LINE__, LOG_ERR, "Failed to open RADIUS socket: %s\n", strerror(errno));
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* set up the local end of the socket communications */
  s_in = (struct sockaddr_in *) &salocal;
  memset ((char *) s_in, '\0', sizeof(struct sockaddr));
  s_in->sin_family = AF_INET;
  s_in->sin_addr.s_addr = INADDR_ANY;

  /*
   *  Use our process ID as a local port for RADIUS.
   */
  local_port = (getpid() & 0x7fff) + 1024;
  do {
    local_port++;
    s_in->sin_port = htons(local_port);
  } while ((bind(conf->sockfd, &salocal, sizeof (struct sockaddr_in)) < 0) && 
	   (local_port < 64000));
  
  if (local_port >= 64000) {
    close(conf->sockfd);
    _pam_log(__LINE__, LOG_ERR, "No open port we could bind to.");
    return PAM_AUTHINFO_UNAVAIL;
  }

  return PAM_SUCCESS;
}

/*
 * Helper function for building a radius packet.
 * It initializes *some* of the header, and adds common attributes.
 */
static void
build_radius_packet(AUTH_HDR *request, CONST char *user, CONST char *password, radius_conf_t *conf)
{
  char hostname[256];
  UINT4 ipaddr;
  
  hostname[0] = '\0';
  gethostname(hostname, sizeof(hostname) - 1);

  request->length = htons(AUTH_HDR_LEN);

  if (password) {		/* make a random authentication req vector */
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

  /* the packet is from localhost if on localhost, to make configs easier */
  if ((conf->server->ip.s_addr == ntohl(0x7f000001)) || (!hostname[0])) {
    ipaddr = 0x7f000001;
  } else {
    struct hostent *hp;
    
    if ((hp = gethostbyname(hostname)) == (struct hostent *) NULL) {
      ipaddr = 0x00000000;	/* no client IP address */
    } else {
      ipaddr = ntohl(*(UINT4 *) hp->h_addr); /* use the first one available */
    }
  }

  /* If we can't find an IP address, then don't add one */
  if (ipaddr) {
    add_int_attribute(request, PW_NAS_IP_ADDRESS, ipaddr);
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
  _pam_log(__LINE__, LOG_DEBUG, "Start function %s(conf, request, response, [%s], [%s], %d)", __FUNCTION__, "", "", tries);

  int salen, total_length;
  fd_set set;
  struct timeval tv;
  time_t now, end;
  int rcode;
  struct sockaddr saremote;
  struct sockaddr_in *s_in = (struct sockaddr_in *) &saremote;
  radius_server_t *server = conf->server;
  int ok;
  int server_tries;
  int retval;

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
      _pam_log(__LINE__, LOG_ERR,
	       "Failed looking up IP address for RADIUS server %s (errcode=%d)",
	       server->hostname, retval);
      ok = FALSE;
      goto next;		/* skip to the next server */
    }

    /* set up per-server IP && port configuration */
    memset ((char *) s_in, '\0', sizeof(struct sockaddr));
    s_in->sin_family = AF_INET;
    s_in->sin_addr.s_addr = htonl(server->ip.s_addr);
    s_in->sin_port = server->port;
    total_length = ntohs(request->length);
    
    if (!password) { 		/* make an RFC 2139 p6 request authenticator */
      get_accounting_vector(request, server);
    }

    server_tries = tries;
send:
    /* send the packet */
    if (sendto(conf->sockfd, (char *) request, total_length, 0,
	       &saremote, sizeof(struct sockaddr_in)) < 0) {
      _pam_log(__LINE__, LOG_ERR, "Error sending RADIUS packet to server %s: %s",
	       server->hostname, strerror(errno));
      ok = FALSE;
      goto next;		/* skip to the next server */
    }

    /* ************************************************************ */
    /* Wait for the response, and verify it. */
    salen = sizeof(struct sockaddr);
    tv.tv_sec = server->timeout; /* wait for the specified time */
    tv.tv_usec = 0;
    FD_ZERO(&set);		/* clear out the set */
    FD_SET(conf->sockfd, &set);	/* wait only for the RADIUS UDP socket */
    
    time(&now);
    end = now + tv.tv_sec;
    
    /* loop, waiting for the select to return data */
    ok = TRUE;
    while (ok) {

      rcode = select(conf->sockfd + 1, &set, NULL, NULL, &tv);

      /* select timed out */
      if (rcode == 0) {
	_pam_log(__LINE__, LOG_ERR, "RADIUS server %s failed to respond",
		 server->hostname);
	if (--server_tries)
	  goto send;
	ok = FALSE;
	break;			/* exit from the select loop */
      } else if (rcode < 0) {

	/* select had an error */
	if (errno == EINTR) {	/* we were interrupted */
	  time(&now);
	  
	  if (now > end) {
	    _pam_log(__LINE__, LOG_ERR, "RADIUS server %s failed to respond",
		     server->hostname);
	    if (--server_tries)
	      goto send;
	    ok = FALSE;
	    break;			/* exit from the select loop */
	  }
	  
	  tv.tv_sec = end - now;
	  if (tv.tv_sec == 0) {	/* keep waiting */
	    tv.tv_sec = 1;
	  }

	} else {		/* not an interrupt, it was a real error */
	  _pam_log(__LINE__, LOG_ERR, "Error waiting for response from RADIUS server %s: %s",
		   server->hostname, strerror(errno));
	  ok = FALSE;
	  break;
	}

	/* the select returned OK */
      } else if (FD_ISSET(conf->sockfd, &set)) {

	/* try to receive some data */
	if ((total_length = recvfrom(conf->sockfd, (char *) response,
				     BUFFER_SIZE,
				     0, &saremote, &salen)) < 0) {
	  _pam_log(__LINE__, LOG_ERR, "error reading RADIUS packet from server %s: %s",
		   server->hostname, strerror(errno));
	  ok = FALSE;
	  break;

	  /* there's data, see if it's valid */
	} else {
	  char *p = server->secret;
	  
	  if ((ntohs(response->length) != total_length) ||
	      (ntohs(response->length) > BUFFER_SIZE)) {
	    _pam_log(__LINE__, LOG_ERR, "RADIUS packet from server %s is corrupted",
		     server->hostname);
	    ok = FALSE;
	    break;
	  }

	  /* Check if we have the data OK.  We should also check request->id */

	  if (password) {
	    if (old_password) {
#ifdef LIVINGSTON_PASSWORD_VERIFY_BUG_FIXED
	      p = old_password;	/* what it should be */
#else
	      p = "";		/* what it really is */
#endif
	    }
	    /* 
	     * RFC 2139 p.6 says not do do this, but the Livingston 1.16
	     * server disagrees.  If the user says he wants the bug, give in.
	     */
	  } else {		/* authentication request */
	    if (conf->accounting_bug) {
	      p = "";
	    }
	  }
	    
	  if (!verify_packet(p, response, request)) {
	    _pam_log(__LINE__, LOG_ERR, "packet from RADIUS server %s fails verification: The shared secret is probably incorrect.",
		     server->hostname);
	    ok = FALSE;
	    break;
	  }

	  /*
	   * Check that the response ID matches the request ID.
	   */
	  if (response->id != request->id) {
	    _pam_log(__LINE__, LOG_WARNING, "Response packet ID %d does not match the request packet ID %d: verification of packet fails", response->id, request->id);
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
      radius_server_t *old;	/* forget about this server */
      
      old = server;
      server = server->next;
      conf->server = server;

      _pam_forget(old->secret);
      free(old->hostname);
      free(old);

      if (server) {		/* if there's more servers to check */
	/* get a new authentication vector, and update the passwords */
	get_random_vector(request->vector);
	request->id = request->vector[0];
	
	/* update passwords, as appropriate */
	if (password) {
	  get_random_vector(request->vector);
	  if (old_password) {	/* password change request */
	    add_password(request, PW_PASSWORD, password, old_password);
	    add_password(request, PW_OLD_PASSWORD, old_password, old_password);
	  } else {		/* authentication request */
	    add_password(request, PW_PASSWORD, password, server->secret);
	  }
	}
      }
      continue;

    } else {
      /* we've found one that does respond, forget about the other servers */
      cleanup(server->next);
      server->next = NULL;
      live_server = server;	/* we've got a live one! */
      break;
    }
  }

  if (!server) {
    _pam_log(__LINE__, LOG_ERR, "All RADIUS servers failed to respond.");
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
  
  resp_msg.msg_style = msg_style;
  resp_msg.msg = message;
  msg[0] = &resp_msg;
  
  /* grab the password */
  retval = pam_get_item(pamh, PAM_CONV, (CONST void **) &conv);
  PAM_FAIL_CHECK;
  
  retval = conv->conv(1, msg, &resp,conv->appdata_ptr);
  PAM_FAIL_CHECK;
  
  if (password) {		/* assume msg.type needs a response */
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
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {	\
	int *pret = malloc( sizeof(int) );		\
	*pret = retval;					\
	pam_set_data( pamh, "rad_setcred_return"	\
	              , (void *) pret, _int_free );	\
	return retval; }

/**
  * function check user into passwd
  * default return: 1
  * @param user - user name for checking
  * @return int  1 - if user found or found more than one match or error, 0 - if user not found
  */
static int pmw_match_grep(char *user, char *pattern)
  {
        _pam_log(__LINE__, LOG_DEBUG, "run function %s([%s], [%s])", __FUNCTION__, user, pattern);
        char cmd[65536];
        char buf[1024];
        int rtrn = 1;
        int ret = NULL;
        int check_regex__ = 0;

        sprintf(cmd, "echo \"%s\" | grep -c -E \"^(%s)$\"", user, pattern);
        _pam_log(__LINE__, LOG_DEBUG, "RUN script : %s", cmd);

        FILE *ptr;
        if ((ptr = popen(cmd, "r")) != NULL)
          {
            ret = fgets(buf, sizeof(buf), ptr);
            if ( ret != NULL )
              {
                _pam_log(__LINE__, LOG_DEBUG, "count success regex [%s] for string [%s] : [%s]", pattern, user, buf);
                rtrn = atoi(buf);
              }
            pclose(ptr);
          }
          else
            {
              _pam_log(__LINE__, LOG_ERR, "NOT run script [%s]", cmd);
            }

//        _pam_log(__LINE__, LOG_DEBUG, "COUNT passwd : %s", rtrn);
        return rtrn;
}

int pmw_match(const char *string, char *pattern)
  {
    _pam_log(__LINE__, LOG_DEBUG, "run function %s([%s], [%s])", __FUNCTION__, string, pattern);
    int status;
    regex_t re;
    if ( regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0 )
      {
        return(0);
      }
    status = regexec(&re, string, 0, NULL, 0);
    regfree(&re);
    if ( 0 != status )
      {
        return(0);
      }
    return(1);
  }

/**
  * function check user into MySQL server
  * default return: 0
  * @param user - user name for checking
  * @return int  0 - if user not found or error, 1 or more - if user found
  */
static int pmw_check_to_mysql_user(char *user)
  {
     _pam_log(__LINE__, LOG_DEBUG, "run function %s(%s)", __FUNCTION__, user);

     MYSQL *conn;
     MYSQL_RES *res;
     MYSQL_ROW *row;
     char sSQL[65536];
     int retval = 0;
     //sprintf(sSQL, "SELECT COUNT(*) FROM usergroup WHERE UserName='%s';", user);
     sprintf(sSQL, "SELECT COUNT(*) FROM %s WHERE %s='%s';", var_MYSQL_TABLE, var_MYSQL_FIELD, user);
     conn = mysql_init(NULL);
     if ( !mysql_real_connect(conn, var_MYSQL_SERVER, var_MYSQL_USER, var_MYSQL_PASS, var_MYSQL_DB, 0, NULL, 0)) 
       {
         _pam_log(__LINE__, LOG_ERR, "not connect to MySQL server [%s:%s] database [%s] : %s", var_MYSQL_SERVER, var_MYSQL_PORT, var_MYSQL_DB, mysql_error(conn));
         return 0;
       }
     if ( mysql_query(conn, sSQL) )
       {
         _pam_log(__LINE__, LOG_ERR, "errro MySQL query : %s", mysql_error(conn));
         mysql_close(conn);
         return 0;
       }
     res = mysql_use_result(conn);
     while ( (row = mysql_fetch_row(res)) != NULL )
       {
         retval = atoi(row[0]);
       }
     mysql_free_result(res);
     mysql_close(conn);
     return retval;
  }


/**
  * function check regex
  * @param char *s - string
  * @param char *pattern - regex-string (PCRE) for search
  * @return int  1 - if matches string f , 0 - if not matches
  */
static int pmw_regex_match(char *s, char *pattern)
  {
    _pam_log(__LINE__, LOG_DEBUG, "run function %s([%s], [%s])", __FUNCTION__, s, pattern);
    regex_t c_pattern; /* save compile template  */
    int count = 1;
    int err = 0;
    int status;
    char errbuf[512];
    //regmatch_t p[20];
    //_pam_log(__LINE__, LOG_DEBUG, "regex [%s] for string [%s]", pattern, s);
    if ( (status = regcomp(&c_pattern, pattern, REG_EXTENDED)) != 0 )
      {
        _pam_log(__LINE__, LOG_ERR, "regex compile [%s]", pattern);
        count = 0;
      }
    if ( 0 != count )
      {
        //_pam_log(__LINE__, LOG_DEBUG, "check regex [%s] for string [%s]", pattern, s);
        if ( (status = regexec(&c_pattern, s, NULL, NULL, NULL)) != 0  )
          {
              regerror(status, &c_pattern, errbuf, sizeof(errbuf));
              _pam_log(__LINE__, LOG_DEBUG, "regex [%s] for string [%s] not found (return=[%d]). error: [%s]", pattern, s, status, errbuf);
              count = 0;
          }
          else
            {
              //_pam_log(__LINE__, LOG_DEBUG, "regex [%s] for string [%s] success", pattern, s);
              count = 1;
            }
        //regfree(&c_pattern);
      }
    _pam_log(__LINE__, LOG_DEBUG, "exit status function regex = [%d]", count);
    return count;
  }

/**
  * function check user into passwd
  * default return: 1
  * @param user - user name for checking
  * @return int  1 - if user found or found more than one match or error, 0 - if user not found
  */
static int check_login_to_passwd(char *user)
  {
        _pam_log(__LINE__, LOG_DEBUG, "run function %s([%s])", __FUNCTION__, user);
        char cmd[65536];
        char buf[1024];
        int rtrn = 1;
        int ret = NULL;
        int check_regex__ = 1;
        int check_count_user__ = 0;
        char *pattern = "";
        char *rtrn_func = "";
        //strcpy(pattern, var_USERS_PATTERN);

        //check_regex__ = pmw_match_grep(user, var_USERS_PATTERN);
        if ( strcmp(var_USERS_PATTERN, "") != 0 )
          {
            check_regex__ = pmw_regex_match(user, var_USERS_PATTERN);
            if ( check_regex__ == 0 ) { rtrn_func = "false"; } else { rtrn_func = "true"; };
            _pam_log(__LINE__, LOG_DEBUG, "return regex : [%s]", rtrn_func);
          }
        if ( 0 == check_regex__ )
          {
            _pam_log(__LINE__, LOG_WARNING, "User [%s] is does not fit into regex [%s]", user, var_USERS_PATTERN);
            return 2;
          }
        check_count_user__ = pmw_check_to_mysql_user(user);
        _pam_log(__LINE__, LOG_DEBUG, "check users into DB radius (MySQL) : [%d]", check_count_user__);
        if ( 0 == check_count_user__ )
          {
            _pam_log(__LINE__, LOG_DEBUG, "COUNT login for %s : [%s]", user, buf);
            return 3;
          }

        sprintf(cmd, "echo $(/bin/cat /etc/passwd | grep -c \"%s:\")", user);
        _pam_log(__LINE__, LOG_DEBUG, "RUN script : %s", cmd);

        FILE *ptr;
        if ((ptr = popen(cmd, "r")) != NULL)
          {
            ret = fgets(buf, sizeof(buf), ptr);
            if ( ret != NULL )
              {
                _pam_log(__LINE__, LOG_DEBUG, "count login for %s : [%s]", user, buf);
                if ( atoi(buf) == 0 ) rtrn = 0;
              }
            pclose(ptr);
          }
          else
            {
              _pam_log(__LINE__, LOG_ERR, "NOT run script [%s]", cmd);
            }

//        _pam_log(__LINE__, LOG_DEBUG, "COUNT passwd : %s", rtrn);
        return rtrn;
}


static int create_usix_user(CONST char *user)
  {
        _pam_log(__LINE__, LOG_DEBUG, "run function %s([%s])", __FUNCTION__, user);
        char cmd[65536];
        sprintf(cmd, "/usr/sbin/useradd -e 2020-01-01 -M -N %s", user);
        char buf[4096];
        int ret = NULL;
        FILE *ptr;

        if ((ptr = popen(cmd, "r")) != NULL)
          {
            ret = fgets(buf, sizeof(buf), ptr);
            if ( ret != NULL )
              {
                _pam_log(__LINE__, LOG_DEBUG, "CREATE unix user %s : %s", user, buf);
              }
            pclose(ptr);
          }
          else
            {
              _pam_log(__LINE__, LOG_ERR, "NOT run script [%s]", cmd);
            }
        return 0;
}


PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc,CONST char **argv)
{
  _pam_log(__LINE__, LOG_DEBUG, "run function %s(pamb, [%d], [%d], argv)", __FUNCTION__, flags, argc);
  CONST char *user;
  CONST char **userinfo;
  char *password = NULL;
  CONST char *rhost;
  char *resp2challenge = NULL;
  int ctrl;
  int retval = PAM_AUTH_ERR;

  char recv_buffer[4096];
  char send_buffer[4096];
  int ret = 0;
  AUTH_HDR *request = (AUTH_HDR *) send_buffer;
  AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
  radius_conf_t config;

  ctrl = _pam_parse(argc, argv, &config);

  /*
   * Get the IP address of the authentication server
   * Then, open a socket, and bind it to a port
   */
  _pam_log(__LINE__, LOG_DEBUG, "before function initialize");
  retval = initialize(&config, FALSE);
  _pam_log(__LINE__, LOG_DEBUG, "after function initialize, return=[%d]", retval);
  PAM_FAIL_CHECK;


  /* grab the user name */
  retval = pam_get_user(pamh, &user, "PMW login:");
  PAM_FAIL_CHECK;


  /* check that they've entered something, and not too long, either */
  if ((user == NULL) ||
      (strlen(user) > MAXPWNAM)) {
    int *pret = malloc( sizeof(int) );
    *pret = PAM_USER_UNKNOWN;
    pam_set_data( pamh, "rad_setcred_return", (void *) pret, _int_free );

    DPRINT(__LINE__, LOG_DEBUG, "User name was NULL, or too long");
    return PAM_USER_UNKNOWN;
  }

  // [PMW] check user 
  if ( user != NULL)
    {
      /* check user into passwd */
      ret = check_login_to_passwd(user);
      if ( ret == 0 ) create_usix_user(user);
      if ( ret > 1 )
        {
          return PAM_USER_UNKNOWN;
        }
    }
  DPRINT(__LINE__, LOG_DEBUG, "Got user name %s", user);

  if (ctrl & PAM_RUSER_ARG) {
    retval = pam_get_item(pamh, PAM_RUSER, (CONST void **) &userinfo);
    PAM_FAIL_CHECK;
    DPRINT(__LINE__, LOG_DEBUG, "Got PAM_RUSER name %s", userinfo);

    if (!strcmp("root", user)) {
      user = userinfo;
      DPRINT(__LINE__, LOG_DEBUG, "Username now %s from ruser", user);
    } else {
      DPRINT(__LINE__, LOG_DEBUG, "Skipping ruser for non-root auth");
    };
  };


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
    DPRINT(__LINE__, LOG_DEBUG, "Got password %s", password);
  }

  /* no previous password: maybe get one from the user */
  if (!password) {
    if (ctrl & PAM_USE_FIRST_PASS) {
      retval = PAM_AUTH_ERR;	/* use one pass only, stopping if it fails */
      goto error;
    }
    
    /* check to see if we send a NULL password the first time around */
    if (!(ctrl & PAM_SKIP_PASSWD)) {
      retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
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

  DPRINT(__LINE__, LOG_DEBUG, "Sending RADIUS request code %d", request->code);

  retval = talk_radius(&config, request, response, password,
                       NULL, config.retries + 1);
  PAM_FAIL_CHECK;

  DPRINT(__LINE__, LOG_DEBUG, "Got RADIUS response code %d", response->code);

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
      _pam_log(__LINE__, LOG_ERR, "RADIUS Access-Challenge received with State or Reply-Message missing");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto error;
    }

    /*
     *	Security fixes.
     */
    if ((a_state->length <= 2) || (a_reply->length <= 2)) {
      _pam_log(__LINE__, LOG_ERR, "RADIUS Access-Challenge received with invalid State or Reply-Message");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto error;
    }

    memcpy(challenge, a_reply->data, a_reply->length - 2);
    challenge[a_reply->length - 2] = 0;

    /* It's full challenge-response, we should have echo on */
    retval = rad_converse(pamh, PAM_PROMPT_ECHO_ON, challenge, &resp2challenge);

    /* now that we've got a response, build a new radius packet */
    build_radius_packet(request, user, resp2challenge, &config);
    /* request->code is already PW_AUTHENTICATION_REQUEST */
    request->id++;		/* one up from the request */

    /* copy the state over from the servers response */
    add_attribute(request, PW_STATE, a_state->data, a_state->length - 2);

    retval = talk_radius(&config, request, response, resp2challenge, NULL, 1);
    PAM_FAIL_CHECK;

    DPRINT(__LINE__, LOG_DEBUG, "Got response to challenge code %d", response->code);
  }

  /* Whew! Done the pasword checks, look for an authentication acknowledge */
  if (response->code == PW_AUTHENTICATION_ACK) {
    retval = PAM_SUCCESS;
  } else {
    retval = PAM_AUTH_ERR;	/* authentication failure */

error:
    /* If there was a password pass it to the next layer */
    if (password && *password) {
      pam_set_item(pamh, PAM_AUTHTOK, password);
    }
  }

  if (ctrl & PAM_DEBUG_ARG) {
    _pam_log(__LINE__, LOG_DEBUG, "authentication %s"
	     , retval==PAM_SUCCESS ? "succeeded":"failed" );
  }
  
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

  /* grab the user name */
  retval = pam_get_user(pamh, &user, "pam_private_session LOGIN : ");
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

  close(config.sockfd);
  cleanup(config.server);

  return retval;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, CONST char **argv)
{
  return pam_private_session(pamh, flags, argc, argv, PW_STATUS_START);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, CONST char **argv)
{
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

  /* grab the user name */
  retval = pam_get_user(pamh, &user, "pam_sm_chauthtok LOGIN: ");
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
    if (!password) {		/* no previous password: ask for one */
      retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF, "Password: ", &password);
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
    
    if (!new_password) {	/* not found yet: ask for it */
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
	  
	  break;		/* the new password is OK */
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
	  goto error;		/* ??? maybe this should be a 'continue' ??? */
	}

	break;			/* everything's fine */
      }	/* loop, trying to get matching new passwords */

      if (attempts >= 3) { /* too many new password attempts: die */
	retval = PAM_AUTHTOK_ERR;
	goto error;
      }
    } /* now we have a new password which passes all of our tests */

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
    _pam_log(__LINE__, LOG_DEBUG, "password change %s"
	     , retval==PAM_SUCCESS ? "succeeded":"failed" );
  }
  
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

