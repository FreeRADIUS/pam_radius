/*
 *   Authenticate a user via a RADIUS session
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
 */

/**
 * $Id: ee1d54767afa6c3801bb201f8a907dedb376cb11 $
 *
 * @file pam_radius_auth.c
 * @brief Authenticate a user via a RADIUS session
 *
 * @copyright 1996 Cristian Gafton <gafton@redhat.com>
 * @copyright 1998 CRYPTOCard Inc
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include<stddef.h>
#include "pam_radius_auth.h"

#define DPRINT if (debug) _pam_log

/* internal data */
static CONST char pam_module_name[] = "pam_radius_auth";

/* module version */
static CONST char pam_module_version[] = PAM_RADIUS_VERSION_STRING
#ifndef NDEBUG
	" DEVELOPER BUILD - "
#endif
#ifdef PAM_RADIUS_VERSION_COMMIT
	" (git #" PAM_RADIUS_VERSION_COMMIT ")"
#endif
	", built on " __DATE__ " at " __TIME__ ""
;

/**
 * Convert the packet code to string.
 */
static const char *get_packet_name(int code) {
	switch(code) {
		case PW_ACCESS_REQUEST: return "Access-Request";
		case PW_ACCESS_ACCEPT: return "Access-Accept";
		case PW_ACCESS_REJECT: return "Access-Reject";
		case PW_ACCOUNTING_REQUEST: return "Accounting-Request";
		case PW_ACCOUNTING_RESPONSE: return "Accounting-Response";
		case PW_ACCOUNTING_STATUS: return "Accounting-Status";
		case PW_ACCOUNTING_MESSAGE: return "Accounting-Message";
		case PW_ACCESS_CHALLENGE: return "Access-Challenge";
		default: return "Unknown";
	}
}

/** log helper
 *
 * @param[in] err		Syslog priority id.
 * @param[in] msg		Mensagem to print.
 * @param[in] ...		Arguments for msg string.
 */
static void _pam_log(int err, char CONST *msg, ...)
{
	char buf[BUFFER_SIZE];
	va_list ap;

	va_start(ap, msg);
#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
	(void)vsnprintf(buf, sizeof(buf), msg, ap);
#ifdef __clang__
#	pragma clang diagnostic pop
#endif
	va_end(ap);

	/* don't do openlog or closelog, but put our name in to be friendly */
	syslog(err, "%s: %s", pam_module_name, buf);
}


/** Argument parsing
 *
 * @param[in] argc		Number of parameters
 * @param[in] argv		Array with all parameters
 * @param[out] conf		Where to write the radius_conf_t.
 * @return
 *	- PAM used parameters
 */
static int _pam_parse(int argc, CONST char **argv, radius_conf_t *conf)
{
	int ctrl = 0;
	int i = 0;

	memset(conf, 0, sizeof(radius_conf_t)); /* ensure it's initialized */

	conf->conf_file = CONF_FILE;

	/* set the default prompt */
	snprintf(conf->prompt, MAXPROMPT, "%s: ", DEFAULT_PROMPT);

	conf->use_ipv4 = 1;
	conf->use_ipv6 = 1;
#ifdef HAVE_LIBSSL
	conf->radsec = 2; // default value try
	conf->ssl_verify = 1;
#endif

	/*
	 *	If either is not there, then we can't parse anything.
	 */
	if ((argc == 0) || (argv == NULL)) return ctrl;

	/* step through arguments */
	for (i = 0; i < argc; i++) {
		char *arg;

		memcpy(&arg, &argv[i], sizeof(arg));

#ifndef NDEBUG
		_pam_log(LOG_DEBUG, "_pam_parse: argv[%d] = '%s'", i, arg);
#endif

		/* generic options */
		if (!strncmp(arg, "conf=", 5)) {
			conf->conf_file = (arg + 5);

		} else if (!strcmp(arg, "use_first_pass")) {
			ctrl |= PAM_USE_FIRST_PASS;

		} else if (!strcmp(arg, "try_first_pass")) {
			ctrl |= PAM_TRY_FIRST_PASS;

		} else if (!strcmp(arg, "skip_passwd")) {
			ctrl |= PAM_SKIP_PASSWD;

		} else if (!strncmp(arg, "retry=", 6)) {
			conf->retries = strtoul((arg + 6), 0, 10);

		} else if (!strcmp(arg, "localifdown")) {
			conf->localifdown = 1;

		} else if (!strncmp(arg, "client_id=", 10)) {
			if (conf->client_id) {
				_pam_log(LOG_WARNING, "ignoring duplicate '%s'", arg);
			} else {
				conf->client_id = (arg + 10); /* point to the client-id */
			}

		} else if (!strcmp(arg, "ruser")) {
			ctrl |= PAM_RUSER_ARG;

		} else if (!strcmp(arg, "debug")) {
			ctrl |= PAM_DEBUG_ARG;
			conf->debug = TRUE;

		} else if (!strncmp(arg, "hostname=", 9)) {
			if (conf->hostname[0] != '\0') {
				_pam_log(LOG_WARNING, "ignoring duplicate '%s'", arg);
			} else {
				/* truncate excessive hostnames to MAXHOSTNAMELEN length */
				if (strlen(arg + 9) > MAXHOSTNAMELEN) {
					*(arg + 9 + MAXHOSTNAMELEN) = '\0';
				}
				/* set the new hostname */
				strcpy(conf->hostname, arg + 9);
			}

		} else if (!strncmp(arg, "prompt=", 7)) {
			if (!strncmp(conf->prompt, (arg+7), MAXPROMPT)) {
				_pam_log(LOG_WARNING, "ignoring duplicate '%s'", arg);
			} else {
				/* truncate excessive prompts to (MAXPROMPT - 3) length */
				if (strlen((arg+7)) >= (MAXPROMPT - 3)) {
					*((arg + 7) + (MAXPROMPT - 3)) = '\0';
				}

				/* set the new prompt */
				memset(conf->prompt, 0, sizeof(conf->prompt));
				snprintf(conf->prompt, MAXPROMPT, "%s: ", (arg+7));
			}

		} else if (!strcmp(arg, "force_prompt")) {
			conf->force_prompt = TRUE;

		} else if (!strcmp(arg, "prompt_attribute")) {
			conf->prompt_attribute = TRUE;

		} else if (!strncmp(arg, "max_challenge=", 14)) {
			conf->max_challenge = strtoul((arg+14), 0, 10);

		} else if (!strncmp(arg, "ipv4=", 5)) {
			if (!strcmp(arg + 5, "yes")) conf->use_ipv4 = 1;
			if (!strcmp(arg + 5, "no")) conf->use_ipv4 = 0;

		} else if (!strncmp(arg, "ipv6=", 5)) {
			if (!strcmp(arg + 5, "yes")) conf->use_ipv6 = 1;
			if (!strcmp(arg + 5, "no")) conf->use_ipv6 = 0;

		} else if (!strcmp(arg, "privilege_level")) {
			conf->privilege_level = TRUE;

		} else if (!strcmp(arg, "require_message_authenticator")) {
			conf->require_message_authenticator = TRUE;

		} else if (!strncmp(arg, "radsec=", 7)) {
		#ifdef HAVE_LIBSSL
			if (!strcmp(arg + 7, "try")) conf->radsec = 2;	// If SSL fails, fallback to RADIUS UDP on tls:// 
			if (!strcmp(arg + 7, "yes")) conf->radsec = 1;	// Always use RADSEC, even without tls:// */
			if (!strcmp(arg + 7, "no")) conf->radsec = 0;	// Never use RADSEC, fallback to RADIUS UDP on tls://
		#else
			_pam_log(LOG_WARNING, "unrecognized option '%s': missing RADSEC support", arg);
		#endif

		} else if (!strncmp(arg, "verify=", 7)) {
		#ifdef HAVE_LIBSSL
			if (!strcmp(arg + 7, "yes")) conf->ssl_verify = 1;
			if (!strcmp(arg + 7, "no")) conf->ssl_verify = 0;
		#else
			_pam_log(LOG_WARNING, "unrecognized option '%s': missing RADSEC support", arg);
		#endif

		} else if (!strncmp(arg, "cert=", 5)) {
		#ifdef HAVE_LIBSSL
			conf->cert=arg + 5;
		#else
			_pam_log(LOG_WARNING, "unrecognized option '%s': missing RADSEC support", arg);
		#endif

		} else if (!strncmp(arg, "key=", 4)) {
		#ifdef HAVE_LIBSSL
			conf->key= arg + 4;
		#else
			_pam_log(LOG_WARNING, "unrecognized option '%s': missing RADSEC support", arg);
		#endif

		} else if (!strncmp(arg, "ca=", 3)) {
		#ifdef HAVE_LIBSSL
			conf->ca= arg + 3;
		#else
			_pam_log(LOG_WARNING, "unrecognized option '%s': missing RADSEC support", arg);
		#endif

		} else {
			_pam_log(LOG_WARNING, "unrecognized option '%s'", arg);
		}
	}

	if (!conf->use_ipv4 && !conf->use_ipv6) {
		_pam_log(LOG_WARNING, "Cannot disable both IPv4 and IPv6'");

		conf->use_ipv4 = 1;
	}

#ifdef HAVE_LIBSSL
	if(conf->radsec) {
		if((conf->cert && !conf->key) || (!conf->cert && conf->key)) {
			_pam_log(LOG_WARNING, "RADSEC disabled: both cert and key must be defined");
		}
	} else {
		_pam_log(LOG_WARNING, "RADSEC disabled by configuration: radsec=no");
	}
#endif

	if (conf->debug) {
#define print_bool(cond) (cond) ? "yes" : "no"
#define print_string(cond) (cond) ? cond : ""

		_pam_log(LOG_DEBUG, "DEBUG: conf='%s' use_first_pass=%s try_first_pass=%s skip_passwd=%s retry=%d " \
							"localifdown=%s client_id='%s' ruser=%s prompt='%s' force_prompt=%s "\
							"prompt_attribute=%s max_challenge=%d privilege_level=%s "\
							"require_message_authenticator=%s "
#ifdef HAVE_LIBSSL
							"radsec=%s verify=%s cert=%s key=%s ca=%s"
#endif
				,
				conf->conf_file,
				print_bool(ctrl & PAM_USE_FIRST_PASS),
				print_bool(ctrl & PAM_TRY_FIRST_PASS),
				print_bool(ctrl & PAM_SKIP_PASSWD),
				conf->retries,
				print_bool(conf->localifdown),
				print_string(conf->client_id),
				print_bool(ctrl & PAM_RUSER_ARG),
				conf->prompt,
				print_bool(conf->force_prompt),
				print_bool(conf->prompt_attribute),
				conf->max_challenge,
				print_bool(conf->privilege_level),
				print_bool(conf->require_message_authenticator)
			#ifdef HAVE_LIBSSL
				,conf->radsec == 2 ? "try" : ( conf->radsec ? "yes" : "no"),
				print_bool(conf->ssl_verify),
				print_string(conf->cert),
				print_string(conf->key),
				print_string(conf->ca)
			#endif
		);
	}

	return ctrl;
}

/** Callback function used to free the saved return value for pam_setcred.
 *
 * @param[in] pamh			PAM context specified by the pamh argument
 * @param[in] data			Associate some data with the handle pamh
 * @param[in] error_status	used to indicate to the module the sort of action it
 */
static void _int_free(UNUSED pam_handle_t *pamh, void *data, UNUSED int error_status)
{
	free(data);
}

/** A strerror_r() wrapper function to deal with its nuisances.
 *
 * @param[in] errnum		syslog priority id
 * @param[in] buf	        Variadic arguments
 * @param[in] buflen	    Variadic arguments
 */
static void get_error_string(int errnum, char *buf, size_t buflen)
{
#if !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE)
	/* XSI version of strerror_r(). */
	int retval = strerror_r(errnum, buf, buflen);

	/* POSIX does not state what will happen to the buffer if the function fails.
	 * Put it into a known state rather than leave it possibly uninitialized. */
	if (retval != 0 && buflen > (size_t)0) {
		buf[0] = '\0';
	}
#else
	/* GNU version of strerror_r(). */
	char tmp_buf[BUFFER_SIZE];
	char *retval = strerror_r(errnum, tmp_buf, sizeof(tmp_buf));

	snprintf(buf, buflen, "%s", retval);
#endif
}

/** Return an IP address as a struct sockaddr
 *
 * @param[in] host		Hostname
 * @param[out] addr	    sockaddr buffer
 * @param[in] port	    used port
 * @return
 *	- returns zero on success or one of the error codes listed in gai_strerror(3)
 *    if an error occurs
 */
static int get_ipaddr(CONST char *host, struct sockaddr *addr, CONST char *port)
{
	struct addrinfo hints;
	struct addrinfo *results;
	int retval;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	retval = getaddrinfo(host, port && port[0] ? port : NULL, &hints, &results);
	if (retval == 0) {
		memcpy(addr, results->ai_addr, results->ai_addrlen);
		freeaddrinfo(results);
	}

	return retval;
}

/** take server->hostname, and convert it to server->ip
 *
 * @param[in]  debug		Debug status
 * @param[out] server	    radius_server_t buffer
 * @return
 *	- returns zero on success or one of the error codes listed in gai_strerror(3)
 *    if an error occurs
 */
static int host2server(int debug, radius_server_t *server)
{
	char hostbuffer[256];
	char tmp[256];
	char *hostname;
	char *portstart;
	char *p, *port;
	int retval, n;

	/* hostname might be [ipv6::address] or tcp:// or tls:// */
	strncpy(hostbuffer, server->hostname, sizeof(hostbuffer) - 1);

	hostbuffer[sizeof(hostbuffer) - 1] = 0;
	hostname = hostbuffer;
	portstart = hostbuffer;

	if (!strncmp("tcp://",hostname,6) || !strncmp("tls://",hostname,6)) {
		hostname += 6;
		portstart += 6;
	}

	if (hostname[0] == '[') {
		if ((p = strchr(hostname, ']')) != NULL) {
			hostname++;
			*p++ = 0;
			portstart = p;
		}
	}

	if ((port = strchr(portstart, ':')) != NULL) {
		*port++ = '\0';
		if (isdigit((uint8_t)*port) && server->accounting && server->proto != rad_proto_sec) {
			if (sscanf(port, "%d", &n) == 1) {
				snprintf(tmp, sizeof(tmp), "%d", n + 1);
				port = tmp;
			}
		}
	} else {
		strncpy(tmp, (server->proto == rad_proto_sec) ? "radsec" : ((server->accounting) ? "radacct" : "radius"), sizeof(tmp));
		port = tmp;
	}

	server->ip = (struct sockaddr *)&server->ip_storage;
	retval = get_ipaddr(hostname, server->ip, port);

	DPRINT(LOG_DEBUG, "DEBUG: get_ipaddr(%s) returned %d.\n", hostname, retval);

	return retval;
}

/** Do XOR of two buffers.
 */
static uint8_t * xor(uint8_t *p, uint8_t *q, int length)
{
	uint8_t *retval= p;
	int i;

	for (i = 0; i < length; i++) *(p++) ^= *(q++);

	return retval;
}

/**************************************************************************
 * MID-LEVEL RADIUS CODE
 **************************************************************************/

/* get a pseudo-random vector.
 */
static void get_random_vector(uint8_t *vector)
{
#ifdef linux
	int total = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY); /* Linux: get *real* random numbers */
	if (fd >= 0) {
		while (total < AUTH_VECTOR_LEN) {
			int bytes = read(fd, vector + total, AUTH_VECTOR_LEN - total);
			if (bytes <= 0)	break;			/* oops! Error */
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

		/**
		 * Use the time of day with the best resolution the system can
		 * give us -- often close to microsecond accuracy.
		 */
		gettimeofday(&tv,&tz);

		if (session == 0) session = getppid();	/* (possibly) hard to guess information */

		tv.tv_sec ^= getpid() * session++;

		/* Hash things to get maybe cryptographically strong pseudo-random numbers */
		MD5Init(&my_md5);
		MD5Update(&my_md5, (uint8_t *) &tv, sizeof(tv));
		MD5Update(&my_md5, (uint8_t *) &tz, sizeof(tz));
		MD5Final(vector, &my_md5);				/* set the final vector */
	}
}

/**
 *	Follow RFC 2866 for Accounting-Request vector.
 */
static void get_accounting_vector(AUTH_HDR *request, radius_server_t *server)
{
	MD5_CTX my_md5;
	uint16_t len = ntohs(request->length);
	int secretlen = strlen(server->secret);

	memset(request->vector, 0, AUTH_VECTOR_LEN);
	MD5Init(&my_md5);
	memcpy(((char *)request) + len, server->secret, secretlen);

	MD5Update(&my_md5, (uint8_t *)request, len + secretlen);
	MD5Final(request->vector, &my_md5);			/* set the final vector */
}

/**
 * Verify the response from the server
 */
static int verify_packet(radius_server_t *server, AUTH_HDR *response, AUTH_HDR *request, radius_conf_t *conf)
{
	MD5_CTX my_md5;
	uint8_t calculated[AUTH_VECTOR_LEN];
	uint8_t reply[AUTH_VECTOR_LEN];
	uint8_t *message_authenticator = NULL;
	CONST uint8_t *attr, *end;
	size_t secret_len = strlen(server->secret);

	attr = response->data;
	end = (uint8_t *) response + ntohs(response->length);

	/*
	 *	Check that the packet is well-formed, and find the Message-Authenticator.
	 */
	while (attr < end) {
		size_t remaining = end - attr;

		if (remaining < 2) return FALSE;

		if (attr[1] < 2) return FALSE;

		if (attr[1] > remaining) return FALSE;

		if (attr[0] == PW_MESSAGE_AUTHENTICATOR) {
			if (attr[1] != 18) return FALSE;

			if (message_authenticator) return FALSE;

			message_authenticator = (uint8_t *) response + (attr - (uint8_t *) response) + 2;
		}

		attr += attr[1];
	}

	if ((request->code == PW_ACCESS_REQUEST) && conf->require_message_authenticator && !message_authenticator) {
		return FALSE;
	}

	/*
	 * We could dispense with the memcpy, and do MD5's of the packet
	 * + vector piece by piece.	This is easier understand, and maybe faster.
	 */
	memcpy(reply, response->vector, AUTH_VECTOR_LEN); /* save the reply */
	memcpy(response->vector, request->vector, AUTH_VECTOR_LEN); /* sent vector */

	/* MD5(response packet header + vector + response packet data + secret) */
	MD5Init(&my_md5);
	MD5Update(&my_md5, (uint8_t *) response, ntohs(response->length));
	MD5Update(&my_md5, (CONST uint8_t *) server->secret, secret_len);
	MD5Final(calculated, &my_md5);			/* set the final vector */

	/* Did he use the same random vector + shared secret? */
	if (memcmp(calculated, reply, AUTH_VECTOR_LEN) != 0) return FALSE;

	if (!message_authenticator) return TRUE;

	/*
	 *	RFC2869 Section 5.14.
	 *
	 *	Message-Authenticator is calculated with the Request
	 *	Authenticator (copied into the packet above), and with
	 *	the Message-Authenticator attribute contents set to
	 *	zero.
	 */
	memcpy(reply, message_authenticator, AUTH_VECTOR_LEN);
	memset(message_authenticator, 0, AUTH_VECTOR_LEN);

	hmac_md5(calculated, (uint8_t *) response, ntohs(response->length), (const uint8_t *) server->secret, secret_len);

	if (memcmp(calculated, reply, AUTH_VECTOR_LEN) != 0) return FALSE;

	return TRUE;
}

/**
 * Find an attribute in a RADIUS packet.	Note that the packet length
 * is *always* kept in network byte order.
 */
static attribute_t *find_attribute(AUTH_HDR *response, uint8_t type)
{
	attribute_t *attr = (attribute_t *) &response->data;
	uint16_t len;

	len = (ntohs(response->length) - AUTH_HDR_LEN);

	while (attr->attribute != type) {
		if ((len -= attr->length) <= 0) return NULL;		/* not found */

		attr = (attribute_t *) ((char *) attr + attr->length);
	}

	return attr;
}

/**
 * Add an attribute to a RADIUS packet.
 */
static void add_attribute(AUTH_HDR *request, uint8_t type, CONST uint8_t *data, int length)
{
	attribute_t *p;

	p = (attribute_t *) ((uint8_t *)request + ntohs(request->length));
	p->attribute = type;
	p->length = length + 2;		/* the total size of the attribute */

	request->length = htons(ntohs(request->length) + p->length);

	memcpy(p->data, data, length);
}

/**
 * Add an integer attribute to a RADIUS packet.
 */
static void add_int_attribute(AUTH_HDR *request, uint8_t type, int data)
{
	uint32_t value = htonl(data);

	add_attribute(request, type, (uint8_t *) &value, sizeof(value));
}

static void add_nas_ip_address(AUTH_HDR *request, CONST char *hostname) {
	struct addrinfo hints;
	struct addrinfo *ai_start;
	struct addrinfo *ai;
	int v4seen = 0, v6seen = 0;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	r = getaddrinfo(hostname, NULL, &hints, &ai_start);
	if (r != 0)	return;

	ai = ai_start;
	while (ai != NULL) {
		if (!v4seen && ai->ai_family == AF_INET) {
			v4seen = 1;

			r = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

			add_int_attribute(request, PW_NAS_IP_ADDRESS, ntohl(r));
		}

		if (!v6seen && ai->ai_family == AF_INET6) {
			v6seen = 1;

			add_attribute(request, PW_NAS_IPV6_ADDRESS,
				(uint8_t *) &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
		}

		ai = ai->ai_next;
	}

	freeaddrinfo(ai_start);
}

/*
 * Add a RADIUS password attribute to the packet.
 *
 * If the password attribute already exists, it's over-written.	This allows
 * us to simply call add_password to update the password for different
 * servers.
 */
static void add_password(AUTH_HDR *request, uint8_t type, CONST char *password, CONST char *secret)
{
	MD5_CTX md5_secret, my_md5;
	uint8_t misc[AUTH_VECTOR_LEN];
	int i;
	int length = strlen(password);
	uint8_t hashed[256 + AUTH_PASS_LEN];	/* can't be longer than this */
	uint8_t *vector;
	attribute_t *attr;

	if (length > MAXPASS) {				    /* shorten the password for now */
		length = MAXPASS;
	}

	memcpy(hashed, password, length);
	memset(hashed + length, 0, sizeof(hashed) - length);

	if (length == 0) {
		length = AUTH_PASS_LEN;			    /* 0 maps to 16 */
	} if ((length & (AUTH_PASS_LEN - 1)) != 0) {
		length += (AUTH_PASS_LEN - 1);		/* round it up */
		length &= ~(AUTH_PASS_LEN - 1);		/* chop it off */
	}						/* 16*N maps to itself */

	attr = find_attribute(request, PW_USER_PASSWORD);
	vector = request->vector;

	/* ************************************************************ */
	/* encrypt the password */
	/* password : e[0] = p[0] ^ MD5(secret + vector) */
	MD5Init(&md5_secret);
	MD5Update(&md5_secret, (CONST uint8_t *) secret, strlen(secret));
	my_md5 = md5_secret;				/* so we won't re-do the hash later */
	MD5Update(&my_md5, vector, AUTH_VECTOR_LEN);
	MD5Final(misc, &my_md5);			/* set the final vector */
	xor(hashed, misc, AUTH_PASS_LEN);

	/* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
	for (i = 1; i < (length >> 4); i++) {
		my_md5 = md5_secret;			/* grab old value of the hash */
		MD5Update(&my_md5, &hashed[(i-1) * AUTH_PASS_LEN], AUTH_PASS_LEN);
		MD5Final(misc, &my_md5);			/* set the final vector */
		xor(&hashed[i * AUTH_PASS_LEN], misc, AUTH_PASS_LEN);
	}

	if (!attr) {
		add_attribute(request, type, hashed, length);
	} else {
		memcpy(attr->data, hashed, length); /* overwrite the old value of the attribute */
	}
}

static void cleanup(radius_server_t *server)
{
	radius_server_t *next;

	while (server) {
		next = server->next;
		_pam_drop(server->hostname);
		_pam_forget(server->secret);

	#ifdef HAV_LIBSSL
		if (server->ssl) SSL_free(server->ssl);
	#endif
		if (server->sockfd != -1) close(server->sockfd);

		if (server->sockfd6 != -1) close(server->sockfd6);

		_pam_drop(server);
		server = next;
	}
}

static int initialize_sockets(radius_conf_t const *conf, int *sockfd, int *sockfd6, struct sockaddr_storage *salocal4, struct sockaddr_storage *salocal6, char *vrf, int tcp)
{
	if (!conf->use_ipv4) {
		*sockfd = -1;
		goto use_ipv6;
	}

	/* open a socket.	Dies if it fails */
	*sockfd = socket(AF_INET, (tcp? SOCK_STREAM: SOCK_DGRAM), 0);

	if (*sockfd < 0) {
		char error_string[BUFFER_SIZE];
		get_error_string(errno, error_string, sizeof(error_string));
		_pam_log(LOG_ERR, "Failed to open RADIUS socket: %s\n", error_string);
		return -1;
	}

#ifndef HAVE_POLL_H
	if (*sockfd >= FD_SETSIZE) {
		_pam_log(LOG_ERR, "Unusable socket, FD is larger than %d\n", FD_SETSIZE);
		return -1;
	}
#endif

	if (vrf && vrf[0]) {
#ifdef SO_BINDTODEVICE
		int r = setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, vrf, strlen(vrf));
		if (r != 0) {
			_pam_log(LOG_ERR, "Failed bind to %s: %s", vrf, strerror(errno));
			return -1;
		}
#else
		_pam_log(LOG_ERR, "No SO_BINDTODEVICE, unable to bind to: %s", vrf);
		return -1;
#endif
	}

	/* If not TCP or has a source address set up the local end of the socket communications */
	if(!tcp || ((struct sockaddr_in*)salocal4)->sin_addr.s_addr != 0) {
		if (bind(*sockfd, (struct sockaddr *)salocal4, sizeof (struct sockaddr_in)) < 0) {
			char error_string[BUFFER_SIZE];
			get_error_string(errno, error_string, sizeof(error_string));
			_pam_log(LOG_ERR, "Failed binding to port: %s", error_string);
			return -1;
		}
	}

	if (!conf->use_ipv6) {
		*sockfd6 = -1;
		return 0;
	}

use_ipv6:
	/* open a IPv6 socket. */
	*sockfd6 = socket(AF_INET6, (tcp? SOCK_STREAM: SOCK_DGRAM), 0);
	if (*sockfd6 < 0) {
		char error_string[BUFFER_SIZE];

		/*
		 *	IPv6 can be disabled on localhost.
		 */
		if (errno == EAFNOSUPPORT) return 0;

		get_error_string(errno, error_string, sizeof(error_string));
		_pam_log(LOG_ERR, "Failed to open RADIUS IPv6 socket: %s\n", error_string);
		return -1;
	}
#ifndef HAVE_POLL_H
	if (*sockfd6 >= FD_SETSIZE) {
		_pam_log(LOG_ERR, "Unusable socket, FD is larger than %d\n", FD_SETSIZE);
		return -1;
	}
#endif

	if (vrf && vrf[0]) {
#ifdef SO_BINDTODEVICE
		int r = setsockopt(*sockfd6, SOL_SOCKET, SO_BINDTODEVICE, vrf, strlen(vrf));
		if (r != 0) {
			_pam_log(LOG_ERR, "Failed bind to %s: %s", vrf, strerror(errno));
			return -1;
		}
#else
		_pam_log(LOG_ERR, "No SO_BINDTODEVICE, unable to bind to: %s", vrf);
		return -1;
#endif
	}

	/* If not TCP or has a source address set up the local end of the socket communications */
	if(!tcp || memcmp(&((struct sockaddr_in6*)salocal6)->sin6_addr,&in6addr_any,sizeof(struct in6_addr))) {

		if (bind(*sockfd6, (struct sockaddr *)salocal6, sizeof (struct sockaddr_in6)) < 0) {
			char error_string[BUFFER_SIZE];
			get_error_string(errno, error_string, sizeof(error_string));
			_pam_log(LOG_ERR, "Failed binding to IPv6 port: %s", error_string);
			return -1;
		}

	}

	return 0;
}

#ifdef HAVE_LIBSSL
static SSL_CTX* initialize_ssl(const char *certfile,const char *keyfile,const char *cafilename)
{
	SSL_CTX *ctx;
	char error_string[BUFFER_SIZE];
	if( !(ctx = SSL_CTX_new(TLS_client_method()))) return NULL;
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1); // ma forse meglio SSL_set_min_proto_version(sslctx,TLS1_1_VERSION);
	SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);
	if(cafilename) {
		if( !SSL_CTX_load_verify_locations(ctx, cafilename, NULL)) {
			_pam_log(LOG_ERR,"Could not load CAs from '%s': %s", cafilename, ERR_error_string(ERR_get_error(), error_string));
			SSL_CTX_free(ctx);
			return NULL;
		}
	}
	else if( !SSL_CTX_set_default_verify_paths(ctx)) {
		_pam_log(LOG_ERR,"Could not load CAs: %s", cafilename, ERR_error_string(ERR_get_error(), error_string));
		SSL_CTX_free(ctx);
		return NULL;
	}
	if( SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) == 1) {
		if( SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) == 1) {
			if( SSL_CTX_check_private_key(ctx) == 1) {
				return ctx;
			}
			else _pam_log(LOG_ERR,"Wrong certificate/private key: %s", ERR_error_string(ERR_get_error(), error_string));
		}
		else _pam_log(LOG_ERR,"Could not load private key from '%s': %s", keyfile, ERR_error_string(ERR_get_error(), error_string));
	}
	else _pam_log(LOG_ERR,"Could not load certificate from '%s': %s", certfile, ERR_error_string(ERR_get_error(), error_string));
	SSL_CTX_free(ctx);
	return NULL;
}
#endif

/*
 * allocate and open a local port for communication with the RADIUS
 * server
 */
static int initialize(radius_conf_t *conf, int accounting)
{
	struct sockaddr_storage salocal;
	struct sockaddr_storage salocal4;
	struct sockaddr_storage salocal6;
	char hostname[BUFFER_SIZE];
	char secret[BUFFER_SIZE];

	char buffer[BUFFER_SIZE];
	char *p;
	FILE *fp;
	radius_server_t *server, **last;
	int timeout, ctimeout;
	int line = 0;
	char src_ip[MAX_IP_LEN+1];
	int valid_src_ip;
	char vrf[IFNAMSIZ+1];
	char *tok, *eptr, *pptr;

	memset(&salocal4, 0, sizeof(salocal4));
	memset(&salocal6, 0, sizeof(salocal6));
	((struct sockaddr *)&salocal4)->sa_family = AF_INET;
	((struct sockaddr *)&salocal6)->sa_family = AF_INET6;
	conf->sockfd = -1;
	conf->sockfd6 = -1;

#ifdef HAVE_LIBSSL
	/* Setup OpenSSL and certificates if radsec is enabled */
	if(conf->radsec && conf->cert && conf->key) {
		if( !(conf->ssl = initialize_ssl(conf->cert, conf->key, conf->ca ? conf->ca : NULL))) {
			_pam_log(LOG_ERR,"Could not initialize SSL, all RADSEC servers are disabled");
		}
	}
#endif

	/* the first time around, read the configuration file */
	fp = fopen (conf->conf_file, "r");
	if (!fp) {
		char error_string[BUFFER_SIZE];
		get_error_string(errno, error_string, sizeof(error_string));
		_pam_log(LOG_ERR, "Could not open configuration file %s: %s\n",
			 conf->conf_file, error_string);
		return PAM_ABORT;
	}

	conf->server = NULL;
	last = &conf->server;

	/*
	 *	Read the file
	 */
	while (!feof(fp) && (fgets (buffer, sizeof(buffer), fp) != NULL) && (!ferror(fp))) {
		line++;
		p = buffer;

		/*
		 *	Skip whitespace
		 */
		while ((*p == ' ') || (*p == '\t')) p++;

		/*
		 *	Skip blank lines and comments.
		 */
		if ((*p == '\r') || (*p == '\n') || (*p == '#')) continue;

		/*
		 *	Error out if the text is too long.
		 */
		if (!*p) {
			_pam_log(LOG_ERR, "ERROR reading %s, line %d: Line too long\n",
				 conf->conf_file, line);
			break;
		}

		/*
		 *	Initialize the optional variables.
		 */
		timeout = 3;
		ctimeout = 2;
		src_ip[0] = 0;
		vrf[0] = 0;

		/*
		 *	Scan the line for data.
		 */
		//#define _PARSE_STRICT_
		/* Read hostname */
		pptr=NULL;
		if(!(tok=strtok_r(p," \t\r\n", &pptr))) {
			_pam_log(LOG_ERR, "ERROR reading %s, line %d: Could not read hostname",
				 conf->conf_file, line);
			continue;			/* invalid line */
		}
		strcpy(hostname, tok);
		p=tok+strlen(tok)+1;	/* reset just ahead the hostname */

		/* Read secret */
		while ((*p == ' ') || (*p == '\t') || (*p == '\r') || (*p == '\n')) p++;
		if(*p == '\'') {
			/* secret is a quoted string*/
			p++;
			tok = secret;
			while(*p && (*p != '\'' && *p != '\r' && *p != '\n')) {
				/* allow single quote in secret if escaped by "\" */
				if(*p == '\\' && p[1] == '\'') p++;
				*tok++ = *p++;
			}
			if(*p != '\'') {
				/* closing quote not found */
				_pam_log(LOG_ERR, "ERROR reading %s, line %d: Could not read secret, quote not closed",
					 conf->conf_file, line);
				continue;			/* invalid line */
			}
			*tok = '\0';
			p++;			/* restart parsing context at next strtok */
			pptr=NULL;
		} else {
			/* allow secret stating with single quote if escaped by "\" */
			if(*p == '\\' && (p[1] == '\'' || p[1] == '\\')) p++;
			pptr=NULL;
			if(!(tok=strtok_r(p," \t\r\n", &pptr))) {
				_pam_log(LOG_ERR, "ERROR reading %s, line %d: Could not read secret",
					conf->conf_file, line);
				continue;			/* invalid line */
			}
			strcpy(secret, tok);
			p=NULL;			/* continue strtok as usual */
		}

		/* Read timout */
		if((tok=strtok_r(p," \t\r\n", &pptr))) {
			timeout = strtol(tok, &eptr, 10);
			if(eptr != tok && *eptr == ',') {
				tok=eptr + 1;
				ctimeout = strtol(tok, &eptr, 10);
			}
		#ifdef _PARSE_STRICT_
			if(eptr != tok && *eptr=='\0')
		#else
			if(eptr != tok)
		#endif
			{
				/* Read src_ip */
				if((tok=strtok_r(NULL," \t\r\n", &pptr))) {
					strncpy(src_ip, tok, sizeof(src_ip)-1);
					if(src_ip[sizeof(src_ip)-2] != '\0') {
						_pam_log(LOG_ERR, "ERROR reading %s, line %d: source_ip '%s' to long (max %zu chars)",
							conf->conf_file, line, tok, sizeof(src_ip)-1);
						continue;			/* invalid line */
					}

					/* Read vrf */
					if((tok=strtok_r(NULL," \t\r\n", &pptr))) {
						strncpy(vrf, tok, sizeof(vrf)-1);
						if(vrf[sizeof(vrf)-2] != '\0') {
							_pam_log(LOG_ERR, "ERROR reading %s, line %d: vrf '%s' to long (max %zu chars)",
								conf->conf_file, line, tok, sizeof(vrf)-1);
							continue;			/* invalid line */
						}

					#ifdef _PARSE_STRICT_
						if((tok=strtok_r(NULL," \t\r\n", &pptr))) {
							_pam_log(LOG_ERR, "ERROR reading %s, line %d: Unexpected content at '%s'",
								conf->conf_file, line, tok);
							continue;			/* invalid line */
						}
					#endif

					}
				}
			}
		#ifdef _PARSE_STRICT_
			else {
				_pam_log(LOG_ERR, "ERROR reading %s, line %d: Invalid timeout '%s'",
					 conf->conf_file, line, tok);
				continue;			/* invalid line */
			}
		#endif
		}

		/*
		 *	Fill in the relevant fields.
		 */
		server = calloc(1, sizeof(radius_server_t));
		//*last = server;
		server->next = NULL;
		//last = &server->next;

		/* Check if TCP */
		if(!strncmp("tcp://",hostname,6)) server->proto = rad_proto_tcp;
	#ifdef HAVE_LIBSSL
		else if(!strncmp("tls://",hostname,6)) {
			if(!conf->ssl) {
				if(conf->radsec == 1) {
					_pam_log(LOG_ERR,"Could not use RADIUS server %s: RADSEC disabled", hostname);
					free(server);
					continue;
				}
				_pam_log(LOG_WARNING,"RADSEC disabled. server %s fallback to UDP", hostname);
				server->proto = rad_proto_udp;
			}
			else server->proto = rad_proto_sec;
		}
		else if(conf->radsec) {
			if(conf->ssl && conf->radsec == 1) server->proto = rad_proto_sec;
			else server->proto = rad_proto_udp;
		}
	#else
		else if(!strncmp("tls://",hostname,6)) {
			server->proto = rad_proto_udp;
			_pam_log(LOG_WARNING,"RADSEC unsupported. server %s fallback to UDP", hostname);
		}
	#endif
		else server->proto = rad_proto_udp;

		*last = server;
		//server->next = NULL;
		last = &server->next;

		/* sometime later do memory checks here */
		server->hostname = strdup(hostname);
		server->secret = strdup(secret);
		server->accounting = accounting;

		/*
		 *	Clamp the timeouts to reasonable values.
		 */
		if (timeout < 3) {
			server->timeout = 3;
		} else if (timeout > 60) {
			server->timeout = 60;
		} else {
			server->timeout = timeout;
		}
		if (ctimeout < 1) {
			server->connect_timeout = 1;
		} else if (ctimeout > 60) {
			server->connect_timeout = 60;
		} else {
			server->connect_timeout = ctimeout;
		}

		server->sockfd = -1;
		server->sockfd6 = -1;

		/*
		 *	No source IP for this socket and not TCP, it uses the
		 *	global one.
		 */
		if (!src_ip[0] && !server->proto) continue;

		memset(&salocal4, 0, sizeof(salocal4));
		memset(&salocal6, 0, sizeof(salocal6));
		((struct sockaddr *)&salocal4)->sa_family = AF_INET;
		((struct sockaddr *)&salocal6)->sa_family = AF_INET6;

		valid_src_ip = -1;
		vrf[IFNAMSIZ - 1] = 0;

		memset(&salocal, 0, sizeof(salocal));
		valid_src_ip = get_ipaddr(src_ip, (struct sockaddr *)&salocal, NULL);
		if (valid_src_ip == 0) {
			switch (salocal.ss_family) {
			case AF_INET:
				memcpy(&salocal4, &salocal, sizeof(salocal));
				break;

			case AF_INET6:
				memcpy(&salocal6, &salocal, sizeof(salocal));
				break;
			}
		}

		/* TCP needs its own socket */
		if (valid_src_ip == 0 || vrf[0] || server->proto) {
		#ifndef NDEBUG
			if(server->proto) _pam_log(LOG_DEBUG,"Use TCP for %s\n",server->hostname);
		#endif
			if (initialize_sockets(conf, &server->sockfd, &server->sockfd6, &salocal4, &salocal6, vrf, server->proto) != 0) {
				goto error;
			}
		}
	}

	if (!conf->server) {		/* no server found, die a horrible death */
		_pam_log(LOG_ERR, "No RADIUS server found in configuration file %s\n",
			 conf->conf_file);
		goto error;
	}

	/*
	 *	Open the global sockets.
	 */
	memset(&salocal4, 0, sizeof(salocal4));
	memset(&salocal6, 0, sizeof(salocal6));
	((struct sockaddr *)&salocal4)->sa_family = AF_INET;
	((struct sockaddr *)&salocal6)->sa_family = AF_INET6;

	if (initialize_sockets(conf, &conf->sockfd, &conf->sockfd6, &salocal4, &salocal6, NULL, 0) != 0) {
		goto error;
	}

	fclose(fp);
	return PAM_SUCCESS;

error:
	fclose(fp);

	if (conf->sockfd != -1)	close(conf->sockfd);
	
	if (conf->sockfd6 != -1) close(conf->sockfd6);
	
	cleanup(conf->server);
	
	return PAM_AUTHINFO_UNAVAIL;
}

/*
 * Helper function for building a radius packet.
 * It initializes *some* of the header, and adds common attributes.
 */
static void build_radius_packet(AUTH_HDR *request, CONST char *user, CONST char *password, radius_conf_t *conf)
{
	char hostname[MAXHOSTNAMELEN + 1];

	hostname[0] = '\0';
	if (conf->hostname[0] != '\0') {
		strcpy(hostname, conf->hostname);
	} else {
		gethostname(hostname, sizeof(hostname) - 1);
	}

	/*
	 *	For Access-Request, create a random authentication
	 *	vector, and always add a Message-Authenticator
	 *	attribute.
	 */
	if (request->code == PW_ACCESS_REQUEST) {
              uint8_t *attr = (uint8_t *) request + AUTH_HDR_LEN;

	      get_random_vector(request->vector);

              attr[0] = PW_MESSAGE_AUTHENTICATOR;
              attr[1] = 18;
              memset(attr + 2, 0, AUTH_VECTOR_LEN);
	      conf->message_authenticator = attr + 2;

              request->length = htons(AUTH_HDR_LEN + 18);
	} else {
		request->length = htons(AUTH_HDR_LEN);
		conf->message_authenticator = NULL;
	}

	add_attribute(request, PW_USER_NAME, (CONST uint8_t *) user, strlen(user));

	/*
	 *	Add a password, if given.
	 */
	if (password) {
		add_password(request, PW_USER_PASSWORD, password, conf->server->secret);

		/*
		 *	Add a NULL password to non-accounting requests.
		 */
	} else if (request->code != PW_ACCOUNTING_REQUEST) {
		add_password(request, PW_USER_PASSWORD, "", conf->server->secret);
	}

	/* Perhaps add NAS IP Address (and v6 version) */
	add_nas_ip_address(request, hostname);

	/* There's always a NAS identifier */
	if (conf->client_id && *conf->client_id) {
		add_attribute(request, PW_NAS_IDENTIFIER, (CONST uint8_t *) conf->client_id, strlen(conf->client_id));
	}

	/*
	 *	Add in the port (pid) and port type (virtual).
	 *
	 *	We might want to give the TTY name here, too.
	 */
	add_int_attribute(request, PW_NAS_PORT_ID, getpid());
	add_int_attribute(request, PW_NAS_PORT_TYPE, PW_NAS_PORT_TYPE_VIRTUAL);
}

static int ipaddr_cmp(struct sockaddr_storage const *a, struct sockaddr_storage const *b)
{
	if (a->ss_family != b->ss_family) {
		_pam_log(LOG_ERR, "RADIUS packet from invalid source - ignoring it");
		return 0;
	}

	switch (a->ss_family) {
	case AF_INET:
		return (memcmp(&((struct sockaddr_in const *) a)->sin_addr.s_addr,
			       &((struct sockaddr_in const *) b)->sin_addr.s_addr,
			       sizeof(((struct sockaddr_in const *) a)->sin_addr.s_addr)) == 0);

	case AF_INET6:
		return (memcmp(&((struct sockaddr_in6 const *) a)->sin6_addr.s6_addr,
			       &((struct sockaddr_in6 const *) b)->sin6_addr.s6_addr,
			       sizeof(((struct sockaddr_in6 const *) a)->sin6_addr.s6_addr)) == 0);

	default:
		break;
	}

	return 0;
}

static int connect_tmout(int sockfd,struct sockaddr *ip,socklen_t salen,int tmout 
#ifdef HAVE_LIBSSL 
,SSL *ssl
#endif
)
{
	int rcode;
	int flags;
	int done = 0;
#ifdef HAVE_POLL_H
	struct pollfd pollfds[1];
#else
	fd_set set;
#endif
	struct timeval now, end;
	struct timeval tv;
	socklen_t len=sizeof(flags);

	if((flags=fcntl(sockfd, F_GETFL, 0))!=-1) {
		flags |= O_NONBLOCK;
		flags=fcntl(sockfd, F_SETFL, flags);
	}
	if(flags!=-1) {
		if(connect(sockfd, ip, salen)==-1)
		{
			if(errno!=EINPROGRESS) {
				return -1;
			}
		}
	}
	else {
		return -1;
	}

#ifdef HAVE_POLL_H
	pollfds[0].fd = sockfd;   
	pollfds[0].events = POLLOUT;     /* wait for data to write */
#else
	FD_ZERO(&set); 
	FD_SET(sockfd, &set);    
#endif
	gettimeofday(&end,NULL);
	tv.tv_sec = tmout; 
	tv.tv_usec = 0;
	end.tv_sec += tv.tv_sec;

	int wr = 1;
	while(1) {
	#ifndef NDEBUG
		_pam_log(LOG_DEBUG,"DEBUG: connect: TM=%u.%u WAIT %u ms [start %u.%u now %u.%u]",tv.tv_sec,tv.tv_usec,tv.tv_sec * 1000 + (int)(tv.tv_usec / 1000),end.tv_sec,end.tv_usec,now.tv_sec,now.tv_usec);
	#endif
#ifdef HAVE_POLL_H
		wr = wr; /* avoid compiler warning */
		rcode = poll((struct pollfd *) &pollfds, 1, tv.tv_sec * 1000 + (int)(tv.tv_usec / 1000));
#else
		rcode = select(sockfd + 1, wr ? NULL : &set, wr ? &set : NULL, NULL, &tv);
#endif
		if(rcode == -1) {
			if (errno != EINTR) return -1;
		}
		else if(!rcode) {
			errno=ETIMEDOUT;
			return -1;
#ifdef HAVE_POLL_H
		} else if (pollfds[0].revents & POLLOUT || (pollfds[0].revents & POLLIN)) {
#else
		} else if(FD_ISSET(sockfd,&set)) {
#endif
			if(!done) {
				if(getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)&flags,&len) ==-1) return -1;
				if(!flags) {
				#ifdef HAVE_LIBSSL
					if(!ssl) break; /* TCP connected we are done */
				#endif
					done = 1;
				} else {
					errno = flags;
					return -1;
				}
			}
		#ifdef HAVE_LIBSSL
			if( (rcode = SSL_connect(ssl)) < 1) {
				int err;
				err	= SSL_get_error(ssl, rcode);
				switch(err) {
					case SSL_ERROR_SYSCALL:
						if(!errno) errno=ECONNRESET;
						return -1;
					default:
						return -2;
					case SSL_ERROR_WANT_READ:
						wr = 0;
					#ifdef HAVE_POLL_H
						pollfds[0].events = POLLIN;
					#endif
						break;
					case SSL_ERROR_WANT_WRITE:
						wr = 1;
					#ifdef HAVE_POLL_H
						pollfds[0].events = POLLOUT;
					#endif
						break;
				}
			}
			else 
		#endif
			break;
		}
#ifdef HAVE_POLL_H
		/* calculate next timeout */
		gettimeofday(&now,NULL);
		timersub(&end,&now,&tv);
		if(tv.tv_sec < 0 ) {
			tv.tv_sec = tv.tv_usec = 0;
		}
#endif
	}
	if((flags=fcntl(sockfd, F_GETFL, 0)) == -1) return -1;
	flags &= (~O_NONBLOCK);
	if((flags=fcntl(sockfd, F_SETFL, flags)) ==-1 ) return -1;
	return 0;
}

/*
 * Talk RADIUS to a server.
 * Send a packet and get the response
 */
static int talk_radius(radius_conf_t *conf, AUTH_HDR *request, AUTH_HDR *response,
		       char *password, int tries)
{
	int total_length;
#ifdef HAVE_POLL_H
	struct pollfd pollfds[1];
#else
	fd_set set;
#endif
	struct timeval tv;

	struct timeval now, end;
	int rcode;
	radius_server_t *server = conf->server;
	int ok;
	int server_tries;
	int retval;
	int sockfd;
	socklen_t salen;
	struct sockaddr_storage sockaddr_storage;

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
		/* clear the response */
		memset(response, 0, sizeof(AUTH_HDR));

		/* only look up IP information as necessary */
		retval = host2server(conf->debug, server);
		if (retval != 0) {
			_pam_log(LOG_ERR,
				 "Failed looking up IP address for RADIUS server %s (error=%s)",
				 server->hostname, gai_strerror(retval));
			ok = FALSE;
			goto next;		/* skip to the next server */
		}

		if (request->code == PW_ACCESS_REQUEST) {
			memset(conf->message_authenticator, 0, AUTH_VECTOR_LEN);
			hmac_md5(conf->message_authenticator, (uint8_t *) request, ntohs(request->length),
				 (const uint8_t *) server->secret, strlen(server->secret));

		} else {
			/* make an RFC 2139 p6 request authenticator */
			get_accounting_vector(request, server);
		}

		if (server->ip->sa_family == AF_INET) {
			sockfd = server->sockfd != -1 ? server->sockfd : conf->sockfd;
		} else {
			sockfd = server->sockfd6 != -1 ? server->sockfd6 : conf->sockfd6;
		}

		/*
		 *	Is there a valid socket for this server + address family?  If not, skip it.
		 */
		if (sockfd < 0) {
			ok = FALSE;
			goto next;
		}

		server_tries = tries;

		/* If TCP/TLS check if connected and otherwise connect */
		if(server->proto) {
			
			salen = sizeof(sockaddr_storage);
			rcode = getpeername(sockfd, (struct sockaddr *) &sockaddr_storage, &salen);
			if(rcode == -1 && errno != ENOTCONN) {
				char error_string[BUFFER_SIZE];
				get_error_string(errno, error_string, sizeof(error_string));
				_pam_log(LOG_ERR, "RADIUS server %s getpeername failed: %s",
				 	server->hostname, error_string);
				ok = FALSE;
				goto next;		/* skip to the next server */

			} else if(rcode == -1) {

				if(conf->debug) _pam_log(LOG_DEBUG,"Setup connection for %s\n",server->hostname);

		#ifdef HAVE_LIBSSL
				if(server->proto == rad_proto_sec) {
					if(!(server->ssl=SSL_new(conf->ssl))) {
						_pam_log(LOG_ERR,"RADIUS server %s TLS initialization failed", server->hostname);
						ok = FALSE;
						goto next;
					}
					SSL_set_fd(server->ssl,sockfd);
				}
		#endif

				rcode = connect_tmout(sockfd, server->ip, server->ip->sa_family == AF_INET? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6), server->connect_timeout
			#ifdef HAVE_LIBSSL
				, server->proto == rad_proto_sec ? server->ssl : NULL
			#endif
				);
				if(rcode < 0) {
					char error_string[BUFFER_SIZE];
					#ifdef HAVE_LIBSSL
					if(rcode == -2) {
						int err;
						err = SSL_get_error(server->ssl, rcode);
						ERR_error_string(err, error_string);
					}
					else 
					#endif
					get_error_string(errno, error_string, sizeof(error_string));
					_pam_log(LOG_ERR,"%s server %s %s failed: %s\n", server->proto == rad_proto_tcp ? "RADIUS": "RADSEC", server->hostname, rcode == -2 ? "handshake" : "connection", error_string);
					ok = FALSE;
					goto next;
				}
				#ifdef HAVE_LIBSSL
				if(server->proto == rad_proto_sec) {
					int err;
					char certname[1000];
					X509 *cert=SSL_get_peer_certificate(server->ssl);
					if(!cert) {
						_pam_log(LOG_ERR,"RADSEC server %s could not get certificate", server->hostname);
						ok = FALSE;
						goto next;
					}
					X509_NAME_oneline(X509_get_subject_name(cert),certname,sizeof(certname));
					X509_free(cert);
					if(conf->debug) _pam_log(LOG_DEBUG,"RADSEC server %s connected: %s", server->hostname, certname);
					if((err=SSL_get_verify_result(server->ssl))!=X509_V_OK) {
						_pam_log(conf->ssl_verify ? LOG_ERR : LOG_WARNING, "RADSEC server %s certificate '%s' invalid: %s", server->hostname, certname, X509_verify_cert_error_string(err));
						if(conf->ssl_verify) {
							ok = FALSE;
							goto next;
						}
					}
				}
				else if(conf->debug) {
				#else
				if(conf->debug) {
				#endif
					_pam_log(LOG_DEBUG,"RADIUS server %s connected\n", server->hostname);
				}
			}
		}
	send:
		if (server->ip->sa_family == AF_INET) {
			salen = sizeof(struct sockaddr_in);
		} else {
			salen = sizeof(struct sockaddr_in6);
		}
		

		total_length = ntohs(request->length);

		/* send the packet */
	#ifdef HAVE_LIBSSL
		if(server->proto == rad_proto_sec) {
			if( (rcode = SSL_write(server->ssl, request, total_length)) < 1) {
				int err=SSL_get_error(server->ssl, rcode);
				char error_string[BUFFER_SIZE];
				if( err == SSL_ERROR_SYSCALL) {
					get_error_string(errno, error_string, sizeof(error_string));
				} else {
					ERR_error_string(err, error_string);
				}
				_pam_log(LOG_ERR, "Error sending RADSEC packet to server %s: %s",
				 	server->hostname, error_string);
				ok = FALSE;
				goto next;		/* skip to the next server */
			}
		} else {
	#endif
		if (sendto(sockfd, (char *) request, total_length, MSG_NOSIGNAL, server->ip, salen) < 0) {
			char error_string[BUFFER_SIZE];
			get_error_string(errno, error_string, sizeof(error_string));
			_pam_log(LOG_ERR, "Error sending RADIUS packet to server %s: %s",
				 server->hostname, error_string);
			ok = FALSE;
			goto next;		/* skip to the next server */
		}
	#ifdef HAVE_LIBSSL
		}
	#endif

		/* ************************************************************ */
		/* Wait for the response, and verify it. */
		gettimeofday(&end,NULL);

		tv.tv_sec = server->timeout;    /* wait for the specified time */
		tv.tv_usec = 0;
		end.tv_sec += tv.tv_sec;

#ifdef HAVE_POLL_H
		pollfds[0].fd = sockfd;   /* wait only for the RADIUS UDP socket */
		pollfds[0].events = POLLIN;     /* wait for data to read */
#else
		FD_ZERO(&set);                  /* clear out the set */
		FD_SET(sockfd, &set);     /* wait only for the RADIUS UDP socket */
#endif

		/* loop, waiting for the network to return data */
		ok = TRUE;
		total_length = 0;
		while (ok) {
		#ifndef NDEBUG
			_pam_log(LOG_DEBUG,"DEBUG: recv: TM=%u.%u WAIT %u ms [start %u.%u now %u.%u]",tv.tv_sec,tv.tv_usec,tv.tv_sec * 1000 + (int)(tv.tv_usec / 1000),end.tv_sec,end.tv_usec,now.tv_sec,now.tv_usec);
		#endif
#ifdef HAVE_POLL_H
			rcode = poll((struct pollfd *) &pollfds, 1, tv.tv_sec * 1000 + (int)(tv.tv_usec / 1000));
#else
			rcode = select(sockfd + 1, &set, NULL, NULL, &tv);
#endif

			/* timed out */
			if (rcode == 0) {
				_pam_log(LOG_ERR, "RADIUS server %s failed to respond", server->hostname);
				if (server->proto == rad_proto_udp && --server_tries) {
					goto send;
				}
				ok = FALSE;
				break;			/* exit from the loop */
			}

			if (rcode < 0) {
				/* poll returned an error */
				if (errno == EINTR) {	/* we were interrupted */
					gettimeofday(&now,NULL);

					if(timercmp(&now,&end,>)) {
						_pam_log(LOG_ERR, "RADIUS server %s failed to respond",
							 server->hostname);
						if (server->proto == rad_proto_udp && --server_tries) goto send;
						ok = FALSE;
						break;		/* exit from the loop */
					}

					timersub(&end,&now,&tv);
					if(tv.tv_sec < 0  ) {
						tv.tv_sec = tv.tv_usec = 0;
					}
				} else {			/* not an interrupt, it was a real error */
					char error_string[BUFFER_SIZE];
					get_error_string(errno, error_string, sizeof(error_string));
					_pam_log(LOG_ERR, "Error waiting for response from RADIUS server %s: %s",
						 server->hostname, error_string);
					ok = FALSE;
					break;
				}

			/* the call returned OK */
#ifdef HAVE_POLL_H
			} else if (pollfds[0].revents & POLLIN) {
#else
			} else if (FD_ISSET(sockfd, &set)) {
#endif
				/* try to receive some data */
				salen = sizeof(sockaddr_storage);

				int rlen;
				if(server->proto == rad_proto_tcp) {
					rlen=recv(sockfd, (void*)(response+total_length), BUFFER_SIZE-total_length, 0);
			#ifdef HAVE_LIBSSL
				} else if(server->proto == rad_proto_sec) {
					if( (rlen=SSL_read(server->ssl,response+total_length, BUFFER_SIZE-total_length)) < 1) {
						int err=SSL_get_error(server->ssl, rlen);
						if(err == SSL_ERROR_WANT_READ) {
						#ifdef HAVE_POLL_H
							/* calculate next timeout */
							gettimeofday(&now,NULL);
							timersub(&end,&now,&tv);
							if(tv.tv_sec < 0 ) {
								tv.tv_sec = tv.tv_usec = 0;
							}
						#endif
							continue;
						}
						else if(err == SSL_ERROR_SYSCALL) {
							rlen=-1;
							if(!errno) errno=ECONNRESET;
						}
						else if(err == SSL_ERROR_ZERO_RETURN) rlen=0;
						else {
							char error_string[BUFFER_SIZE];
							ERR_error_string(err, error_string);
							_pam_log(LOG_ERR,"error reading RADSEC packet from %s: [%u]: %s",
								server->hostname, err, error_string);
							ok = FALSE;
							goto next;
						}
					}
			#endif
				} else {
					rlen=recvfrom(sockfd, (void *) response, BUFFER_SIZE, 0, (struct sockaddr *) &sockaddr_storage, &salen);
				}
				if(rlen < 0) {
					char error_string[BUFFER_SIZE];
					get_error_string(errno, error_string, sizeof(error_string));
					_pam_log(LOG_ERR, "error reading RADIUS packet from server %s: %s",
					 	 server->hostname, error_string);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}
				#ifndef NDEBUG
				_pam_log(LOG_DEBUG,"DEBUG: %s recv len=%u tot=%u\n",server->hostname,rlen,total_length);
				#endif
				if(server->proto) {
					total_length += rlen;
					if(!rlen) {
						_pam_log(LOG_ERR, "error reading RADIUS packet from server %s: Connection closed by foreign host",
					 	 	server->hostname);
						ok = FALSE;
						goto next;
					}
					if( (total_length < (int)offsetof(AUTH_HDR,vector))  /* Check if you have read up to the response length  and */
						|| (ntohs(response->length) > total_length) ) {  /* Check if you have read all the response or wait for more */
					#ifdef HAVE_POLL_H
						/* calculate next timeout */
						gettimeofday(&now,NULL);
						timersub(&end,&now,&tv);
						if(tv.tv_sec < 0 ) {
							tv.tv_sec = tv.tv_usec = 0;
						}
					#endif
						continue;
					}
				} else {

					total_length = rlen;
				/*
				 *	Ignore packets from the wrong source iP
				 */
					if (!ipaddr_cmp(&sockaddr_storage, &server->ip_storage)) {
						_pam_log(LOG_ERR, "Received data from unexpected source - ignoring it");
						continue;
					}
				}

				if ((ntohs(response->length) != total_length) ||
				    (ntohs(response->length) > BUFFER_SIZE)) {
					_pam_log(LOG_ERR, "RADIUS packet from server %s is corrupted",
						 server->hostname);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}

				/*
				 * Check that the response ID matches the request ID.
				 */
				if (response->id != request->id) {
					_pam_log(LOG_WARNING, "Response packet ID %d does not match the "
						 "request packet ID %d: ignoring it.",
						 response->id, request->id);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}

				if ((request->code == PW_ACCOUNTING_REQUEST) && (response->code != PW_ACCOUNTING_RESPONSE)) {
					_pam_log(LOG_WARNING, "Invalid response to Accounting-Request: ignoring it.",
						 response->id, request->id);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}

				if ((request->code == PW_ACCESS_REQUEST) &&
				    !((response->code == PW_ACCESS_ACCEPT) || (response->code == PW_ACCESS_REJECT) || (response->code == PW_ACCESS_CHALLENGE))) {
					_pam_log(LOG_WARNING, "Invalid response to Access-Request: ignoring it.",
						 response->id, request->id);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}

				if (!verify_packet(server, response, request, conf)) {
					_pam_log(LOG_ERR, "packet from RADIUS server %s failed verification: "
						 "The shared secret is probably incorrect.", server->hostname);
					if(server->proto == rad_proto_udp) continue;
					ok = FALSE;
					goto next;
				}

				/*
				 * Whew! The poll is done. It hasn't timed out, or errored out.
				 * It's our descriptor.	We've got some data. It's the right size.
				 * The packet is valid.
				 * NOW, we can skip out of the loop, and process the packet
				 */
				break;
			}
			/* otherwise, we've got data on another descriptor, keep checking the network */
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
		#ifdef HAVE_LIBSSL
			if(server->ssl) {
				SSL_free(server->ssl);
				server->ssl=NULL;
			}
		#endif
			if(old->sockfd != -1) close(old->sockfd);
			if(old->sockfd6 != -1) close(old->sockfd6);
			free(old);

			if (server) {		/* if there's more servers to check */
				/* get a new authentication vector, and update the passwords */
				get_random_vector(request->vector);
				request->id = request->vector[0];

				/* update passwords, as appropriate */
				if (password) {
					get_random_vector(request->vector);
					add_password(request, PW_USER_PASSWORD, password, server->secret);
				}
			}
			continue;

		} else {
			/* we've found one that does respond, forget about the other servers */
			cleanup(server->next);
			server->next = NULL;
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

static int rad_converse(pam_handle_t *pamh, int msg_style, const char *message, char **password)
{
	CONST struct pam_conv *conv;
	struct pam_message resp_msg;
	CONST struct pam_message *msg[1];
	struct pam_response *resp = NULL;
	int retval;

	resp_msg.msg_style = msg_style;
	memcpy(&resp_msg.msg, &message, sizeof(resp_msg.msg));

	msg[0] = &resp_msg;

	/* grab the password */
	retval = pam_get_item(pamh, PAM_CONV, (CONST void **) &conv);
	PAM_FAIL_CHECK;

	retval = conv->conv(1, msg, &resp, conv->appdata_ptr);
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
#define PAM_FAIL_CHECK \
	if (retval != PAM_SUCCESS) { \
		int *pret = malloc(sizeof(int)); \
		*pret = retval;	\
		pam_set_data(pamh, "rad_setcred_return", (void *) pret, _int_free);	\
		return retval; \
	}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, UNUSED int flags, int argc, CONST char **argv)
{
	CONST char *user = NULL;
	CONST char *userinfo = NULL;
	CONST char *old_password = NULL;
	char *password = NULL;
	CONST char *rhost = NULL;
	char *resp2challenge = NULL;
	int ctrl;
	int debug;
	int retval = PAM_AUTH_ERR;
	int num_challenge = 0;

	char recv_buffer[4096];
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
	radius_conf_t config;

	/**
	 *	It must be always printed out helping to know which version is in use.
	 */
	_pam_log(LOG_DEBUG, "%s", pam_module_version);

	ctrl = _pam_parse(argc, argv, &config);
	debug = config.debug;

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something, and not too long, either */
	if ((user == NULL) || (strlen(user) > MAXPWNAM)) {
		int *pret = malloc(sizeof(int));
		*pret = PAM_USER_UNKNOWN;
		pam_set_data(pamh, "rad_setcred_return", (void *) pret, _int_free);

		DPRINT(LOG_DEBUG, "User name was NULL, or too long");
		return PAM_USER_UNKNOWN;
	}

	DPRINT(LOG_DEBUG, "Got user name: '%s'", user);

	if (ctrl & PAM_RUSER_ARG) {
		retval = pam_get_item(pamh, PAM_RUSER, (CONST void **) &userinfo);
		PAM_FAIL_CHECK;
		DPRINT(LOG_DEBUG, "Got PAM_RUSER name %s", userinfo);

		if (!strcmp("root", user)) {
			user = userinfo;
			DPRINT(LOG_DEBUG, "Username now %s from ruser", user);
		} else {
			DPRINT(LOG_DEBUG, "Skipping ruser for non-root auth");
		}
	}

	/*
	 * Get the IP address of the authentication server
	 * Then, open a socket, and bind it to a port
	 */
	retval = initialize(&config, FALSE);
#ifdef HAVE_LIBSSL
	if (retval != PAM_SUCCESS && config.ssl) SSL_CTX_free(config.ssl);
#endif
	PAM_FAIL_CHECK;

	/*
	 * If there's no client id specified, use the service type, to help
	 * keep track of which service is doing the authentication.
	 */
	if (!config.client_id) {
		retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) &config.client_id);
#ifdef HAVE_LIBSSL
		if (retval != PAM_SUCCESS && config.ssl) SSL_CTX_free(config.ssl);
#endif
		PAM_FAIL_CHECK;
	}

	/* now we've got a socket open, so we've got to clean it up on error */
#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { goto do_next; }

	/* build and initialize the RADIUS packet */
	request->code = PW_ACCESS_REQUEST;
	get_random_vector(request->vector);
	request->id = request->vector[0]; /* this should be evenly distributed */

	/* grab the password (if any) from the previous authentication layer */
	if (!config.force_prompt) {
		DPRINT(LOG_DEBUG, "ignore last_pass, force_prompt set");
		retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &old_password);
		PAM_FAIL_CHECK;
	}

	if (old_password) {
		password = strdup(old_password);
	}

	/* no previous password: maybe get one from the user */
	if (!password) {
		if (ctrl & PAM_USE_FIRST_PASS) {
			retval = PAM_AUTH_ERR;	/* use one pass only, stopping if it fails */
			goto do_next;
		}

		/* check to see if we send a NULL password the first time around */
		if (!(ctrl & PAM_SKIP_PASSWD)) {
			retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF, config.prompt, &password);
			PAM_FAIL_CHECK;

		} else {
			password = strdup("");
		}
	} /* end of password == NULL */

	build_radius_packet(request, user, password, &config);

	/* not all servers understand this service type, but some do */
	add_int_attribute(request, PW_USER_SERVICE_TYPE, PW_AUTHENTICATE_ONLY);

	/*
	 *	Tell the server which host the user is coming from.
	 *
	 *	Note that this is NOT the IP address of the machine running PAM!
	 *	It's the IP address of the client.
	 */
	retval = pam_get_item(pamh, PAM_RHOST, (CONST void **) &rhost);
	PAM_FAIL_CHECK;
	if (rhost) {
		add_attribute(request, PW_CALLING_STATION_ID, (const uint8_t *) rhost, strlen(rhost));
	}

	DPRINT(LOG_DEBUG, "Sending RADIUS request code %d (%s)", request->code, get_packet_name(request->code));

	retval = talk_radius(&config, request, response, password, config.retries + 1);
	PAM_FAIL_CHECK;

	DPRINT(LOG_DEBUG, "Got RADIUS response code %d (%s)", response->code, get_packet_name(response->code));

	/*
	 *	If we get an authentication failure, and we sent a NULL password,
	 *	ask the user for one and continue.
	 *
	 *	If we get an access challenge, then do a response, for as many
	 *	challenges as we receive.
	 */
	while (response->code == PW_ACCESS_CHALLENGE) {
		attribute_t *a_state, *a_reply, *a_prompt;
		char challenge[BUFFER_SIZE];
    	int prompt;       

		/* Now we do a bit more work: challenge the user, and get a response */
		if (((a_state = find_attribute(response, PW_STATE)) == NULL) ||
		    ((a_reply = find_attribute(response, PW_REPLY_MESSAGE)) == NULL)) {
			/* Actually, State isn't required. */
			_pam_log(LOG_ERR, "RADIUS Access-Challenge received with State or Reply-Message missing");
			retval = PAM_AUTHINFO_UNAVAIL;
			goto do_next;
		}

		/*
		 *	Security fixes.
		 */
		if ((a_state->length <= 2) || (a_reply->length <= 2)) {
			_pam_log(LOG_ERR, "RADIUS Access-Challenge received with invalid State or Reply-Message");
			retval = PAM_AUTHINFO_UNAVAIL;
			goto do_next;
		}

		memcpy(challenge, a_reply->data, a_reply->length - 2);
		challenge[a_reply->length - 2] = 0;

		/* It's full challenge-response, default to echo on, unless the server wants it off */
		prompt = PAM_PROMPT_ECHO_ON;
		if (config.prompt_attribute) {
			if((a_prompt = find_attribute(response, PW_PROMPT)) != NULL){
				uint32_t prompt_val_net = 0;
				uint32_t prompt_val = 0;

				memcpy((void *)&prompt_val_net, (void *) a_prompt->data, sizeof(uint32_t));
				prompt_val = ntohl(prompt_val_net);

				DPRINT(LOG_DEBUG, "Got Prompt=%d", prompt_val);
				if(!prompt_val) prompt = PAM_PROMPT_ECHO_OFF;
			}
		}

		retval = rad_converse(pamh, prompt, challenge, &resp2challenge);
		PAM_FAIL_CHECK;

		/* now that we've got a response, build a new radius packet */
		build_radius_packet(request, user, resp2challenge, &config);
		/* request->code is already PW_ACCESS_REQUEST */
		request->id++;		/* one up from the request */

		if (rhost) {
			add_attribute(request, PW_CALLING_STATION_ID, (const uint8_t *) rhost, strlen(rhost));
		}

		/* copy the state over from the servers response */
		add_attribute(request, PW_STATE, a_state->data, a_state->length - 2);

		retval = talk_radius(&config, request, response, resp2challenge, 1);
		PAM_FAIL_CHECK;

		DPRINT(LOG_DEBUG, "Got response to challenge code %d", response->code);

		/*
		 * max_challenge limits the # of challenges a server can issue
		 * It's a workaround for buggy servers
		 */
		if (config.max_challenge > 0 && response->code == PW_ACCESS_CHALLENGE) {
			num_challenge++;
			if (num_challenge >= config.max_challenge) {
				DPRINT(LOG_DEBUG, "maximum number of challenges (%d) reached, failing", num_challenge);
				break;
			}
		}
	}

	/* Whew! Done the password checks, look for an authentication acknowledge */
	if (response->code == PW_ACCESS_ACCEPT) {
		attribute_t *attr_fip, *attr_class;

		retval = PAM_SUCCESS;

		/* Read Management-Privilege-Level attribute from the response */
		/* RFC 5607:
		 *  The Management-Privilege-Level (136) Attribute indicates the integer-
		 *  valued privilege level to be assigned for management access for the
		 *  authenticated user.  Many NASes provide the notion of differentiated
		 *  management privilege levels denoted by an integer value.  The
		 *  specific access rights conferred by each value are implementation
		 *  dependent.  It MAY be used in both Access-Request and Access-Accept
		 *  packets.

		 *  The management access level indicated in this attribute, received in
		 *  an Access-Accept packet, MUST be applied to the session authorized by
		 *  the Access-Accept.  If the NAS supports this attribute, but the
		 *  privilege level is unknown, the NAS MUST treat the Access-Accept
		 *  packet as if it had been an Access-Reject.
		 */

		if(config.privilege_level) {
			char priv[21];
			attribute_t *a_mpl;
			int val;

			if ((a_mpl = find_attribute(response, PW_MANAGEMENT_PRIVILEGE_LEVEL)) == NULL) {
				_pam_log(LOG_ERR, "RADIUS Access-Accept received with Management-Privilege-Level missing");
				goto do_next;
			}

			if (a_mpl->length != 6) {
				_pam_log(LOG_ERR, "RADIUS Access-Accept received with invalid Management-Privilege-Level attribute");
				goto do_next;
			}

			val = ntohl(*((int *)a_mpl->data));
			sprintf(priv, "Privilege=%d", val);

			/* Save Management-Privilege-Level value in PAM environment variable 'Privilege' */
			retval = pam_putenv(pamh, priv);
			if(retval != PAM_SUCCESS) {
				_pam_log(LOG_ERR, "unable to set PAM environment variable : Privilege");
				goto do_next;
			}
		}

		if ((attr_fip = find_attribute(response, PW_FRAMED_ADDRESS))) {
			char frameip[100];
			struct in_addr ip_addr;

			memcpy(&ip_addr.s_addr, attr_fip->data, 4);

			snprintf(frameip, sizeof(frameip), "Framed-IP-Address=%s", inet_ntoa(ip_addr));
			retval = pam_putenv(pamh, frameip);
			if(retval != PAM_SUCCESS) {
				_pam_log(LOG_ERR, "unable to set PAM environment variable : Framed-IP-Address");
			}
			else {
				_pam_log(LOG_DEBUG, "Set PAM environment variable : %s", frameip);
			}
		}

		if ((attr_class = find_attribute(response, PW_CLASS))) {
			char *buf;

			if ((buf = malloc(attr_class->length - 1))) {
				buf[0] = attr_class->length - 2;
				memcpy(buf + 1, attr_class->data, attr_class->length - 1);

				if (pam_set_data(pamh, "pam_radius_auth_class", (void*)buf, _int_free) != PAM_SUCCESS) {
					_pam_log(LOG_ERR, "Could not save RADIUS Class: pam_set_data failed");
				}
			} else {
				_pam_log(LOG_ERR,"Could not save RADIUS Class: out of memory");
			}
		}

	} else {
		retval = PAM_AUTH_ERR;	/* authentication failure */
	}

do_next:
	/* If there was a password pass it to the next layer */
	if (password && *password) {
		pam_set_item(pamh, PAM_AUTHTOK, password);
	}

	DPRINT(LOG_DEBUG, "authentication %s", retval == PAM_SUCCESS ? "succeeded":"failed");

	close(config.sockfd);
	if (config.sockfd6 >= 0) close(config.sockfd6);
	
	cleanup(config.server);
#ifdef HAVE_LIBSSL
	if (config.ssl) 
		SSL_CTX_free(config.ssl);
#endif

	_pam_forget(password);
	_pam_forget(resp2challenge);
	{
		int *pret = malloc(sizeof(int));
		*pret = retval;
		pam_set_data(pamh, "rad_setcred_return", (void *) pret, _int_free);
	}
	return retval;
}

/*
 * Return a value matching the return value of pam_sm_authenticate, for
 * greatest compatibility.
 * (Always returning PAM_SUCCESS breaks other authentication modules;
 * always returning PAM_IGNORE breaks PAM when we're the only module.)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, UNUSED int flags, UNUSED int argc, UNUSED CONST char **argv)
{
	int retval = PAM_SUCCESS;
	const int *pret = &retval;

	pam_get_data(pamh, "rad_setcred_return", (CONST void **) &pret);

	return *pret;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return PAM_SESSION_ERR; }

static int pam_private_session(pam_handle_t *pamh, UNUSED int flags, int argc, CONST char **argv, int status)
{
	CONST char *user;
	CONST char *rhost;
	const unsigned char *class = NULL;
	int retval = PAM_AUTH_ERR;

	char recv_buffer[4096];
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
	radius_conf_t config;

	(void) _pam_parse(argc, argv, &config);

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something, and not too long, either */
	if ((user == NULL) || (strlen(user) > MAXPWNAM)) return PAM_USER_UNKNOWN;

	/*
	 * Get the IP address of the authentication server
	 * Then, open a socket, and bind it to a port
	 */
	retval = initialize(&config, TRUE);
#ifdef HAVE_LIBSSL
	if (retval != PAM_SUCCESS && config.ssl) SSL_CTX_free(config.ssl);
#endif
	PAM_FAIL_CHECK;

	/*
	 * If there's no client id specified, use the service type, to help
	 * keep track of which service is doing the authentication.
	 */
	if (!config.client_id) {
		retval = pam_get_item(pamh, PAM_SERVICE, (CONST void **) &config.client_id);
#ifdef HAVE_LIBSSL
		if (retval != PAM_SUCCESS && config.ssl) SSL_CTX_free(config.ssl);
#endif
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
	add_attribute(request, PW_ACCT_SESSION_ID, (uint8_t *) recv_buffer, strlen(recv_buffer));

	add_int_attribute(request, PW_ACCT_AUTHENTIC, PW_AUTH_RADIUS);

	if (pam_get_data(pamh, "pam_radius_auth_class", (const void**)&class) == PAM_SUCCESS) {
		add_attribute(request, PW_CLASS, class + 1, class[0]);
	}

	if (status == PW_STATUS_START) {
		time_t *session_time = malloc(sizeof(time_t));
		time(session_time);
		pam_set_data(pamh, "rad_session_time", (void *) session_time, _int_free);
	} else {
		const time_t *session_time = NULL;

		retval = pam_get_data(pamh, "rad_session_time", (CONST void **)&session_time);
		PAM_FAIL_CHECK;

		add_int_attribute(request, PW_ACCT_SESSION_TIME, time(NULL) - *session_time);
	}

	/*
	 *	Tell the server which host the user is coming from.
	 *
	 *	Note that this is NOT the IP address of the machine running PAM!
	 *	It's the IP address of the client.
	*/
	retval = pam_get_item(pamh, PAM_RHOST, (CONST void **) &rhost);
	PAM_FAIL_CHECK;
	if (rhost) {

		add_attribute(request, PW_CALLING_STATION_ID, (const uint8_t *) rhost, strlen(rhost));
	}

	retval = talk_radius(&config, request, response, NULL, 1);
	PAM_FAIL_CHECK;

	/* oops! They don't have the right password.	Complain and die. */
	if (response->code != PW_ACCOUNTING_RESPONSE) {
		retval = PAM_PERM_DENIED;
		goto error;
	}

	retval = PAM_SUCCESS;

error:

	close(config.sockfd);
	if (config.sockfd6 >= 0)
		close(config.sockfd6);
	cleanup(config.server);
#ifdef HAVE_LIBSSL
	if (config.ssl) 
		SSL_CTX_free(config.ssl);
#endif

	return retval;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, CONST char **argv)
{
	return pam_private_session(pamh, flags, argc, argv, PW_STATUS_START);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, CONST char **argv)
{
	return pam_private_session(pamh, flags, argc, argv, PW_STATUS_STOP);
}

#ifdef PAM_STATIC

/*
 *	Do nothing for account management. This is apparently needed by
 *	some programs.
 */
PAM_EXTERN int pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh, UNUSED int flags, UNUSED int argc, UNUSED CONST char **argv)
{
	return PAM_SUCCESS;
}

/* static module data */
struct pam_module _pam_radius_modstruct = {
	.name = "pam_radius_auth",
	.pam_sm_authenticate = pam_sm_authenticate,
	.pam_sm_setcred = pam_sm_setcred,
	.pam_sm_acct_mgmt = pam_sm_acct_mgmt,
	.pam_sm_open_session = pam_sm_open_session,
	.pam_sm_close_session = pam_sm_close_session,
	.pam_sm_chauthtok = pam_sm_chauthtok,
};
#endif
