#ifndef MD5_H
#define MD5_H
#include "config.h"

/*
 *	Try and determine endianness of the target system.
 *
 *	Other projects seem to use endian.h and variants, but these are
 *	in non standard locations, and may mess up cross compiling.
 *
 *	Here at least the endianness can be set explicitly with
 *	-DLITTLE_ENDIAN or -DBIG_ENDIAN.
 */
#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#  if defined(__LITTLE_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
      defined(AC_LITTLE_ENDIAN)
#    define LITTLE_ENDIAN 1
#  elif defined(__BIG_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
      defined(AC_BIG_ENDIAN)
#    define BIG_ENDIAN 1
#  else
#    error Failed determining endianness of system
#  endif
#endif

/*
 *  Some operating systems MAY resolve the MD5* functions to
 *  secret functions in one of their libraries.  These OS supplied
 *  MD5 functions almost always blow up, and cause problems.
 *  To get around the issue, we re-define the MD5 function names
 *  so that we're sure that our module uses our tested and working
 *  MD5 functions.
 */
#define MD5Init       pra_MD5Init
#define MD5Update     pra_MD5Update
#define MD5Final      pra_MD5Final
#define MD5Transform  pra_MD5Transform

#include <inttypes.h>
#include <stdint.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *);
void MD5Update(struct MD5Context *, unsigned const char *, unsigned);
void MD5Final(unsigned char digest[16], struct MD5Context *);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

void hmac_md5(uint8_t digest[16], uint8_t const *text, size_t text_len,
	      uint8_t const *key, size_t key_len);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */

typedef struct MD5Context MD5_CTX;

#endif /* MD5_H */
