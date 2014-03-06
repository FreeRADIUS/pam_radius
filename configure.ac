dnl #############################################################
dnl #
dnl #  For information about autoconf, see:
dnl #
dnl #  http://www.gnu.org/software/autoconf/
dnl #
dnl #  The recommended order is:
dnl #
dnl #  AC_INIT(file)
dnl #  0. checks for compiler, libtool, and command line options
dnl #  1. checks for programs
dnl #  2. checks for libraries
dnl #  3. checks for header files
dnl #  4. checks for typedefs
dnl #  5. checks for structures and functions
dnl #  6. checks for compiler characteristics
dnl #  7. checks for library functions
dnl #  8. checks for system services
dnl #  AC_OUTPUT([file...])
dnl #
dnl #############################################################

AC_PREREQ([2.59])
export CFLAGS LIBS LDFLAGS CPPFLAGS

AC_INIT([pam_radius],[$]Id[$],[http://bugs.freeradius.org],,[http://www.freeradius.org])
AC_CONFIG_SRCDIR([src/pam_radius_auth.c])
AC_CONFIG_HEADER([src/config.h])
m4_include([m4/ax_cc.m4])

dnl #############################################################
dnl #
dnl #  Custom hackery to discover version at configure time
dnl #
dnl #############################################################

PAM_RADIUS_MAJOR_VERSION=`cat VERSION | sed 's/\..*//'`
PAM_RADIUS_MINOR_VERSION=`cat VERSION | sed 's/^[[^\.]]*\.//' | sed 's/\..*$//'`
PAM_RADIUS_INCRM_VERSION=`cat VERSION | sed 's/^.*\..*\.//' | sed 's/[[\.-]].*$//'`

PAM_RADIUS_VERSION=`echo | awk -v major="$PAM_RADIUS_MAJOR_VERSION" \
-v minor="$PAM_RADIUS_MINOR_VERSION" \
-v incrm="$PAM_RADIUS_INCRM_VERSION" \
'{ printf "%02i%02i%02i", major, minor, incrm }'`

dnl #
dnl #  Still useful for custom builds
dnl #
PAM_RADIUS_VERSION_STRING=`cat VERSION`

dnl #
dnl #  Add definitions to Make.inc as it's used by various build targets
dnl #
AC_SUBST([PAM_RADIUS_VERSION_STRING])

dnl #
dnl #  Add definitions to autoconf.h, so that the headers that we install
dnl #  contain the version number of the server.
dnl #
AC_DEFINE_UNQUOTED([PAM_RADIUS_VERSION], [${PAM_RADIUS_VERSION}], [Version integer in format <ma><ma><mi><mi><in><in>])
AC_DEFINE_UNQUOTED([PAM_RADIUS_VERSION_STRING], ["${PAM_RADIUS_VERSION_STRING}"], [Raw version string from VERSION file])

dnl #############################################################
dnl #
dnl #  0. Checks for compiler, libtool, and command line options.
dnl #
dnl #############################################################

dnl #
dnl #  Get system information
dnl #
AC_CANONICAL_SYSTEM

dnl #
dnl #  Check for GNU cc
dnl #
AC_PROG_CC
AC_PROG_CXX

dnl #
dnl #  check for AIX, to allow us to use some BSD functions
dnl #  must be before macros that call the compiler.
dnl #
AC_AIX

AC_PROG_GCC_TRADITIONAL
AC_PROG_CC_SUNPRO
AC_PROG_RANLIB

dnl #
dnl #  Definitive check for whether the compiler is clang
dnl #
AX_CC_IS_CLANG
if test "x$ax_cv_cc_clang" = "xyes"; then
  AC_SUBST(clang_path, "$CC")
else
  AC_SUBST(clang_path, "")
fi

dnl #
dnl #  Set Default CFLAGS for GCC compatible compilers
dnl #
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall -D_GNU_SOURCE"
fi

dnl #
dnl #  -Qunused-arguments means the compiler won't complain about unsupported arguments
dnl #
AX_CC_QUNUSED_ARGUMENTS_FLAG
if test "x$ax_cv_cc_qunused_arguments_flag" = "xyes"; then
  CFLAGS="$CFLAGS -Qunused-arguments"
  LDFLAGS="$LDFLAGS -Qunused-arguments"
fi

dnl #
dnl #  check for system bytesex
dnl #  AC_DEFINES WORDS_BIGENDIAN
dnl #
AC_C_BIGENDIAN

AC_ARG_ENABLE(werror,
[  --enable-werror         causes the build to fail if any warnings are generated.],
[ case "$enableval" in
    no)
      werror=no
    ;;
    *)
      werror=yes
  esac ]
)

dnl #############################################################
dnl #
dnl #  2. Checks for libraries
dnl #
dnl #############################################################

dnl #
dnl #  Check for -lresolv
dnl #  This library may be needed later.
dnl #
AC_CHECK_LIB(resolv, inet_aton)

dnl #
dnl #  Check if we need -lnsl. Usually if we want to
dnl #  link against -lsocket we need to include -lnsl as well.
dnl #
AC_CHECK_LIB(nsl, inet_ntoa)

dnl #############################################################
dnl #
dnl #  3. Checks for header files
dnl #
dnl #############################################################

AC_CHECK_HEADERS( \
	ctype.h \
	errno.h \
	fcntl.h \
	limits.h \
	malloc.h \
	netdb.h \
	netinet/in.h \
	stdarg.h \
	stdio.h \
	stdlib.h \
	string.h \
	sys/param.h \
	sys/resource.h \
	sys/socket.h \
	sys/stat.h \
	sys/time.h \
	sys/types.h \
	syslog.h \
	time.h \
	unistd.h \
	utmp.h
)

AC_CHECK_HEADERS(security/pam_appl.h pam/pam_appl.h)
AC_CHECK_HEADERS(security/pam_modules.h pam/pam_modules.h)
if test x"$ac_cv_header_security_pam_modules_h" != x"yes" -a x"$ac_cv_header_pam_modules_appl_h" != x"yes"; then
	AC_MSG_ERROR([pam_modules.h not found])
fi

dnl #
dnl #  FreeBSD requires sys/socket.h before net/if.h
dnl #
AC_CHECK_HEADERS(net/if.h, [], [],
  [
    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif
  ]
)

dnl #############################################################
dnl #
dnl #  4. Checks for typedefs
dnl #
dnl #############################################################

dnl #
dnl #  Ensure that these are defined
dnl #
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

dnl #
dnl #  Check for socklen_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_SYS_TYPES_H
    #  include <sys/types.h>
    #endif

    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif
  ],
  socklen_t, int, [socklen_t is generally 'int' on systems which don't use it]
)

dnl #
dnl #  Check for uint8_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint8_t, unsigned char, [uint8_t should be the canonical 'octet' for network traffic]
)

dnl #
dnl #  Check for uint16_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint16_t, unsigned short, [uint16_t should be the canonical '2 octets' for network traffic]
)

dnl #
dnl #  Check for uint32_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint32_t, unsigned int, [uint32_t should be the canonical 'network integer']
)

dnl #
dnl #  Check for uint64_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint64_t, unsigned long long, [uint64_t is required for larger counters]
)

dnl #############################################################
dnl #
dnl #  5. Checks for structures and functions
dnl #
dnl #############################################################
AC_CHECK_FUNCS( \
  snprintf \
  inet_aton \
  inet_pton \
  inet_ntop \
  strlcat \
  strlcpy
)

AC_CHECK_TYPE(struct in6_addr, AC_DEFINE(HAVE_STRUCT_IN6_ADDR, 1, [IPv6 address structure]), [],
  [
    #ifdef HAVE_NETINET_IN_H
    #  include <netinet/in.h>
    #endif
  ]
)

dnl #############################################################
dnl #
dnl #  6. Checks for compiler characteristics
dnl #
dnl #############################################################

dnl #
dnl #  Check for system bytesex
dnl #
AC_C_BIGENDIAN(
  [AC_DEFINE(AC_BIG_ENDIAN, 1, [Define if your processor stores words with the most significant byte first])],
  [AC_DEFINE(AC_LITTLE_ENDIAN, 1, [Define if your processor stores words with the least significant byte first])]
)

dnl #
dnl #  Ensure that these are defined
dnl #
AC_C_CONST

dnl #
dnl #  Tell the compiler to parse doxygen documentation and verify it against function and variable declarations
dnl #
AX_CC_WDOCUMENTATION_FLAG
if test "x$ax_cv_cc_wdocumentation_flag" = "xyes"; then
devflags="-Wdocumentation"
fi

dnl #
dnl #  May of been set outside of this configure script
dnl #
AC_MSG_CHECKING([if building with -DNDEBUG])
if echo "$CFLAGS" | grep '\-DNDEBUG' > /dev/null; then
  AC_MSG_RESULT([yes])
  AC_DEFINE([WITH_NDEBUG], [1], [define if pam_radius was built with -DNDEBUG])
else
  AC_MSG_RESULT([no])
fi

AC_SUBST(HOSTINFO, $host)

dnl #############################################################
dnl #
dnl #  Add -Werror last, so it doesn't interfere with autoconf's
dnl #  test programs.
dnl #
dnl #############################################################
if test "x$werror" == "xyes"; then
  CFLAGS="-Werror $CFLAGS"
fi
AC_SUBST(LIBS)
AC_OUTPUT()
