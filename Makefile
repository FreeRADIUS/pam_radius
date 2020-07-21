######################################################################
#
#  A minimal 'Makefile', by Alan DeKok <aland@freeradius.org>
#
# $Id: Makefile,v 1.13 2007/03/26 04:22:11 fcusack Exp $
#
#############################################################################
VERSION=2.0.0

######################################################################
#
# If we're really paranoid, use these flags
#CFLAGS = -Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return
#
#  If you're not using GCC, then you'll have to change the CFLAGS.
#
CFLAGS += -Wall -fPIC

#
# On Irix, use this with MIPSPRo C Compiler, and don't forget to export CC=cc
# gcc on Irix does not work yet for pam_radius
# Also, use gmake instead of make
# Then copy pam_radius_auth.so to /usr/freeware/lib32/security (PAM dir)
# CFLAGS =

#LDFLAGS += -shared -Wl,--version-script=pamsymbols.ver
LDFLAGS += -shared

$(if $(wildcard src/config.h),,$(error You must run './configure [options]' before doing 'make'))

######################################################################
#
#  The default rule to build everything.
#
all: pam_radius_auth.so

######################################################################
#
#  Build the object file from the C source.
#
export CFLAGS

src/pam_radius_auth.o: src/pam_radius_auth.c src/pam_radius_auth.h
	@$(MAKE) -C src $(notdir $@)

src/md5.o: src/md5.c src/md5.h
	@$(MAKE) -C src $(notdir $@)

#
# This is what should work on Irix:
#pam_radius_auth.so: pam_radius_auth.o md5.o
#	ld -shared pam_radius_auth.o md5.o -L/usr/freeware/lib32 -lpam -lc -o pam_radius_auth.so


######################################################################
#
#  Build the shared library.
#
#  The -Bshareable flag *should* work on *most* operating systems.
#
#  On Solaris, you might try using '-G', instead.
#
#  On systems with a newer GCC, you will need to do:
#
#	gcc -shared pam_radius_auth.o md5.o -lpam -lc -o pam_radius_auth.so
#
pam_radius_auth.so: src/pam_radius_auth.o src/md5.o
	$(CC) $(LDFLAGS) $^ -lpam -o pam_radius_auth.so

######################################################################
#
#  Check a distribution out of the source tree, and make a tar file.
#
.PHONY: pam_radius-$(VERSION).tar.gz
pam_radius-$(VERSION).tar.gz:
	git archive --format=tar --prefix=pam_radius-$(VERSION)/ master | gzip > pam_radius-$(VERSION).tar.gz

%.sig: %
	gpg --default-key packages@freeradius.org -b $<


dist: pam_radius-$(VERSION).tar.gz pam_radius-$(VERSION).tar.gz.sig

######################################################################
#
#  Clean up everything
#
.PHONY: clean
clean:
	@rm -f *~ *.so *.o src/*.o src/*~
