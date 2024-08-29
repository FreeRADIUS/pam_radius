######################################################################
#
#  A minimal 'Makefile', by Alan DeKok <aland@freeradius.org>
#
# $Id: Makefile,v 1.13 2007/03/26 04:22:11 fcusack Exp $
#
#############################################################################

#
#  We require Make.inc, UNLESS the target is "make deb" or "make rpm"
#
#  Since "make deb" re-runs configure... there's no point in
#  requiring the developer to run configure *before* making
#  the debian packages.
#
ifneq "$(MAKECMDGOALS)" "deb"
ifneq "$(MAKECMDGOALS)" "rpm"
$(if $(wildcard src/config.h),,$(error You must run './configure [options]' before doing 'make'))
$(if $(wildcard Make.inc),,$(error Missing 'Make.inc' Run './configure [options]' and retry))

include Make.inc
endif
endif

VERSION = $(shell cat VERSION)

######################################################################
#
# If we're really paranoid, use these flags
#CFLAGS = -Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Waggregate-return
#
#  If you're not using GCC, then you'll have to change the CFLAGS.
#
CFLAGS += -Wall

#
# On Irix, use this with MIPSPRo C Compiler, and don't forget to export CC=cc
# gcc on Irix does not work yet for pam_radius
# Also, use gmake instead of make
# Then copy pam_radius_auth.so to /usr/freeware/lib32/security (PAM dir)
# CFLAGS =

#LDFLAGS += -shared -Wl,--version-script=pamsymbols.ver
LDFLAGS += -shared

######################################################################
#
#  The default rule to build everything.
#
all: pam_radius_auth.so

######################################################################
#
#  Build the object file from the C source.
#
export CFLAGS LDFLAGS

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

BRANCH = $(shell git rev-parse --abbrev-ref HEAD)

pam_radius-$(VERSION).tar.gz: .git/HEAD
	git archive --format=tar --prefix=pam_radius-$(VERSION)/ $(BRANCH) | gzip > $@

pam_radius-$(VERSION).tar.bz2: .git/HEAD
	git archive --format=tar --prefix=pam_radius-$(VERSION)/ $(BRANCH) | bzip2 > $@

%.sig: %
	gpg --default-key packages@freeradius.org -b $<

.PHONY: dist
dist: pam_radius-$(VERSION).tar.gz pam_radius-$(VERSION).tar.bz2

dist-sign: pam_radius-$(VERSION).tar.gz.sig pam_radius-$(VERSION).tar.bz2.sig

######################################################################
#
#  Clean up everything
#
.PHONY: clean
clean:
	@rm -f *~ *.so *.o src/*.o src/*~

######################################################################
#
#  Install it
#
.PHONY: install
install: all
	install -Dm 0644 pam_radius_auth.so $(DESTDIR)/lib/security/pam_radius_auth.so
	install -Dm 0644 pam_radius_auth.conf $(DESTDIR)/etc/pam_radius_auth.conf

######################################################################
#
#	Build a debian package
#
debian/changelog: debian/changelog.in
	sed "s/@VERSION@/$(VERSION)/g" < $^ > $@

.PHONY: deb
deb: debian/changelog
	@if ! command -v fakeroot; then \
		if ! command -v apt-get; then \
		  echo "'make deb' only works on debian systems" ; \
		  exit 1; \
		fi ; \
		echo "Please run 'apt-get install build-essential fakeroot' "; \
		exit 1; \
	fi
	fakeroot debian/rules debian/control
	fakeroot dpkg-buildpackage -b -uc

#
#  Build an RPM package
#
.PHONY: rpm
rpmbuild/SOURCES/pam_radius-$(VERSION).tar.bz2: pam_radius-$(VERSION).tar.bz2
	@mkdir -p $(addprefix rpmbuild/,SOURCES SPECS BUILD RPMS SRPMS BUILDROOT)
	@for file in `awk '/^Source...:/ {print $$2}' redhat/pam_radius_auth.spec` ; do cp redhat/$$file rpmbuild/SOURCES/$$file ; done
	@cp $< $@

rpm: rpmbuild/SOURCES/pam_radius-$(VERSION).tar.bz2
	@if ! yum-builddep -q -C --assumeno --define "_version $(VERSION)" redhat/pam_radius_auth.spec 1> /dev/null 2>&1; then \
		echo "ERROR: Required dependencies not found, install them with: yum-builddep redhat/pam_radius_auth.spec"; \
		exit 1; \
	fi
	@QA_RPATHS=0x0003 rpmbuild --define "_version $(VERSION)" --define "_topdir `pwd`/rpmbuild" -bb redhat/pam_radius_auth.spec
