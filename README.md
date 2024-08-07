# pam_radius

[![CI](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci.yml/badge.svg)](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci.yml)
[![CI RPM](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci-rpm.yml/badge.svg)](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci-rpm.yml)
[![CI DEB](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci-deb.yml/badge.svg)](https://github.com/FreeRADIUS/pam_radius/actions/workflows/ci-deb.yml)

This is the PAM to RADIUS authentication module.  It allows any Linux, OSX or
Solaris machine to become a RADIUS client for authentication.  You will need to
supply your own RADIUS server to perform the actual authentication.

The latest version has a simple merger of the original `pam_radius`
session accounting code which will work *only* on Linux.

See INSTALL for instructions on building and installing this module. It has
been successfully used for RADIUS authentication on CentOS, RHEL and Rocky
Linux versions 7 to 9, Debian, Ubuntu, many older Linux distributions such
as RedHat 5.x and RedHat 6.x, as well as Solaris 2.6 and OSX 10.9.1.

A number of options are supported by this module.  See USAGE for
more details.

Care should be taken when configuring RADIUS authentication.  Your
RADIUS server should have a minimal set of machines in its 'clients'
file.  The server should NOT be visible to the world at large, but
should be contained behind a firewall.  If your RADIUS server is
visible from the Internet, a number of attacks become possible.

Any additional questions can be directed to the FreeRADIUS user's
mailing list: https://www.freeradius.org/support/

For the latest version and updates, see the main web or ftp site:

- https://freeradius.org/pam_radius_auth/
- ftp://ftp.freeradius.org/pub/radius/

The `pam_radius_auth` module based on an old version of Cristian
Gafton's `pam_radius.c`, and on the RADIUS Apache module.

The source contains a full suite of RADIUS functions, instead of
using libpwdb.  It makes sense, because we want it to compile
out of the box on Linux and Solaris 2.6.

There are minimal restrictions on using the code, as set out in the
disclaimer and copyright notice in `pam_radius_auth.c`.

Building it is straightforward: use GNU make, and type `./configure`,
followed by `make`.  If you've got some other weird make, you'll
have to edit the Makefile to remove the GNU make directives.

Alan DeKok <aland@freeradius.org>

## Debugging

When building under clang and some later versions of GCC with `--enable-developer`, you can add the following flags:

- `--enable-address-sanitizer`, enables address sanitizer (detects use after
  free issues, and out of bounds accesses).

- `--enable-leak-sanitizer`, enables leak sanitizer (detects memory leaks).

## Packages

## RPM (RedHat, CentOS, Rocky Linux etc)

```
$ ./configure
$ make rpm
$ rpm -ivh rpmbuild/RPMS/x86_64/pam*.rpm
```

Configuration example for sshd+PAM in [redhat/pam_sshd_example](redhat/pam_sshd_example)

## DEB (Debian, Ubuntu etc)

```
$ ./configure
$ make deb
$ dpkg -i ../libpam-radius-auth_*.deb
```

Configuration example for sshd+PAM in [debian/pam_sshd_example](debian/pam_sshd_example)
