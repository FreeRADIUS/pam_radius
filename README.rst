pam_radius
----------

|BuildStatus|_ 

This is the PAM to RADIUS authentication module.  It allows any
Linux, OSX or Solaris machine to become a RADIUS client for 
authentication and password change requests.  You will need to supply 
your own RADIUS server to perform the actual authentication.

The latest version has a simple merger of the original pam_radius
session accounting code which will work *only* on Linux.

See INSTALL for instructions on building and installing this module.
It has been successfully used it for RADIUS authentication on RedHat 4.2,
RedHat 5.x, RedHat 6.x, Solaris 2.6 and OSX 10.9.1.

A number of options are supported by this module.  See USAGE for
more details.

Care should be taken when configuring RADIUS authentication.  Your
RADIUS server should have a minimal set of machines in it's 'clients'
file.  The server should NOT be visible to the world at large, but
should be contained behind a firewall.  If your RADIUS server is
visible from the Internet, a number of attacks become possible.

Any additional questions can be directed to the FreeRADIUS user's
mailing list http://freeradius.org/list/users.html.

For the latest version and updates, see the main web or ftp site:
http://www.freeradius.org/
ftp://ftp.freeradius.org/pub/radius/

The pam_radius_auth module based on an old version of Cristian
Gafton's pam_radius.c, and on the RADIUS Apache module.

The source contains a full suite of RADIUS functions, instead of
using libpwdb.  It makes sense, because we want it to compile
out of the box on Linux and Solaris 2.6.

There are minimal restrictions on using the code, as set out in the
disclaimer and copyright notice in ``pam_radius_auth.c``.

Building it is straightforward: use GNU make, and type ``./configure``,
followed by ``make``.  If you've got some other weird make, you'll
have to edit the Makefile to remove the GNU make directives.

Alan DeKok <aland@freeradius.org>

.. |BuildStatus| image:: https://travis-ci.org/FreeRADIUS/pam_radius.png?branch=master
.. _BuildStatus: https://travis-ci.org/FreeRADIUS/pam_radius
