#
# @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
# Author: Jorge Pereira <jorge@networkradius.com>
#
%global debug_package %{nil}
%define name pam_radius_auth
%define version %{_version}
%define release 0

Name: %{name}
Summary: PAM Module for RADIUS Authentication
Version: %{version}
Release: %{release}
Source: ftp://ftp.freeradius.org/pub/freeradius/pam_radius-%{version}.tar.bz2
URL: http://www.freeradius.org/pam_radius_auth/
Group: System Environment/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
Requires: pam
BuildRequires: pam-devel
BuildRequires: gcc
License: GNU GPL
Packager: Network RADIUS SARL <info@networkradius.com>
Vendor: Network RADIUS SARL

# Disable shebang mangling script,
# which errors out on any file with versionless `python` in its shebang
# See: https://github.com/atom/atom/issues/21937
%undefine __brp_mangle_shebangs

%description
This is the PAM to RADIUS authentication module. It allows any PAM-capable
machine to become a RADIUS client for authentication and accounting
requests. You will need a RADIUS server to perform the actual
authentication.

%prep
%setup -q -n pam_radius-%{version}

%build
# Retain CFLAGS from the environment...
export CFLAGS="$CFLAGS -fpic"
export CXXFLAGS="$CFLAGS"

# Need to pass these explicitly for clang, else rpmbuilder bails when trying to extract debug info from
# the libraries.  Guessing GCC does this by default.  Why use clang over gcc? The version of clang
# which ships with RHEL 6 has basic C11 support, gcc doesn't.
export LDFLAGS="-Wl,--build-id"

%configure --disable-developer
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_lib}/security
install -m 0755 pam_radius_auth.so %{buildroot}/%{_lib}/security

# It contains the radius secret, which should not be in a "world readable" file.
mkdir -p %{buildroot}%{_sysconfdir}
install -m 0600 pam_radius_auth.conf %{buildroot}%{_sysconfdir}/pam_radius_auth.conf

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc README.md INSTALL USAGE LICENSE Changelog
%config(noreplace) %attr(0600, root, root) %{_sysconfdir}/pam_radius_auth.conf
%dir %attr(755,root,root) /%{_lib}/security/
/%{_lib}/security/pam_radius_auth.so

%changelog
* Thu Nov 4 2021 Network RADIUS SARL <info@networkradius.com> - %{_version}
- Initial Debian version.
