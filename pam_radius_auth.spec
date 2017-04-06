%define name pam_radius_auth
%define version 1.4.1
%define release 0

Name: %{name}
Summary: PAM Module for RADIUS Authentication
Version: %{version}
Release: %{release}
Source: ftp://ftp.freeradius.org/pub/freeradius/pam_radius-%{version}.tar
URL: http://www.freeradius.org/pam_radius_auth/
Group: System Environment/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
License: BSD-like or GNU GPL
Requires: pam

%description
This is the PAM to RADIUS authentication module. It allows any PAM-capable
machine to become a RADIUS client for authentication and accounting
requests. You will need a RADIUS server to perform the actual
authentication.

%prep
%setup -q -n pam_radius-%{version}

%build
./configure
make

%install
mkdir -p %{buildroot}/lib/security
cp -p pam_radius_auth.so %{buildroot}/lib/security
mkdir -p %{buildroot}/etc/raddb
[ -f %{buildroot}/etc/raddb/server ] || cp -p pam_radius_auth.conf %{buildroot}/etc/raddb/server

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%postun
rmdir /etc/raddb || true

%files
%defattr(-,root,root,0755)
%doc README INSTALL USAGE Changelog
%config /etc/raddb/server
%config %attr(0600,root,root) /etc/raddb/server
/lib/security/pam_radius_auth.so

%changelog
* Mon Jun 03 2002 Richie Laager <rlaager@wiktel.com> 1.3.15-0
- Inital RPM Version
