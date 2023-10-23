Name:           haproxy-spoe-auth
Version:        __PKG_VERSION__
Release:        1%{?dist}
Summary:        HAProxy SPOE authentication agent

License:        Apache 2.0
URL:            https://github.com/ErmakovDmitriy/haproxy-spoe-auth
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang systemd-rpm-macros
Requires:       systemd

%description
HAProxy SPOE agent which implements OpenID and LDAP authentication mechanisms
and allows extracting an authenticated user information to an HAProxy session
state.

%global debug_package %{nil}

%prep
%autosetup


%build
mkdir -p build/
cd ./cmd/haproxy-spoe-auth/
go build -v -ldflags=-linkmode=external -o ../../build/haproxy-spoe-auth

%install
rm -rf %{buildroot}

# Binary
install -p -D -m 755 build/haproxy-spoe-auth $RPM_BUILD_ROOT/%{_bindir}/%{name}

# Service
install -p -D -m 644 resources/systemd/haproxy-spoe-auth.service %{buildroot}/%{_unitdir}/%{name}.service

# Default config
install -p -D -m 640 resources/systemd/haproxy-spoe-auth %{buildroot}/%{_sysconfdir}/default/haproxy-spoe-auth
install -p -D -m 640 resources/configuration/config.yml %{buildroot}/%{_sysconfdir}/haproxy-spoe-auth/config.yml

%pre
# sysusers_create_package does not work on RedHat 7 and silently fails.
getent group %{name} || groupadd %{name}
getent passwd %{name} || useradd -g %{name} %{name}


%post
chgrp -R haproxy-spoe-auth %{_sysconfdir}/haproxy-spoe-auth/
%systemd_post haproxy-spoe-auth.service

%preun
%systemd_preun haproxy-spoe-auth.service

%postun
%systemd_postun_with_restart haproxy-spoe-auth.service

%files
%license LICENSE
%doc docs/
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) %{_sysconfdir}/default/haproxy-spoe-auth
%config(noreplace) %{_sysconfdir}/haproxy-spoe-auth/config.yml


%changelog
* Mon Oct 23 2023 Dmitrii Ermakov <dmitrii.ermakov@maxiv.lu.se>
- First RPM package version
