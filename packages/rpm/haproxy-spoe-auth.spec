Name:           haproxy-spoe-auth
Version:        __PKG_VERSION__
Release:        1%{?dist}
Summary:        HAProxy SPOE authentication agent

License:        Apache 2.0
URL:            https://github.com/ErmakovDmitriy/haproxy-spoe-auth
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang
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
go build -C ./cmd/haproxy-spoe-auth/ -v -ldflags=-linkmode=external -o ../../build/haproxy-spoe-auth

%install
rm -rf %{buildroot}

# Binary
mkdir -p %{buildroot}/%{_bindir}
install -m 755 build/haproxy-spoe-auth $RPM_BUILD_ROOT/%{_bindir}/%{name}

# Service
mkdir -p %{buildroot}/%{_unitdir}/
install -m 644 resources/systemd/haproxy-spoe-auth.service %{buildroot}/%{_unitdir}/%{name}.service

# Default config
mkdir -p %{buildroot}/%{_sysconfdir}/default/
install -m 600 resources/systemd/haproxy-spoe-auth %{buildroot}/%{_sysconfdir}/default/haproxy-spoe-auth
mkdir -p %{buildroot}/%{_sysconfdir}/haproxy-spoe-auth/
install -m 600 resources/configuration/config.yml %{buildroot}/%{_sysconfdir}/haproxy-spoe-auth/config.yml


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
