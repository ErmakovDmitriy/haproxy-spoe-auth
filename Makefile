help:
	@echo "Supported commands:"
	@echo "build - builds a binary"
	@echo "build-no-cgo - builds a binary with CGO_ENABLED=0"
	@echo "build-install-systemd - installs a default configuration and a systemd unit"

build:
	go build -C cmd/haproxy-spoe-auth -o haproxy-spoe-auth

build-no-cgo:
	CGO_ENABLED=0 go build -C cmd/haproxy-spoe-auth -o haproxy-spoe-auth

copy-systemd-unit:
	cp resources/systemd/haproxy-spoe-auth.service /etc/systemd/system/haproxy-spoe-auth.service
	systemctl daemon-reload

create-user:
	getent passwd haproxy-spoe-auth || useradd haproxy-spoe-auth

copy-default-settings:
	# Default flags
	mkdir -p /etc/default/
	cp resources/systemd/haproxy-spoe-auth /etc/default/haproxy-spoe-auth
	chown root:root /etc/default/haproxy-spoe-auth
	chmod 644 /etc/default/haproxy-spoe-auth
	# Default configuration file
	mkdir -p /etc/haproxy-spoe-auth/
	cp resources/configuration/config.yml /etc/haproxy-spoe-auth/config.yml
	chown root:root /etc/haproxy-spoe-auth/config.yml
	chmod 644 /etc/haproxy-spoe-auth/config.yml

build-install-systemd: build create-user copy-default-settings copy-systemd-unit
	cp cmd/haproxy-spoe-auth/haproxy-spoe-auth /usr/bin/haproxy-spoe-auth
	chown haproxy-spoe-auth:haproxy-spoe-auth /usr/bin/haproxy-spoe-auth
	chmod 550 /usr/bin/haproxy-spoe-auth
