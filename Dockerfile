FROM docker.io/library/golang:1.24-alpine3.22 as builder

WORKDIR /usr/app
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY . .
RUN go build -C cmd/haproxy-spoe-auth -o /usr/app/haproxy-spoe-auth

FROM docker.io/library/alpine:3.22
COPY --from=builder /usr/app/haproxy-spoe-auth /usr/local/bin/
USER 65535
CMD ["/usr/local/bin/haproxy-spoe-auth", "-c", "/etc/haproxy-spoe-auth/config.yml"]
