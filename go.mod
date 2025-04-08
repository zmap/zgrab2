module github.com/zmap/zgrab2

go 1.23.0

toolchain go1.23.5

require (
	github.com/hdm/jarm-go v0.0.7
	github.com/miekg/dns v1.1.65
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.21.1
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/sirupsen/logrus v1.9.3
	github.com/zmap/zcrypto v0.0.0-20250324021606-4f0ea0eaccac
	github.com/zmap/zdns/v2 v2.0.3
	github.com/zmap/zflags v1.4.0-beta.1.0.20200204220219-9d95409821b6
	golang.org/x/crypto v0.37.0
	golang.org/x/net v0.38.0
	golang.org/x/sys v0.32.0
	golang.org/x/text v0.24.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/miekg/dns => github.com/zmap/dns v1.1.65

require (
	github.com/asergeyev/nradix v0.0.0-20220715161825-e451993e425c // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/weppos/publicsuffix-go v0.40.3-0.20250311103038-7794c8c0723b // indirect
	github.com/zmap/go-dns-root-anchors v0.0.0-20241218192521-63aee68224b6 // indirect
	github.com/zmap/go-iptree v0.0.0-20210731043055-d4e632617837 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/tools v0.31.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)
