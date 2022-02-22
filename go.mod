module github.com/zmap/zgrab2

go 1.12

require (
	github.com/RumbleDiscovery/jarm-go v0.0.6
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/common v0.20.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/zmap/zcrypto v0.0.0-20220222153637-55904056ad9f
	github.com/zmap/zflags v1.4.0-beta.1.0.20200204220219-9d95409821b6
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007
	golang.org/x/text v0.3.6
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.4.0
)

// TODO: remove when done
// replace github.com/zmap/zcrypto => /home/dissoupov/code/censys/zcrypto
