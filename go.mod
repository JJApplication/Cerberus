module ebpf-monitor

go 1.21

require (
	github.com/cilium/ebpf v0.12.3
	github.com/mattn/go-sqlite3 v1.14.18
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
	github.com/BurntSushi/toml v1.3.2
	github.com/sirupsen/logrus v1.9.3
	github.com/shirou/gopsutil/v3 v3.23.10
	github.com/stretchr/testify v1.8.4
)
