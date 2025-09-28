package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NetworkMonitor ../../ebpf/network_monitor.c

type NetworkEvent struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Bytes     uint64
	Timestamp time.Time
	URL       string
}

type SystemEvent struct {
	PID         uint32
	CPUUsage    uint32
	MemoryUsage uint64
	DiskIO      uint64
	Timestamp   time.Time
	Comm        string
}

type IPStats struct {
	ConnectionCount uint32
	BytesSent       uint64
	BytesReceived   uint64
	LastSeen        time.Time
}

type Monitor struct {
	objs          *NetworkMonitorObjects
	networkLink   link.Link
	networkReader *ringbuf.Reader
	systemReader  *ringbuf.Reader
	logger        *logrus.Logger
	ctx           context.Context
	cancel        context.CancelFunc

	// 事件处理回调
	NetworkEventHandler func(*NetworkEvent)
	SystemEventHandler  func(*SystemEvent)
}

func NewMonitor(logger *logrus.Logger) (*Monitor, error) {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 加载eBPF程序
	spec, err := LoadNetworkMonitor()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	objs := &NetworkMonitorObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load and assign eBPF objects: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Monitor{
		objs:   objs,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	return m, nil
}

func (m *Monitor) Start(interfaceName string) error {
	// 获取网络接口
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", interfaceName, err)
	}

	// 附加XDP程序到网络接口
	m.networkLink, err = link.AttachXDP(link.XDPOptions{
		Program:   m.objs.MonitorNetwork,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // 使用通用模式，兼容性更好
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// 创建ringbuf读取器
	m.networkReader, err = ringbuf.NewReader(m.objs.NetworkEvents)
	if err != nil {
		return fmt.Errorf("failed to create network events reader: %w", err)
	}

	m.systemReader, err = ringbuf.NewReader(m.objs.SystemEvents)
	if err != nil {
		return fmt.Errorf("failed to create system events reader: %w", err)
	}

	// 启动事件处理goroutines
	go m.handleNetworkEvents()
	go m.handleSystemEvents()

	m.logger.Infof("eBPF monitor started on interface %s", interfaceName)
	return nil
}

func (m *Monitor) Stop() error {
	m.cancel()

	if m.networkLink != nil {
		if err := m.networkLink.Close(); err != nil {
			m.logger.Errorf("Failed to close network link: %v", err)
		}
	}

	if m.networkReader != nil {
		if err := m.networkReader.Close(); err != nil {
			m.logger.Errorf("Failed to close network reader: %v", err)
		}
	}

	if m.systemReader != nil {
		if err := m.systemReader.Close(); err != nil {
			m.logger.Errorf("Failed to close system reader: %v", err)
		}
	}

	if m.objs != nil {
		m.objs.Close()
	}

	m.logger.Info("eBPF monitor stopped")
	return nil
}

func (m *Monitor) handleNetworkEvents() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			record, err := m.networkReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				m.logger.Errorf("Failed to read network event: %v", err)
				continue
			}

			event := m.parseNetworkEvent(record.RawSample)
			if event != nil && m.NetworkEventHandler != nil {
				m.NetworkEventHandler(event)
			}
		}
	}
}

func (m *Monitor) handleSystemEvents() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			record, err := m.systemReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				m.logger.Errorf("Failed to read system event: %v", err)
				continue
			}

			event := m.parseSystemEvent(record.RawSample)
			if event != nil && m.SystemEventHandler != nil {
				m.SystemEventHandler(event)
			}
		}
	}
}

func (m *Monitor) parseNetworkEvent(data []byte) *NetworkEvent {
	if len(data) < 32 { // 最小事件大小
		return nil
	}

	event := &NetworkEvent{}

	// 解析二进制数据
	srcIP := binary.LittleEndian.Uint32(data[0:4])
	dstIP := binary.LittleEndian.Uint32(data[4:8])
	event.SrcPort = binary.LittleEndian.Uint16(data[8:10])
	event.DstPort = binary.LittleEndian.Uint16(data[10:12])
	event.Protocol = data[12]
	event.Bytes = binary.LittleEndian.Uint64(data[16:24])
	timestamp := binary.LittleEndian.Uint64(data[24:32])

	// 转换IP地址
	event.SrcIP = make(net.IP, 4)
	binary.BigEndian.PutUint32(event.SrcIP, srcIP)
	event.DstIP = make(net.IP, 4)
	binary.BigEndian.PutUint32(event.DstIP, dstIP)

	// 转换时间戳
	event.Timestamp = time.Unix(0, int64(timestamp))

	// 解析URL（如果存在）
	if len(data) > 32 {
		urlBytes := data[32:]
		nullIndex := -1
		for i, b := range urlBytes {
			if b == 0 {
				nullIndex = i
				break
			}
		}
		if nullIndex > 0 {
			event.URL = string(urlBytes[:nullIndex])
		}
	}

	return event
}

func (m *Monitor) parseSystemEvent(data []byte) *SystemEvent {
	if len(data) < 32 { // 最小事件大小
		return nil
	}

	event := &SystemEvent{}

	// 解析二进制数据
	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.CPUUsage = binary.LittleEndian.Uint32(data[4:8])
	event.MemoryUsage = binary.LittleEndian.Uint64(data[8:16])
	event.DiskIO = binary.LittleEndian.Uint64(data[16:24])
	timestamp := binary.LittleEndian.Uint64(data[24:32])

	// 转换时间戳
	event.Timestamp = time.Unix(0, int64(timestamp))

	// 解析进程名
	if len(data) > 32 {
		commBytes := data[32:]
		nullIndex := -1
		for i, b := range commBytes {
			if b == 0 {
				nullIndex = i
				break
			}
		}
		if nullIndex > 0 {
			event.Comm = string(commBytes[:nullIndex])
		}
	}

	return event
}

// BanIP 封禁指定IP地址
func (m *Monitor) BanIP(ip net.IP) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported")
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)
	banValue := uint8(1)

	return m.objs.BannedIps.Update(unsafe.Pointer(&ipUint32), unsafe.Pointer(&banValue), ebpf.UpdateAny)
}

// UnbanIP 解封指定IP地址
func (m *Monitor) UnbanIP(ip net.IP) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("only IPv4 addresses are supported")
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)
	return m.objs.BannedIps.Delete(unsafe.Pointer(&ipUint32))
}

// GetIPStats 获取指定IP的统计信息
func (m *Monitor) GetIPStats(ip net.IP) (*IPStats, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 addresses are supported")
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)
	var stats struct {
		ConnectionCount uint32
		BytesSent       uint64
		BytesReceived   uint64
		LastSeen        uint64
	}

	err := m.objs.IpStatsMap.Lookup(unsafe.Pointer(&ipUint32), unsafe.Pointer(&stats))
	if err != nil {
		return nil, err
	}

	return &IPStats{
		ConnectionCount: stats.ConnectionCount,
		BytesSent:       stats.BytesSent,
		BytesReceived:   stats.BytesReceived,
		LastSeen:        time.Unix(0, int64(stats.LastSeen)),
	}, nil
}

// IsMaliciousURL 检查URL是否包含恶意模式
func IsMaliciousURL(url string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(url, pattern) {
			return true
		}
	}
	return false
}
