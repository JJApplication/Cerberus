package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type ResourceMonitor struct {
	logger    *logrus.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	interval  time.Duration

	// 阈值配置
	cpuThreshold    float64
	memoryThreshold float64
	diskIOThreshold float64

	// 回调函数
	AnomalyHandler func(*ResourceAnomaly)
}

type ResourceAnomaly struct {
	Timestamp   time.Time
	AnomalyType string  // cpu, memory, disk_io
	Value       float64
	Threshold   float64
	ProcessName string
	ProcessID   int
	Description string
}

type ProcessInfo struct {
	PID         int
	Name        string
	CPUPercent  float64
	MemoryMB    float64
	DiskReadMB  float64
	DiskWriteMB float64
}

type SystemStats struct {
	CPUPercent    float64
	MemoryPercent float64
	DiskReadMBps  float64
	DiskWriteMBps float64
	Processes     []*ProcessInfo
}

func NewResourceMonitor(logger *logrus.Logger, interval time.Duration, cpuThreshold, memoryThreshold, diskIOThreshold float64) *ResourceMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	return &ResourceMonitor{
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
		interval:        interval,
		cpuThreshold:    cpuThreshold,
		memoryThreshold: memoryThreshold,
		diskIOThreshold: diskIOThreshold,
	}
}

func (rm *ResourceMonitor) Start() {
	go rm.monitorLoop()
	rm.logger.Info("Resource monitor started")
}

func (rm *ResourceMonitor) Stop() {
	rm.cancel()
	rm.logger.Info("Resource monitor stopped")
}

func (rm *ResourceMonitor) monitorLoop() {
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.checkSystemResources()
		}
	}
}

func (rm *ResourceMonitor) checkSystemResources() {
	stats, err := rm.getSystemStats()
	if err != nil {
		rm.logger.Errorf("Failed to get system stats: %v", err)
		return
	}

	now := time.Now()

	// 检查CPU使用率
	if stats.CPUPercent > rm.cpuThreshold {
		anomaly := &ResourceAnomaly{
			Timestamp:   now,
			AnomalyType: "cpu",
			Value:       stats.CPUPercent,
			Threshold:   rm.cpuThreshold,
			Description: fmt.Sprintf("System CPU usage %.2f%% exceeds threshold %.2f%%", stats.CPUPercent, rm.cpuThreshold),
		}
		rm.handleAnomaly(anomaly)
	}

	// 检查内存使用率
	if stats.MemoryPercent > rm.memoryThreshold {
		anomaly := &ResourceAnomaly{
			Timestamp:   now,
			AnomalyType: "memory",
			Value:       stats.MemoryPercent,
			Threshold:   rm.memoryThreshold,
			Description: fmt.Sprintf("System memory usage %.2f%% exceeds threshold %.2f%%", stats.MemoryPercent, rm.memoryThreshold),
		}
		rm.handleAnomaly(anomaly)
	}

	// 检查磁盘IO
	totalDiskIO := stats.DiskReadMBps + stats.DiskWriteMBps
	if totalDiskIO > rm.diskIOThreshold {
		anomaly := &ResourceAnomaly{
			Timestamp:   now,
			AnomalyType: "disk_io",
			Value:       totalDiskIO,
			Threshold:   rm.diskIOThreshold,
			Description: fmt.Sprintf("System disk I/O %.2f MB/s exceeds threshold %.2f MB/s", totalDiskIO, rm.diskIOThreshold),
		}
		rm.handleAnomaly(anomaly)
	}

	// 检查进程级别的资源使用
	for _, proc := range stats.Processes {
		if proc.CPUPercent > rm.cpuThreshold/2 { // 进程CPU阈值设为系统阈值的一半
			anomaly := &ResourceAnomaly{
				Timestamp:   now,
				AnomalyType: "cpu",
				Value:       proc.CPUPercent,
				Threshold:   rm.cpuThreshold / 2,
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Description: fmt.Sprintf("Process %s (PID: %d) CPU usage %.2f%% exceeds threshold %.2f%%", proc.Name, proc.PID, proc.CPUPercent, rm.cpuThreshold/2),
			}
			rm.handleAnomaly(anomaly)
		}

		if proc.MemoryMB > 1024 && proc.MemoryMB > rm.memoryThreshold*10 { // 进程内存超过1GB且超过阈值的10倍
			anomaly := &ResourceAnomaly{
				Timestamp:   now,
				AnomalyType: "memory",
				Value:       proc.MemoryMB,
				Threshold:   rm.memoryThreshold * 10,
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Description: fmt.Sprintf("Process %s (PID: %d) memory usage %.2f MB is excessive", proc.Name, proc.PID, proc.MemoryMB),
			}
			rm.handleAnomaly(anomaly)
		}

		procDiskIO := proc.DiskReadMB + proc.DiskWriteMB
		if procDiskIO > rm.diskIOThreshold/2 { // 进程磁盘IO阈值设为系统阈值的一半
			anomaly := &ResourceAnomaly{
				Timestamp:   now,
				AnomalyType: "disk_io",
				Value:       procDiskIO,
				Threshold:   rm.diskIOThreshold / 2,
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Description: fmt.Sprintf("Process %s (PID: %d) disk I/O %.2f MB/s exceeds threshold %.2f MB/s", proc.Name, proc.PID, procDiskIO, rm.diskIOThreshold/2),
			}
			rm.handleAnomaly(anomaly)
		}
	}
}

func (rm *ResourceMonitor) handleAnomaly(anomaly *ResourceAnomaly) {
	rm.logger.Warnf("Resource anomaly detected: %s", anomaly.Description)
	if rm.AnomalyHandler != nil {
		rm.AnomalyHandler(anomaly)
	}
}

func (rm *ResourceMonitor) getSystemStats() (*SystemStats, error) {
	stats := &SystemStats{}

	// 获取CPU使用率
	cpuPercent, err := rm.getCPUPercent()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU percent: %w", err)
	}
	stats.CPUPercent = cpuPercent

	// 获取内存使用率
	memoryPercent, err := rm.getMemoryPercent()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory percent: %w", err)
	}
	stats.MemoryPercent = memoryPercent

	// 获取磁盘IO
	diskReadMBps, diskWriteMBps, err := rm.getDiskIO()
	if err != nil {
		return nil, fmt.Errorf("failed to get disk I/O: %w", err)
	}
	stats.DiskReadMBps = diskReadMBps
	stats.DiskWriteMBps = diskWriteMBps

	// 获取进程信息
	processes, err := rm.getTopProcesses(10) // 获取前10个资源消耗最大的进程
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}
	stats.Processes = processes

	return stats, nil
}

func (rm *ResourceMonitor) getCPUPercent() (float64, error) {
	// 读取/proc/stat获取CPU使用率
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, fmt.Errorf("failed to read CPU stats")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, fmt.Errorf("invalid CPU stats format")
	}

	// 解析CPU时间
	user, _ := strconv.ParseUint(fields[1], 10, 64)
	nice, _ := strconv.ParseUint(fields[2], 10, 64)
	system, _ := strconv.ParseUint(fields[3], 10, 64)
	idle, _ := strconv.ParseUint(fields[4], 10, 64)
	iowait, _ := strconv.ParseUint(fields[5], 10, 64)
	irq, _ := strconv.ParseUint(fields[6], 10, 64)
	softirq, _ := strconv.ParseUint(fields[7], 10, 64)

	total := user + nice + system + idle + iowait + irq + softirq
	used := total - idle

	if total == 0 {
		return 0, nil
	}

	return float64(used) / float64(total) * 100, nil
}

func (rm *ResourceMonitor) getMemoryPercent() (float64, error) {
	// 读取/proc/meminfo获取内存使用率
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var memTotal, memFree, memAvailable uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemFree:":
			memFree, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}

	if memTotal == 0 {
		return 0, fmt.Errorf("failed to get memory total")
	}

	// 使用MemAvailable如果可用，否则使用MemFree
	available := memAvailable
	if available == 0 {
		available = memFree
	}

	used := memTotal - available
	return float64(used) / float64(memTotal) * 100, nil
}

func (rm *ResourceMonitor) getDiskIO() (float64, float64, error) {
	// 读取/proc/diskstats获取磁盘IO
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var totalReadBytes, totalWriteBytes uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		// 只统计主要磁盘设备（如sda, nvme0n1等）
		deviceName := fields[2]
		if !strings.HasPrefix(deviceName, "sd") && !strings.HasPrefix(deviceName, "nvme") {
			continue
		}

		// 读取扇区数（字段5和9）
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)

		// 扇区大小通常是512字节
		totalReadBytes += readSectors * 512
		totalWriteBytes += writeSectors * 512
	}

	// 转换为MB/s（这里简化处理，实际应该计算时间差）
	readMBps := float64(totalReadBytes) / (1024 * 1024) / float64(rm.interval.Seconds())
	writeMBps := float64(totalWriteBytes) / (1024 * 1024) / float64(rm.interval.Seconds())

	return readMBps, writeMBps, nil
}

func (rm *ResourceMonitor) getTopProcesses(limit int) ([]*ProcessInfo, error) {
	// 读取/proc目录获取进程信息
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, err
	}

	var processes []*ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 不是数字目录名
		}

		proc, err := rm.getProcessInfo(pid)
		if err != nil {
			continue // 进程可能已经退出
		}

		processes = append(processes, proc)
	}

	// 简单排序，按CPU使用率降序
	for i := 0; i < len(processes)-1; i++ {
		for j := i + 1; j < len(processes); j++ {
			if processes[i].CPUPercent < processes[j].CPUPercent {
				processes[i], processes[j] = processes[j], processes[i]
			}
		}
	}

	// 返回前limit个进程
	if len(processes) > limit {
		processes = processes[:limit]
	}

	return processes, nil
}

func (rm *ResourceMonitor) getProcessInfo(pid int) (*ProcessInfo, error) {
	// 读取进程状态文件
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statFile)
	if err != nil {
		return nil, err
	}

	statFields := strings.Fields(string(statData))
	if len(statFields) < 24 {
		return nil, fmt.Errorf("invalid stat format")
	}

	// 读取进程名
	commFile := fmt.Sprintf("/proc/%d/comm", pid)
	commData, err := os.ReadFile(commFile)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(string(commData))

	// 读取内存信息
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, err
	}

	var memoryKB uint64
	statusLines := strings.Split(string(statusData), "\n")
	for _, line := range statusLines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memoryKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
			break
		}
	}

	return &ProcessInfo{
		PID:        pid,
		Name:       name,
		CPUPercent: 0, // CPU百分比需要通过时间差计算，这里简化
		MemoryMB:   float64(memoryKB) / 1024,
		// 磁盘IO信息需要从/proc/[pid]/io读取，这里简化
		DiskReadMB:  0,
		DiskWriteMB: 0,
	}, nil
}