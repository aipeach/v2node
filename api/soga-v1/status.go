package panel

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type sogaNodeStatusBody struct {
	CPU    float64            `json:"cpu"`
	Mem    sogaResourceStatus `json:"mem"`
	Swap   sogaResourceStatus `json:"swap"`
	Disk   sogaResourceStatus `json:"disk"`
	Uptime int64              `json:"uptime"`
}

type sogaResourceStatus struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

func (c *Client) ReportNodeStatus() error {
	if c == nil {
		return nil
	}
	cpuUsage := readLinuxCPUUsage(c)
	memTotal, memUsed, swapTotal, swapUsed := readLinuxMemInfo()
	diskTotal, diskUsed := readDiskUsage("/")
	uptime := readLinuxUptime()
	if uptime <= 0 {
		uptime = int64(time.Since(c.startedAt).Seconds())
		if uptime < 0 {
			uptime = 0
		}
	}

	body := sogaNodeStatusBody{
		CPU: cpuUsage,
		Mem: sogaResourceStatus{
			Total: memTotal,
			Used:  memUsed,
		},
		Swap: sogaResourceStatus{
			Total: swapTotal,
			Used:  swapUsed,
		},
		Disk: sogaResourceStatus{
			Total: diskTotal,
			Used:  diskUsed,
		},
		Uptime: uptime,
	}

	r, err := c.client.R().
		SetBody(body).
		ForceContentType("application/json").
		Post("api/v1/status")
	if err != nil {
		return err
	}
	return ensureSogaCodeOK("report node status", r)
}

func readLinuxCPUUsage(c *Client) float64 {
	if c == nil {
		return 0
	}
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0
		}
		total := uint64(0)
		values := make([]uint64, 0, len(fields)-1)
		for _, part := range fields[1:] {
			value, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return 0
			}
			values = append(values, value)
			total += value
		}
		idle := values[3]
		if len(values) > 4 {
			idle += values[4]
		}
		if !c.hasCPUStat {
			c.lastCPUTotal = total
			c.lastCPUIdle = idle
			c.hasCPUStat = true
			return 0
		}
		deltaTotal := total - c.lastCPUTotal
		deltaIdle := idle - c.lastCPUIdle
		c.lastCPUTotal = total
		c.lastCPUIdle = idle
		if deltaTotal == 0 {
			return 0
		}
		usage := float64(deltaTotal-deltaIdle) * 100 / float64(deltaTotal)
		if usage < 0 {
			return 0
		}
		return usage
	}
	return 0
}

func readLinuxMemInfo() (memTotal int64, memUsed int64, swapTotal int64, swapUsed int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer f.Close()

	values := map[string]int64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		values[key] = value * 1024
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, 0
	}

	memTotal = values["MemTotal"]
	memAvailable := values["MemAvailable"]
	if memAvailable == 0 {
		memAvailable = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	memUsed = memTotal - memAvailable
	if memUsed < 0 {
		memUsed = 0
	}

	swapTotal = values["SwapTotal"]
	swapFree := values["SwapFree"]
	swapUsed = swapTotal - swapFree
	if swapUsed < 0 {
		swapUsed = 0
	}
	return memTotal, memUsed, swapTotal, swapUsed
}

func readLinuxUptime() int64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 {
		return 0
	}
	return int64(value)
}

func readDiskUsage(path string) (total int64, used int64) {
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used = total - available
	if used < 0 {
		used = 0
	}
	return total, used
}
