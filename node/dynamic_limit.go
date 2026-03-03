package node

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/conf"
)

var utc8Location = time.FixedZone("UTC+8", 8*3600)

type dynamicLimitRange struct {
	startMinute int
	endMinute   int
}

type dynamicLimitSample struct {
	at    time.Time
	bytes int64
}

type dynamicLimitRuntime struct {
	triggerWindow time.Duration
	triggerSpeed  float64
	limitSpeed    int
	limitDuration time.Duration
	whiteUserIDs  map[int]struct{}
	ranges        []dynamicLimitRange
	lastTotals    map[int]int64
	samples       map[int][]dynamicLimitSample
}

func newDynamicLimitRuntime(c *conf.Conf) (*dynamicLimitRuntime, error) {
	if c == nil || !c.DyLimitEnable {
		return nil, nil
	}
	ranges, err := parseDynamicLimitRanges(c.DyLimitDuration)
	if err != nil {
		return nil, err
	}
	white := map[int]struct{}{}
	for uid := range c.DyLimitWhiteUserIDs {
		white[uid] = struct{}{}
	}
	return &dynamicLimitRuntime{
		triggerWindow: time.Duration(c.DyLimitTriggerTime) * time.Second,
		triggerSpeed:  float64(c.DyLimitTriggerSpeed),
		limitSpeed:    c.DyLimitSpeed,
		limitDuration: time.Duration(c.DyLimitTime) * time.Second,
		whiteUserIDs:  white,
		ranges:        ranges,
		lastTotals:    map[int]int64{},
		samples:       map[int][]dynamicLimitSample{},
	}, nil
}

func (d *dynamicLimitRuntime) taskInterval() time.Duration {
	interval := d.triggerWindow / 6
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	return interval
}

func (d *dynamicLimitRuntime) taskTimeout() time.Duration {
	timeout := d.triggerWindow
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	return timeout
}

func (d *dynamicLimitRuntime) activeAt(now time.Time) bool {
	if len(d.ranges) == 0 {
		return true
	}
	localNow := now.In(utc8Location)
	minute := localNow.Hour()*60 + localNow.Minute()
	for _, r := range d.ranges {
		if minute >= r.startMinute && minute < r.endMinute {
			return true
		}
	}
	return false
}

func (d *dynamicLimitRuntime) collectTriggeredUsers(now time.Time, totals map[int]int64) []int {
	if totals == nil {
		totals = map[int]int64{}
	}
	if !d.activeAt(now) {
		d.samples = map[int][]dynamicLimitSample{}
		for uid, total := range totals {
			d.lastTotals[uid] = total
		}
		for uid := range d.lastTotals {
			if _, ok := totals[uid]; !ok {
				delete(d.lastTotals, uid)
			}
		}
		return nil
	}

	triggered := map[int]struct{}{}
	windowStart := now.Add(-d.triggerWindow)
	for uid, total := range totals {
		prev, exists := d.lastTotals[uid]
		d.lastTotals[uid] = total
		if !exists {
			continue
		}

		delta := total - prev
		if delta < 0 {
			// Counter was reset by traffic reporting; treat current total as current delta.
			delta = total
		}

		points := append(d.samples[uid], dynamicLimitSample{
			at:    now,
			bytes: delta,
		})
		start := 0
		for start < len(points) && points[start].at.Before(windowStart) {
			start++
		}
		if start > 0 {
			points = points[start:]
		}
		d.samples[uid] = points

		var bytesInWindow int64
		for _, p := range points {
			bytesInWindow += p.bytes
		}
		if bytesInWindow <= 0 {
			continue
		}
		if _, white := d.whiteUserIDs[uid]; white {
			continue
		}
		speedMbps := float64(bytesInWindow*8) / d.triggerWindow.Seconds() / 1000000
		if speedMbps >= d.triggerSpeed {
			triggered[uid] = struct{}{}
		}
	}

	for uid := range d.lastTotals {
		if _, ok := totals[uid]; ok {
			continue
		}
		delete(d.lastTotals, uid)
		delete(d.samples, uid)
	}

	result := make([]int, 0, len(triggered))
	for uid := range triggered {
		result = append(result, uid)
	}
	return result
}

func (c *Controller) dynamicSpeedLimitTask() error {
	if c.dynamicLimit == nil || c.server == nil || c.limiter == nil {
		return nil
	}

	totals, err := c.server.GetUserTrafficTotalMap(c.tag)
	if err != nil {
		return err
	}
	now := time.Now()
	triggered := c.dynamicLimit.collectTriggeredUsers(now, totals)
	if len(triggered) == 0 {
		return nil
	}

	expire := now.Add(c.dynamicLimit.limitDuration)
	updated := 0
	for _, uid := range triggered {
		if err := c.limiter.UpdateDynamicSpeedLimitByUID(uid, c.dynamicLimit.limitSpeed, expire); err == nil {
			updated++
		}
	}
	if updated > 0 {
		log.WithField("tag", c.tag).Debugf("Dynamic speed limit applied to %d users", updated)
	}
	return nil
}

func parseDynamicLimitRanges(raw string) ([]dynamicLimitRange, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	ranges := make([]dynamicLimitRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		period := strings.Split(part, "-")
		if len(period) != 2 {
			return nil, fmt.Errorf("invalid period %q", part)
		}
		startMinute, err := parseClockMinute(period[0], false)
		if err != nil {
			return nil, fmt.Errorf("invalid start time in %q: %w", part, err)
		}
		endMinute, err := parseClockMinute(period[1], true)
		if err != nil {
			return nil, fmt.Errorf("invalid end time in %q: %w", part, err)
		}
		if startMinute >= endMinute {
			return nil, fmt.Errorf("period %q crosses midnight or is empty", part)
		}
		ranges = append(ranges, dynamicLimitRange{
			startMinute: startMinute,
			endMinute:   endMinute,
		})
	}
	return ranges, nil
}

func parseClockMinute(raw string, allow24 bool) (int, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("time format should be HH:MM")
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid hour")
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid minute")
	}
	if allow24 && hour == 24 && minute == 0 {
		return 24 * 60, nil
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("time out of range")
	}
	return hour*60 + minute, nil
}
