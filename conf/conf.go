package conf

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

type Conf struct {
	LogConfig               LogConfig               `mapstructure:"Log"`
	NodeConfigs             []NodeConfig            `mapstructure:"-"`
	PprofPort               int                     `mapstructure:"PprofPort"`
	SubmitAliveIPMinTraffic int                     `mapstructure:"submit_alive_ip_min_traffic"`
	SubmitTrafficMinTraffic int                     `mapstructure:"submit_traffic_min_traffic"`
	UserIPLimitCIDRPrefixV4 int                     `mapstructure:"user_ip_limit_cidr_prefix_v4"`
	UserIPLimitCIDRPrefixV6 int                     `mapstructure:"user_ip_limit_cidr_prefix_v6"`
	GlobalDeviceLimitConfig GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
	GeositeFile             string                  `mapstructure:"geosite_file"`
	GeoipFile               string                  `mapstructure:"geoip_file"`
	AuditWhiteListFile      string                  `mapstructure:"audit_white_list_file"`
	ForbiddenPorts          string                  `mapstructure:"forbidden_ports"`
	BanPrivateIP            bool                    `mapstructure:"ban_private_ip"`
	ForbiddenBitTorrent     bool                    `mapstructure:"forbidden_bit_torrent"`
	DyLimitEnable           bool                    `mapstructure:"dy_limit_enable"`
	DyLimitDuration         string                  `mapstructure:"dy_limit_duration"`
	DyLimitTriggerTime      int                     `mapstructure:"dy_limit_trigger_time"`
	DyLimitTriggerSpeed     int                     `mapstructure:"dy_limit_trigger_speed"`
	DyLimitSpeed            int                     `mapstructure:"dy_limit_speed"`
	DyLimitTime             int                     `mapstructure:"dy_limit_time"`
	DyLimitWhiteUserID      string                  `mapstructure:"dy_limit_white_user_id"`
	DyLimitWhiteUserIDs     map[int]struct{}        `mapstructure:"-"`
	DNS                     DNSConfig               `mapstructure:"DNS"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type DNSConfig struct {
	File string `mapstructure:"File"`
}

type GlobalDeviceLimitConfig struct {
	Enable                  bool   `mapstructure:"Enable"`
	EnableDynamicSpeedLimit bool   `mapstructure:"EnableDynamicSpeedLimit"`
	RedisNetwork            string `mapstructure:"RedisNetwork"`
	RedisAddr               string `mapstructure:"RedisAddr"`
	RedisUsername           string `mapstructure:"RedisUsername"`
	RedisPassword           string `mapstructure:"RedisPassword"`
	RedisDB                 int    `mapstructure:"RedisDB"`
	Timeout                 int    `mapstructure:"Timeout"`
	Expiry                  int    `mapstructure:"Expiry"`
}

type NodeConfig struct {
	APIHost             string `mapstructure:"ApiHost"`
	NodeID              int
	NodeType            string `mapstructure:"NodeType"`
	Key                 string `mapstructure:"ApiKey"`
	Timeout             int    `mapstructure:"Timeout"`
	ListenIP            string `mapstructure:"ListenIP"`
	CertFile            string `mapstructure:"CertFile"`
	KeyFile             string `mapstructure:"KeyFile"`
	AcceptProxyProtocol bool   `mapstructure:"acceptProxyProtocol"`
}

type nodeConfigSource struct {
	APIHost             string      `mapstructure:"ApiHost"`
	NodeID              interface{} `mapstructure:"NodeID"`
	NodeType            string      `mapstructure:"NodeType"`
	Key                 string      `mapstructure:"ApiKey"`
	Timeout             int         `mapstructure:"Timeout"`
	ListenIP            string      `mapstructure:"ListenIP"`
	CertFile            string      `mapstructure:"CertFile"`
	KeyFile             string      `mapstructure:"KeyFile"`
	AcceptProxyProtocol bool        `mapstructure:"acceptProxyProtocol"`
}

type fileConf struct {
	LogConfig               LogConfig               `mapstructure:"Log"`
	NodeSources             []nodeConfigSource      `mapstructure:"Nodes"`
	PprofPort               int                     `mapstructure:"PprofPort"`
	SubmitAliveIPMinTraffic int                     `mapstructure:"submit_alive_ip_min_traffic"`
	SubmitTrafficMinTraffic int                     `mapstructure:"submit_traffic_min_traffic"`
	UserIPLimitCIDRPrefixV4 int                     `mapstructure:"user_ip_limit_cidr_prefix_v4"`
	UserIPLimitCIDRPrefixV6 int                     `mapstructure:"user_ip_limit_cidr_prefix_v6"`
	GlobalDeviceLimitConfig GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
	GeositeFile             string                  `mapstructure:"geosite_file"`
	GeoipFile               string                  `mapstructure:"geoip_file"`
	AuditWhiteListFile      string                  `mapstructure:"audit_white_list_file"`
	ForbiddenPorts          string                  `mapstructure:"forbidden_ports"`
	BanPrivateIP            bool                    `mapstructure:"ban_private_ip"`
	ForbiddenBitTorrent     bool                    `mapstructure:"forbidden_bit_torrent"`
	DyLimitEnable           bool                    `mapstructure:"dy_limit_enable"`
	DyLimitDuration         string                  `mapstructure:"dy_limit_duration"`
	DyLimitTriggerTime      int                     `mapstructure:"dy_limit_trigger_time"`
	DyLimitTriggerSpeed     int                     `mapstructure:"dy_limit_trigger_speed"`
	DyLimitSpeed            int                     `mapstructure:"dy_limit_speed"`
	DyLimitTime             int                     `mapstructure:"dy_limit_time"`
	DyLimitWhiteUserID      string                  `mapstructure:"dy_limit_white_user_id"`
	DNS                     DNSConfig               `mapstructure:"DNS"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
		SubmitAliveIPMinTraffic: -1,
		SubmitTrafficMinTraffic: -1,
		UserIPLimitCIDRPrefixV4: 32,
		UserIPLimitCIDRPrefixV6: 128,
		GlobalDeviceLimitConfig: GlobalDeviceLimitConfig{
			Enable:                  false,
			EnableDynamicSpeedLimit: false,
			RedisNetwork:            "tcp",
			RedisAddr:               "127.0.0.1:6379",
			RedisDB:                 0,
			Timeout:                 5,
			Expiry:                  60,
		},
		GeositeFile:         "/etc/v2node/geosite.dat",
		GeoipFile:           "/etc/v2node/geoip.dat",
		AuditWhiteListFile:  "/etc/v2node/whiteList",
		ForbiddenPorts:      "",
		BanPrivateIP:        false,
		ForbiddenBitTorrent: true,
		DyLimitEnable:       false,
		DyLimitTriggerTime:  60,
		DyLimitTriggerSpeed: 100,
		DyLimitSpeed:        30,
		DyLimitTime:         600,
		DyLimitWhiteUserIDs: map[int]struct{}{},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	loaded := fileConf{
		LogConfig:               p.LogConfig,
		SubmitAliveIPMinTraffic: p.SubmitAliveIPMinTraffic,
		SubmitTrafficMinTraffic: p.SubmitTrafficMinTraffic,
		UserIPLimitCIDRPrefixV4: p.UserIPLimitCIDRPrefixV4,
		UserIPLimitCIDRPrefixV6: p.UserIPLimitCIDRPrefixV6,
		GlobalDeviceLimitConfig: p.GlobalDeviceLimitConfig,
		GeositeFile:             p.GeositeFile,
		GeoipFile:               p.GeoipFile,
		AuditWhiteListFile:      p.AuditWhiteListFile,
		ForbiddenPorts:          p.ForbiddenPorts,
		BanPrivateIP:            p.BanPrivateIP,
		ForbiddenBitTorrent:     p.ForbiddenBitTorrent,
		DyLimitEnable:           p.DyLimitEnable,
		DyLimitDuration:         p.DyLimitDuration,
		DyLimitTriggerTime:      p.DyLimitTriggerTime,
		DyLimitTriggerSpeed:     p.DyLimitTriggerSpeed,
		DyLimitSpeed:            p.DyLimitSpeed,
		DyLimitTime:             p.DyLimitTime,
		DyLimitWhiteUserID:      p.DyLimitWhiteUserID,
	}
	if err := v.Unmarshal(&loaded); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	nodeConfigs, err := expandNodeConfigs(loaded.NodeSources)
	if err != nil {
		return err
	}
	p.LogConfig = loaded.LogConfig
	p.NodeConfigs = nodeConfigs
	p.PprofPort = loaded.PprofPort
	p.SubmitAliveIPMinTraffic = loaded.SubmitAliveIPMinTraffic
	p.SubmitTrafficMinTraffic = loaded.SubmitTrafficMinTraffic
	p.UserIPLimitCIDRPrefixV4 = loaded.UserIPLimitCIDRPrefixV4
	p.UserIPLimitCIDRPrefixV6 = loaded.UserIPLimitCIDRPrefixV6
	p.GlobalDeviceLimitConfig = loaded.GlobalDeviceLimitConfig
	p.GeositeFile = strings.TrimSpace(loaded.GeositeFile)
	p.GeoipFile = strings.TrimSpace(loaded.GeoipFile)
	p.AuditWhiteListFile = strings.TrimSpace(loaded.AuditWhiteListFile)
	p.ForbiddenPorts = strings.TrimSpace(loaded.ForbiddenPorts)
	p.BanPrivateIP = loaded.BanPrivateIP
	p.ForbiddenBitTorrent = loaded.ForbiddenBitTorrent
	p.GlobalDeviceLimitConfig.RedisNetwork = strings.ToLower(strings.TrimSpace(p.GlobalDeviceLimitConfig.RedisNetwork))
	if p.GlobalDeviceLimitConfig.RedisNetwork == "" {
		p.GlobalDeviceLimitConfig.RedisNetwork = "tcp"
	}
	p.GlobalDeviceLimitConfig.RedisAddr = strings.TrimSpace(p.GlobalDeviceLimitConfig.RedisAddr)
	p.GlobalDeviceLimitConfig.RedisUsername = strings.TrimSpace(p.GlobalDeviceLimitConfig.RedisUsername)
	if p.GlobalDeviceLimitConfig.RedisDB < 0 {
		p.GlobalDeviceLimitConfig.RedisDB = 0
	}
	if p.GlobalDeviceLimitConfig.Timeout <= 0 {
		p.GlobalDeviceLimitConfig.Timeout = 5
	}
	if p.GlobalDeviceLimitConfig.Expiry <= 0 {
		p.GlobalDeviceLimitConfig.Expiry = 60
	}
	p.DyLimitEnable = loaded.DyLimitEnable
	p.DyLimitDuration = loaded.DyLimitDuration
	p.DyLimitTriggerTime = loaded.DyLimitTriggerTime
	p.DyLimitTriggerSpeed = loaded.DyLimitTriggerSpeed
	p.DyLimitSpeed = loaded.DyLimitSpeed
	p.DyLimitTime = loaded.DyLimitTime
	p.DyLimitWhiteUserID = loaded.DyLimitWhiteUserID
	p.DNS = loaded.DNS
	if p.DNS.File != "" && !filepath.IsAbs(p.DNS.File) {
		p.DNS.File = filepath.Join(filepath.Dir(filePath), p.DNS.File)
	}
	if p.GeositeFile != "" && !filepath.IsAbs(p.GeositeFile) {
		p.GeositeFile = filepath.Join(filepath.Dir(filePath), p.GeositeFile)
	}
	if p.GeoipFile != "" && !filepath.IsAbs(p.GeoipFile) {
		p.GeoipFile = filepath.Join(filepath.Dir(filePath), p.GeoipFile)
	}
	if p.AuditWhiteListFile != "" && !filepath.IsAbs(p.AuditWhiteListFile) {
		p.AuditWhiteListFile = filepath.Join(filepath.Dir(filePath), p.AuditWhiteListFile)
	}
	p.UserIPLimitCIDRPrefixV4 = clamp(p.UserIPLimitCIDRPrefixV4, 0, 32)
	p.UserIPLimitCIDRPrefixV6 = clamp(p.UserIPLimitCIDRPrefixV6, 0, 128)
	if p.DyLimitTriggerTime <= 0 {
		p.DyLimitTriggerTime = 60
	}
	if p.DyLimitTriggerSpeed <= 0 {
		p.DyLimitTriggerSpeed = 100
	}
	if p.DyLimitSpeed <= 0 {
		p.DyLimitSpeed = 30
	}
	if p.DyLimitTime <= 0 {
		p.DyLimitTime = 600
	}
	whiteIDs, err := parseUserIDSet(p.DyLimitWhiteUserID)
	if err != nil {
		return fmt.Errorf("invalid dy_limit_white_user_id: %w", err)
	}
	p.DyLimitWhiteUserIDs = whiteIDs
	return nil
}

func expandNodeConfigs(sources []nodeConfigSource) ([]NodeConfig, error) {
	out := make([]NodeConfig, 0, len(sources))
	for i, source := range sources {
		nodeIDs, err := parseNodeIDs(source.NodeID)
		if err != nil {
			return nil, fmt.Errorf("invalid Nodes[%d].NodeID: %w", i, err)
		}
		if len(nodeIDs) == 0 {
			return nil, fmt.Errorf("invalid Nodes[%d].NodeID: empty", i)
		}
		for _, nodeID := range nodeIDs {
			if nodeID <= 0 {
				return nil, fmt.Errorf("invalid Nodes[%d].NodeID: node id must be > 0", i)
			}
			nodeType := strings.TrimSpace(source.NodeType)
			if nodeType == "" {
				nodeType = "vmess"
			}
			out = append(out, NodeConfig{
				APIHost:             source.APIHost,
				NodeID:              nodeID,
				NodeType:            strings.ToLower(nodeType),
				Key:                 source.Key,
				Timeout:             source.Timeout,
				ListenIP:            source.ListenIP,
				CertFile:            source.CertFile,
				KeyFile:             source.KeyFile,
				AcceptProxyProtocol: source.AcceptProxyProtocol,
			})
		}
	}
	return out, nil
}

func parseNodeIDs(raw interface{}) ([]int, error) {
	switch v := raw.(type) {
	case nil:
		return nil, fmt.Errorf("missing")
	case int:
		return []int{v}, nil
	case int8:
		return []int{int(v)}, nil
	case int16:
		return []int{int(v)}, nil
	case int32:
		return []int{int(v)}, nil
	case int64:
		return []int{int(v)}, nil
	case uint:
		return []int{int(v)}, nil
	case uint8:
		return []int{int(v)}, nil
	case uint16:
		return []int{int(v)}, nil
	case uint32:
		return []int{int(v)}, nil
	case uint64:
		return []int{int(v)}, nil
	case float64:
		if v != math.Trunc(v) {
			return nil, fmt.Errorf("non-integer value %v", v)
		}
		return []int{int(v)}, nil
	case float32:
		if float64(v) != math.Trunc(float64(v)) {
			return nil, fmt.Errorf("non-integer value %v", v)
		}
		return []int{int(v)}, nil
	case []interface{}:
		out := make([]int, 0, len(v))
		for _, item := range v {
			ids, err := parseNodeIDs(item)
			if err != nil {
				return nil, err
			}
			out = append(out, ids...)
		}
		return out, nil
	case []int:
		return append([]int(nil), v...), nil
	case []int64:
		out := make([]int, 0, len(v))
		for _, item := range v {
			out = append(out, int(item))
		}
		return out, nil
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("empty")
		}
		var ids []int
		for _, piece := range strings.Split(v, ",") {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			id, err := strconv.Atoi(piece)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", piece)
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("empty")
		}
		return ids, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", raw)
	}
}

func clamp(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func parseUserIDSet(raw string) (map[int]struct{}, error) {
	result := map[int]struct{}{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return result, nil
	}
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		id, err := strconv.Atoi(token)
		if err != nil {
			return nil, fmt.Errorf("invalid user id %q", token)
		}
		if id <= 0 {
			return nil, fmt.Errorf("user id must be > 0, got %d", id)
		}
		result[id] = struct{}{}
	}
	return result, nil
}
