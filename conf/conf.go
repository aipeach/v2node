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
	GlobalCertConfig        *CertConfig             `mapstructure:"GlobalCertConfig"`
	GlobalCertFile          string                  `mapstructure:"GlobalCertFile"`
	GlobalKeyFile           string                  `mapstructure:"GlobalKeyFile"`
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
	IPUserCacheTime         int                     `mapstructure:"ip_user_cache_time"`
	IPUserCacheSaveEnable   bool                    `mapstructure:"ip_user_cache_save_enable"`
	IPUserCacheSaveDir      string                  `mapstructure:"ip_user_cache_save_dir"`
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

type CertConfig struct {
	CertMode         string            `mapstructure:"CertMode"`
	CertDomain       string            `mapstructure:"CertDomain"`
	CertFile         string            `mapstructure:"CertFile"`
	KeyFile          string            `mapstructure:"KeyFile"`
	KeyType          string            `mapstructure:"KeyType"`
	Provider         string            `mapstructure:"Provider"`
	Email            string            `mapstructure:"Email"`
	DNSEnv           map[string]string `mapstructure:"DNSEnv"`
	RejectUnknownSni bool              `mapstructure:"RejectUnknownSni"`
}

type NodeConfig struct {
	APIHost             string `mapstructure:"ApiHost"`
	NodeID              int
	NodeType            string `mapstructure:"NodeType"`
	Key                 string `mapstructure:"ApiKey"`
	Timeout             int    `mapstructure:"Timeout"`
	ListenIP            string `mapstructure:"ListenIP"`
	MUSuffix            string `mapstructure:"mu_suffix"`
	MURegex             string `mapstructure:"mu_regex"`
	SSObfsUDP           bool   `mapstructure:"ss_obfs_udp"`
	CertConfig          *CertConfig
	GlobalCertConfig    *CertConfig
	CertFile            string `mapstructure:"CertFile"` // 兼容旧配置
	KeyFile             string `mapstructure:"KeyFile"`  // 兼容旧配置
	AcceptProxyProtocol bool   `mapstructure:"acceptProxyProtocol"`
}

type nodeConfigSource struct {
	APIHost             string      `mapstructure:"ApiHost"`
	NodeID              interface{} `mapstructure:"NodeID"`
	NodeType            string      `mapstructure:"NodeType"`
	Key                 string      `mapstructure:"ApiKey"`
	Timeout             int         `mapstructure:"Timeout"`
	ListenIP            string      `mapstructure:"ListenIP"`
	MUSuffix            string      `mapstructure:"mu_suffix"`
	MURegex             string      `mapstructure:"mu_regex"`
	SSObfsUDP           bool        `mapstructure:"ss_obfs_udp"`
	CertConfig          *CertConfig `mapstructure:"CertConfig"`
	CertFile            string      `mapstructure:"CertFile"`
	KeyFile             string      `mapstructure:"KeyFile"`
	AcceptProxyProtocol bool        `mapstructure:"acceptProxyProtocol"`
}

type fileConf struct {
	LogConfig               LogConfig               `mapstructure:"Log"`
	NodeSources             []nodeConfigSource      `mapstructure:"Nodes"`
	GlobalCertConfig        *CertConfig             `mapstructure:"GlobalCertConfig"`
	GlobalCertFile          string                  `mapstructure:"GlobalCertFile"`
	GlobalKeyFile           string                  `mapstructure:"GlobalKeyFile"`
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
	IPUserCacheTime         int                     `mapstructure:"ip_user_cache_time"`
	IPUserCacheSaveEnable   bool                    `mapstructure:"ip_user_cache_save_enable"`
	IPUserCacheSaveDir      string                  `mapstructure:"ip_user_cache_save_dir"`
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
		GeositeFile:           "/etc/v2node/geosite.dat",
		GeoipFile:             "/etc/v2node/geoip.dat",
		AuditWhiteListFile:    "/etc/v2node/whiteList",
		ForbiddenPorts:        "",
		BanPrivateIP:          false,
		ForbiddenBitTorrent:   true,
		DyLimitEnable:         false,
		DyLimitTriggerTime:    60,
		DyLimitTriggerSpeed:   100,
		DyLimitSpeed:          30,
		DyLimitTime:           600,
		DyLimitWhiteUserIDs:   map[int]struct{}{},
		IPUserCacheTime:       24,
		IPUserCacheSaveEnable: true,
		IPUserCacheSaveDir:    "/etc/v2node",
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
		GlobalCertConfig:        p.GlobalCertConfig,
		GlobalCertFile:          p.GlobalCertFile,
		GlobalKeyFile:           p.GlobalKeyFile,
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
		IPUserCacheTime:         p.IPUserCacheTime,
		IPUserCacheSaveEnable:   p.IPUserCacheSaveEnable,
		IPUserCacheSaveDir:      p.IPUserCacheSaveDir,
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
	p.IPUserCacheTime = loaded.IPUserCacheTime
	p.IPUserCacheSaveEnable = loaded.IPUserCacheSaveEnable
	p.IPUserCacheSaveDir = strings.TrimSpace(loaded.IPUserCacheSaveDir)
	p.GlobalCertFile = strings.TrimSpace(loaded.GlobalCertFile)
	p.GlobalKeyFile = strings.TrimSpace(loaded.GlobalKeyFile)
	p.DNS = loaded.DNS
	configDir := filepath.Dir(filePath)
	globalCertConfig := cloneCertConfig(loaded.GlobalCertConfig)
	if globalCertConfig == nil && (p.GlobalCertFile != "" || p.GlobalKeyFile != "") {
		globalCertConfig = &CertConfig{
			CertMode: "file",
			CertFile: p.GlobalCertFile,
			KeyFile:  p.GlobalKeyFile,
		}
	}
	globalCertConfig = normalizeCertConfig(globalCertConfig, configDir)
	p.GlobalCertConfig = globalCertConfig
	for i := range p.NodeConfigs {
		normalizeNodeCertConfig(&p.NodeConfigs[i], configDir)
		p.NodeConfigs[i].GlobalCertConfig = cloneCertConfig(globalCertConfig)
	}
	if p.DNS.File != "" && !filepath.IsAbs(p.DNS.File) {
		p.DNS.File = filepath.Join(configDir, p.DNS.File)
	}
	if p.GeositeFile != "" && !filepath.IsAbs(p.GeositeFile) {
		p.GeositeFile = filepath.Join(configDir, p.GeositeFile)
	}
	if p.GeoipFile != "" && !filepath.IsAbs(p.GeoipFile) {
		p.GeoipFile = filepath.Join(configDir, p.GeoipFile)
	}
	if p.AuditWhiteListFile != "" && !filepath.IsAbs(p.AuditWhiteListFile) {
		p.AuditWhiteListFile = filepath.Join(configDir, p.AuditWhiteListFile)
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
	if p.IPUserCacheTime <= 0 {
		p.IPUserCacheTime = 24
	}
	if p.IPUserCacheSaveDir == "" {
		p.IPUserCacheSaveDir = "/etc/v2node"
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
			certConfig := cloneCertConfig(source.CertConfig)
			if certConfig == nil && (strings.TrimSpace(source.CertFile) != "" || strings.TrimSpace(source.KeyFile) != "") {
				certConfig = &CertConfig{
					CertMode: "file",
					CertFile: source.CertFile,
					KeyFile:  source.KeyFile,
				}
			}
			if certConfig != nil {
				certConfig = normalizeCertConfig(certConfig, "")
			}
			certFile := strings.TrimSpace(source.CertFile)
			keyFile := strings.TrimSpace(source.KeyFile)
			if certConfig != nil {
				if certConfig.CertFile != "" {
					certFile = certConfig.CertFile
				}
				if certConfig.KeyFile != "" {
					keyFile = certConfig.KeyFile
				}
			}
			out = append(out, NodeConfig{
				APIHost:             source.APIHost,
				NodeID:              nodeID,
				NodeType:            strings.ToLower(nodeType),
				Key:                 source.Key,
				Timeout:             source.Timeout,
				ListenIP:            source.ListenIP,
				MUSuffix:            source.MUSuffix,
				MURegex:             source.MURegex,
				SSObfsUDP:           source.SSObfsUDP,
				CertConfig:          certConfig,
				CertFile:            certFile,
				KeyFile:             keyFile,
				AcceptProxyProtocol: source.AcceptProxyProtocol,
			})
		}
	}
	return out, nil
}

func cloneCertConfig(src *CertConfig) *CertConfig {
	if src == nil {
		return nil
	}
	dst := *src
	if src.DNSEnv != nil {
		dst.DNSEnv = make(map[string]string, len(src.DNSEnv))
		for k, v := range src.DNSEnv {
			dst.DNSEnv[k] = v
		}
	}
	return &dst
}

func normalizeDNSEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeCertConfig(certConfig *CertConfig, configDir string) *CertConfig {
	certConfig = cloneCertConfig(certConfig)
	if certConfig == nil {
		return nil
	}

	certConfig.CertMode = strings.ToLower(strings.TrimSpace(certConfig.CertMode))
	if certConfig.CertMode == "" && (strings.TrimSpace(certConfig.CertFile) != "" || strings.TrimSpace(certConfig.KeyFile) != "") {
		certConfig.CertMode = "file"
	}
	certConfig.CertDomain = strings.TrimSpace(certConfig.CertDomain)
	certConfig.CertFile = strings.TrimSpace(certConfig.CertFile)
	certConfig.KeyFile = strings.TrimSpace(certConfig.KeyFile)
	certConfig.KeyType = strings.ToLower(strings.TrimSpace(certConfig.KeyType))
	certConfig.Provider = strings.TrimSpace(certConfig.Provider)
	certConfig.Email = strings.TrimSpace(certConfig.Email)
	certConfig.DNSEnv = normalizeDNSEnv(certConfig.DNSEnv)

	if configDir != "" {
		if certConfig.CertFile != "" && !filepath.IsAbs(certConfig.CertFile) {
			certConfig.CertFile = filepath.Join(configDir, certConfig.CertFile)
		}
		if certConfig.KeyFile != "" && !filepath.IsAbs(certConfig.KeyFile) {
			certConfig.KeyFile = filepath.Join(configDir, certConfig.KeyFile)
		}
	}
	return certConfig
}

func normalizeNodeCertConfig(node *NodeConfig, configDir string) {
	if node == nil {
		return
	}
	node.CertFile = strings.TrimSpace(node.CertFile)
	node.KeyFile = strings.TrimSpace(node.KeyFile)

	certConfig := cloneCertConfig(node.CertConfig)
	if certConfig == nil && (node.CertFile != "" || node.KeyFile != "") {
		certConfig = &CertConfig{
			CertMode: "file",
			CertFile: node.CertFile,
			KeyFile:  node.KeyFile,
		}
	}
	if certConfig == nil {
		return
	}

	certConfig = normalizeCertConfig(certConfig, configDir)

	if certConfig.CertFile != "" {
		node.CertFile = certConfig.CertFile
	} else if node.CertFile != "" && !filepath.IsAbs(node.CertFile) {
		node.CertFile = filepath.Join(configDir, node.CertFile)
		certConfig.CertFile = node.CertFile
	}
	if certConfig.KeyFile != "" {
		node.KeyFile = certConfig.KeyFile
	} else if node.KeyFile != "" && !filepath.IsAbs(node.KeyFile) {
		node.KeyFile = filepath.Join(configDir, node.KeyFile)
		certConfig.KeyFile = node.KeyFile
	}
	node.CertConfig = certConfig
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
