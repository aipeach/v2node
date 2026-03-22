package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	sspanel "github.com/wyx2685/v2node/api/sspanel"
	"github.com/wyx2685/v2node/conf"
)

const (
	None    = sspanel.None
	Tls     = sspanel.Tls
	Reality = sspanel.Reality
)

type NodeInfo = sspanel.NodeInfo
type CommonNode = sspanel.CommonNode
type Route = sspanel.Route
type BaseConfig = sspanel.BaseConfig
type TlsSettings = sspanel.TlsSettings
type CertInfo = sspanel.CertInfo
type EncSettings = sspanel.EncSettings
type FallbackObject = sspanel.FallbackObject

type sogaNodeData struct {
	Basic  *sogaBasicConfig `json:"basic"`
	Config json.RawMessage  `json:"config"`
}

type sogaBasicConfig struct {
	PullInterval any `json:"pull_interval"`
	PushInterval any `json:"push_interval"`
	SpeedLimit   any `json:"speed_limit"`
}

type sogaStreamNodeConfig struct {
	Port        int      `json:"port"`
	StreamType  string   `json:"stream_type"`
	TlsType     string   `json:"tls_type"`
	Path        string   `json:"path"`
	ServiceName string   `json:"service_name"`
	Flow        string   `json:"flow"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	ShortIDs    []string `json:"short_ids"`
	Dest        string   `json:"dest"`
}

type sogaShadowsocksConfig struct {
	Port     int    `json:"port"`
	Cipher   string `json:"cipher"`
	Password string `json:"password"`
	Obfs     string `json:"obfs"`
	Path     string `json:"path"`
	Host     string `json:"host"`
}

type sogaSSRConfig struct {
	Port           int    `json:"port"`
	Method         string `json:"method"`
	Password       string `json:"password"`
	Protocol       string `json:"protocol"`
	Obfs           string `json:"obfs"`
	SinglePortType string `json:"single_port_type"`
}

type sogaHysteriaConfig struct {
	Port         int    `json:"port"`
	Obfs         string `json:"obfs"`
	ObfsPassword string `json:"obfs_password"`
	UpMbps       int    `json:"up_mbps"`
	DownMbps     int    `json:"down_mbps"`
}

type sogaAnyTLSConfig struct {
	Port          int      `json:"port"`
	PaddingScheme []string `json:"padding_scheme"`
}

type sogaAuditRuleRow struct {
	ID   any    `json:"id"`
	Rule string `json:"rule"`
}

func (c *Client) GetNodeInfo() (*NodeInfo, error) {
	nodeChanged, err := c.refreshNodeData()
	if err != nil {
		return nil, err
	}

	routesChanged, err := c.refreshAuditRules()
	if err != nil {
		// 保持上一次缓存，避免因审计接口偶发错误导致节点不可用。
		routesChanged = false
	}

	whiteListChanged, err := c.refreshWhiteList()
	if err != nil {
		// 保持上一次缓存，避免因白名单接口偶发错误导致节点不可用。
		whiteListChanged = false
	}

	if !nodeChanged && !routesChanged && !whiteListChanged {
		return nil, nil
	}
	if c.cachedNodeData == nil {
		return nil, fmt.Errorf("node data cache is empty")
	}
	return c.buildNodeInfo(c.cachedNodeData)
}

func (c *Client) refreshNodeData() (bool, error) {
	r, err := c.client.R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get("api/v1/node")
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return false, nil
	}
	if r.StatusCode() >= 400 {
		return false, fmt.Errorf("get node info failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	hash := sha256.Sum256(r.Body())
	bodyHash := hex.EncodeToString(hash[:])
	c.nodeEtag = r.Header().Get("ETag")
	if c.nodeBodyHash == bodyHash {
		return false, nil
	}

	data := &sogaNodeData{}
	if err := json.Unmarshal(r.Body(), data); err != nil {
		return false, fmt.Errorf("decode soga node info error: %w", err)
	}
	if len(data.Config) == 0 {
		return false, fmt.Errorf("soga node config is empty")
	}

	c.nodeBodyHash = bodyHash
	c.cachedNodeData = data
	return true, nil
}

func (c *Client) refreshAuditRules() (bool, error) {
	r, err := c.client.R().
		SetHeader("If-None-Match", c.auditRuleEtag).
		ForceContentType("application/json").
		Get("api/v1/audit_rules")
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return false, nil
	}
	if r.StatusCode() >= 400 {
		return false, fmt.Errorf("get audit rules failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	hash := sha256.Sum256(r.Body())
	bodyHash := hex.EncodeToString(hash[:])
	c.auditRuleEtag = r.Header().Get("ETag")
	if c.auditRuleBodyHash == bodyHash {
		return false, nil
	}

	routes, err := parseSogaAuditRulesToRoutes(r.Body())
	if err != nil {
		return false, err
	}
	c.auditRuleBodyHash = bodyHash
	c.cachedRoutes = routes
	return true, nil
}

func (c *Client) refreshWhiteList() (bool, error) {
	r, err := c.client.R().
		SetHeader("If-None-Match", c.whiteListEtag).
		ForceContentType("application/json").
		Get("api/v1/white_list")
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return false, nil
	}
	if r.StatusCode() >= 400 {
		return false, fmt.Errorf("get audit white list failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	hash := sha256.Sum256(r.Body())
	bodyHash := hex.EncodeToString(hash[:])
	c.whiteListEtag = r.Header().Get("ETag")
	if c.whiteListBodyHash == bodyHash {
		return false, nil
	}

	var rows []string
	if err := json.Unmarshal(r.Body(), &rows); err != nil {
		return false, fmt.Errorf("decode audit white list error: %w", err)
	}
	c.whiteListBodyHash = bodyHash
	c.cachedWhiteList = dedupeStringSlice(rows)
	return true, nil
}

func (c *Client) buildNodeInfo(data *sogaNodeData) (*NodeInfo, error) {
	if data == nil {
		return nil, fmt.Errorf("nil node data")
	}
	pushInterval, pullInterval := parseNodeIntervals(data.Basic)

	common := &CommonNode{
		ListenIP: resolveListenIP(c.ListenIP),
		Routes:   cloneRoutes(c.cachedRoutes),
		BaseConfig: &BaseConfig{
			PushInterval:           pushInterval,
			PullInterval:           pullInterval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
		AuditWhiteList: append([]string(nil), c.cachedWhiteList...),
	}

	nodeType := normalizeNodeType(c.NodeType)
	node := &NodeInfo{
		Id:           c.NodeId,
		Type:         nodeType,
		Security:     None,
		PushInterval: time.Duration(pushInterval) * time.Second,
		PullInterval: time.Duration(pullInterval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", c.APIHost, nodeType, c.NodeId),
		Common:       common,
	}

	switch nodeType {
	case "vmess":
		cfg := &sogaStreamNodeConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode vmess config error: %w", err)
		}
		if err := applyStreamNode(common, "vmess", cfg, c.AcceptProxyProto); err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(cfg.TlsType), "tls") {
			attachTLS(common, node, c, chooseCertDomain(cfg.ServerNames, common.ListenIP), "vmess")
		}
	case "vless":
		cfg := &sogaStreamNodeConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode vless config error: %w", err)
		}
		if err := applyStreamNode(common, "vless", cfg, c.AcceptProxyProto); err != nil {
			return nil, err
		}
		common.Flow = strings.TrimSpace(cfg.Flow)
		switch strings.ToLower(strings.TrimSpace(cfg.TlsType)) {
		case "reality":
			applyReality(common, node, cfg)
		case "tls":
			attachTLS(common, node, c, chooseCertDomain(cfg.ServerNames, common.ListenIP), "vless")
		}
		if c.EnableFallback {
			fb, err := buildNodeFallbackObject(c.FallbackObject)
			if err != nil {
				return nil, err
			}
			common.EnableFallback = true
			common.FallbackObject = fb
		}
	case "trojan":
		cfg := &sogaStreamNodeConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode trojan config error: %w", err)
		}
		if err := applyStreamNode(common, "trojan", cfg, c.AcceptProxyProto); err != nil {
			return nil, err
		}
		attachTLS(common, node, c, chooseCertDomain(cfg.ServerNames, common.ListenIP), "trojan")
		if c.EnableFallback {
			fb, err := buildNodeFallbackObject(c.FallbackObject)
			if err != nil {
				return nil, err
			}
			common.EnableFallback = true
			common.FallbackObject = fb
		}
	case "shadowsocks":
		cfg := &sogaShadowsocksConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode shadowsocks config error: %w", err)
		}
		if cfg.Port <= 0 {
			return nil, fmt.Errorf("invalid shadowsocks port: %d", cfg.Port)
		}
		common.Protocol = "shadowsocks"
		common.ServerPort = cfg.Port
		common.Cipher = normalizeShadowsocksMethod(cfg.Cipher)
		if common.Cipher == "" {
			return nil, fmt.Errorf("shadowsocks cipher is empty")
		}
		if isShadowsocks2022Method(common.Cipher) {
			common.ServerKey = strings.TrimSpace(cfg.Password)
			if common.ServerKey == "" {
				return nil, fmt.Errorf("shadowsocks 2022 requires node password in config.password")
			}
		}
		if raw, err := buildShadowsocksNetworkSettings(cfg.Obfs, cfg.Path, cfg.Host, c.AcceptProxyProto); err != nil {
			return nil, err
		} else if len(raw) > 0 {
			common.NetworkSettings = raw
		}
	case "shadowsocksr":
		cfg := &sogaSSRConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode shadowsocksr config error: %w", err)
		}
		fillSSRConfigDefaults(cfg, data.Config)
		if cfg.Port <= 0 {
			return nil, fmt.Errorf("invalid shadowsocksr port: %d", cfg.Port)
		}
		common.Protocol = "shadowsocksr"
		common.ServerPort = cfg.Port
		common.SSRMethod = strings.TrimSpace(cfg.Method)
		common.SSRPassword = strings.TrimSpace(cfg.Password)
		common.SSRProtocol = strings.TrimSpace(cfg.Protocol)
		common.SSROBFS = strings.TrimSpace(cfg.Obfs)
		common.SSRMultiUserMode = normalizeSSRSinglePortType(cfg.SinglePortType)
		common.SSObfsUDP = c.SSObfsUDP
		if common.SSRMethod == "" || common.SSRPassword == "" || common.SSRProtocol == "" || common.SSROBFS == "" {
			return nil, fmt.Errorf("invalid shadowsocksr config: method/password/protocol/obfs must not be empty")
		}
	case "hysteria2":
		cfg := &sogaHysteriaConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode hysteria config error: %w", err)
		}
		if cfg.Port <= 0 {
			return nil, fmt.Errorf("invalid hysteria port: %d", cfg.Port)
		}
		common.Protocol = "hysteria2"
		common.ServerPort = cfg.Port
		common.UpMbps = cfg.UpMbps
		common.DownMbps = cfg.DownMbps
		common.Obfs = normalizeHysteriaObfs(cfg.Obfs)
		common.ObfsPassword = strings.TrimSpace(cfg.ObfsPassword)
		if common.UpMbps == 0 && common.DownMbps == 0 {
			common.Ignore_Client_Bandwidth = true
		}
		attachTLS(common, node, c, common.ListenIP, "hysteria2")
	case "anytls":
		cfg := &sogaAnyTLSConfig{}
		if err := json.Unmarshal(data.Config, cfg); err != nil {
			return nil, fmt.Errorf("decode anytls config error: %w", err)
		}
		if cfg.Port <= 0 {
			return nil, fmt.Errorf("invalid anytls port: %d", cfg.Port)
		}
		common.Protocol = "anytls"
		common.ServerPort = cfg.Port
		common.Network = "tcp"
		common.PaddingScheme = append([]string(nil), cfg.PaddingScheme...)
		attachTLS(common, node, c, common.ListenIP, "anytls")
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeType)
	}
	return node, nil
}

func applyStreamNode(common *CommonNode, protocol string, cfg *sogaStreamNodeConfig, acceptProxyProtocol bool) error {
	if common == nil || cfg == nil {
		return fmt.Errorf("invalid stream node config")
	}
	if cfg.Port <= 0 {
		return fmt.Errorf("invalid %s port: %d", protocol, cfg.Port)
	}
	network := normalizeStreamType(protocol, cfg.StreamType)
	raw, err := buildStreamNetworkSettings(network, cfg.Path, "", cfg.ServiceName, acceptProxyProtocol)
	if err != nil {
		return err
	}
	common.Protocol = protocol
	common.ServerPort = cfg.Port
	common.Network = network
	common.NetworkSettings = raw
	return nil
}

func buildStreamNetworkSettings(network string, path string, host string, serviceName string, acceptProxyProtocol bool) (json.RawMessage, error) {
	switch network {
	case "tcp":
		settings := map[string]interface{}{}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		return json.Marshal(settings)
	case "ws":
		settings := map[string]interface{}{
			"path": normalizePath(path),
		}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		host = strings.TrimSpace(host)
		if host != "" {
			settings["headers"] = map[string]string{
				"Host": host,
			}
		}
		return json.Marshal(settings)
	case "grpc":
		settings := map[string]interface{}{
			"serviceName": strings.TrimSpace(serviceName),
		}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		return json.Marshal(settings)
	case "httpupgrade":
		settings := map[string]interface{}{
			"path": normalizePath(path),
		}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		host = strings.TrimSpace(host)
		if host != "" {
			settings["host"] = host
		}
		return json.Marshal(settings)
	case "splithttp":
		settings := map[string]interface{}{
			"path": normalizePath(path),
		}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		host = strings.TrimSpace(host)
		if host != "" {
			settings["host"] = host
		}
		return json.Marshal(settings)
	default:
		return nil, fmt.Errorf("unsupported stream type: %s", network)
	}
}

func buildShadowsocksNetworkSettings(obfs string, path string, host string, acceptProxyProtocol bool) (json.RawMessage, error) {
	obfs = strings.ToLower(strings.TrimSpace(obfs))
	settings := map[string]interface{}{}
	if acceptProxyProtocol {
		settings["acceptProxyProtocol"] = true
	}
	switch obfs {
	case "", "plain":
		if len(settings) == 0 {
			return nil, nil
		}
		return json.Marshal(settings)
	case "simple_obfs_http":
		settings["path"] = normalizePath(path)
		host = strings.TrimSpace(host)
		if host != "" {
			settings["Host"] = host
		}
		return json.Marshal(settings)
	default:
		return nil, fmt.Errorf("unsupported shadowsocks obfs: %s", obfs)
	}
}

func applyReality(common *CommonNode, node *NodeInfo, cfg *sogaStreamNodeConfig) {
	if common == nil || node == nil || cfg == nil {
		return
	}
	serverName := ""
	if len(cfg.ServerNames) > 0 {
		serverName = strings.TrimSpace(cfg.ServerNames[0])
	}
	shortID := ""
	if len(cfg.ShortIDs) > 0 {
		shortID = strings.TrimSpace(cfg.ShortIDs[0])
	}
	destHost, destPort := splitDest(strings.TrimSpace(cfg.Dest))
	if destPort == "" {
		destPort = "443"
	}
	if destHost == "" {
		destHost = serverName
	}
	common.Tls = Reality
	common.TlsSettings = TlsSettings{
		ServerName:       serverName,
		Dest:             destHost,
		ServerPort:       destPort,
		ShortId:          shortID,
		PrivateKey:       strings.TrimSpace(cfg.PrivateKey),
		RejectUnknownSni: "0",
	}
	node.Security = Reality
}

func attachTLS(common *CommonNode, node *NodeInfo, c *Client, defaultDomain string, protocol string) {
	if common == nil || node == nil || c == nil {
		return
	}
	cert := resolveCertInfo(c, defaultDomain, protocol)
	common.Tls = Tls
	common.TlsSettings = TlsSettings{
		ServerName:       cert.CertDomain,
		CertMode:         cert.CertMode,
		CertFile:         cert.CertFile,
		KeyFile:          cert.KeyFile,
		KeyType:          cert.KeyType,
		Provider:         cert.Provider,
		DNSEnv:           dnsEnvToString(cert.DNSEnv),
		RejectUnknownSni: boolToString(cert.RejectUnknownSni),
	}
	common.CertInfo = cert
	if global := resolveGlobalCertInfo(c, cert.CertDomain); global != nil {
		if !sameCertPair(cert, global) {
			common.ExtraCertInfos = append(common.ExtraCertInfos, global)
		}
	}
	node.Security = Tls
}

func resolveCertInfo(c *Client, defaultDomain string, protocol string) *CertInfo {
	certMode := "self"
	certDomain := strings.TrimSpace(defaultDomain)
	if certDomain == "" {
		certDomain = "localhost"
	}
	certFile := strings.TrimSpace(c.CertFile)
	keyFile := strings.TrimSpace(c.KeyFile)
	keyType := ""
	provider := ""
	email := ""
	dnsEnv := map[string]string{}
	rejectUnknownSni := false

	if c.CertConfig != nil {
		local := c.CertConfig
		if mode := strings.ToLower(strings.TrimSpace(local.CertMode)); mode != "" {
			certMode = mode
		}
		if domain := strings.TrimSpace(local.CertDomain); domain != "" {
			certDomain = domain
		}
		if cf := strings.TrimSpace(local.CertFile); cf != "" {
			certFile = cf
		}
		if kf := strings.TrimSpace(local.KeyFile); kf != "" {
			keyFile = kf
		}
		if kt := strings.ToLower(strings.TrimSpace(local.KeyType)); kt != "" {
			keyType = kt
		}
		if p := strings.TrimSpace(local.Provider); p != "" {
			provider = p
		}
		if e := strings.TrimSpace(local.Email); e != "" {
			email = e
		}
		if len(local.DNSEnv) > 0 {
			dnsEnv = make(map[string]string, len(local.DNSEnv))
			for k, v := range local.DNSEnv {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				dnsEnv[k] = strings.TrimSpace(v)
			}
		}
		rejectUnknownSni = local.RejectUnknownSni
	}

	if certFile == "" {
		certFile = filepath.Join("/etc/v2node/", protocol+strconv.Itoa(c.NodeId)+".cer")
	}
	if keyFile == "" {
		keyFile = filepath.Join("/etc/v2node/", protocol+strconv.Itoa(c.NodeId)+".key")
	}

	return &CertInfo{
		CertMode:         certMode,
		CertFile:         certFile,
		KeyFile:          keyFile,
		KeyType:          keyType,
		Email:            email,
		CertDomain:       certDomain,
		DNSEnv:           dnsEnv,
		Provider:         provider,
		RejectUnknownSni: rejectUnknownSni,
	}
}

func resolveGlobalCertInfo(c *Client, defaultDomain string) *CertInfo {
	if c == nil || c.GlobalCertConfig == nil {
		return nil
	}
	global := c.GlobalCertConfig
	certMode := strings.ToLower(strings.TrimSpace(global.CertMode))
	certDomain := strings.TrimSpace(global.CertDomain)
	if certDomain == "" {
		certDomain = strings.TrimSpace(defaultDomain)
	}
	certFile := strings.TrimSpace(global.CertFile)
	keyFile := strings.TrimSpace(global.KeyFile)
	if certMode == "" && (certFile != "" || keyFile != "") {
		certMode = "file"
	}
	if certMode == "" || certMode == "none" {
		return nil
	}
	if certFile == "" || keyFile == "" {
		suffix := sanitizeCertFileToken(certDomain)
		if suffix == "" {
			suffix = "default"
		}
		if certFile == "" {
			certFile = filepath.Join("/etc/v2node/", "global_"+suffix+".cer")
		}
		if keyFile == "" {
			keyFile = filepath.Join("/etc/v2node/", "global_"+suffix+".key")
		}
	}

	dnsEnv := map[string]string{}
	for k, v := range global.DNSEnv {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		dnsEnv[key] = strings.TrimSpace(v)
	}
	email := strings.TrimSpace(global.Email)
	return &CertInfo{
		CertMode:         certMode,
		CertFile:         certFile,
		KeyFile:          keyFile,
		KeyType:          strings.ToLower(strings.TrimSpace(global.KeyType)),
		Email:            email,
		CertDomain:       certDomain,
		DNSEnv:           dnsEnv,
		Provider:         strings.TrimSpace(global.Provider),
		RejectUnknownSni: global.RejectUnknownSni,
	}
}

func parseSogaAuditRulesToRoutes(body []byte) ([]Route, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(body, &raws); err != nil {
		return nil, fmt.Errorf("decode audit rules error: %w", err)
	}
	routes := make([]Route, 0, len(raws))
	seen := make(map[string]struct{}, len(raws))
	for _, raw := range raws {
		id, rule := parseAuditRuleRow(raw)
		if normalized, ok := normalizeDetectPattern(rule); ok {
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			routes = append(routes, Route{
				Id:         id,
				Match:      []string{normalized},
				Action:     "block",
				DetectRule: true,
			})
		}
	}
	return routes, nil
}

func parseAuditRuleRow(raw json.RawMessage) (int, string) {
	var direct string
	if err := json.Unmarshal(raw, &direct); err == nil {
		return 0, strings.TrimSpace(direct)
	}

	row := &sogaAuditRuleRow{}
	if err := json.Unmarshal(raw, row); err == nil {
		return intFromAny(row.ID), strings.TrimSpace(row.Rule)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, ""
	}
	return intFromAny(m["id"]), strings.TrimSpace(stringFromAny(m["rule"]))
}

func normalizeDetectPattern(pattern string) (string, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", false
	}
	lowerPattern := strings.ToLower(pattern)
	if strings.HasPrefix(lowerPattern, "regexp:") {
		pattern = strings.TrimSpace(pattern[len("regexp:"):])
	}
	if pattern == "" {
		return "", false
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return "", false
	}
	return "regexp:" + pattern, true
}

func parseNodeIntervals(basic *sogaBasicConfig) (push int, pull int) {
	push = 60
	pull = 60
	if basic == nil {
		return push, pull
	}
	if v := intFromAny(basic.PushInterval); v > 0 {
		push = v
	}
	if v := intFromAny(basic.PullInterval); v > 0 {
		pull = v
	}
	return push, pull
}

func normalizeStreamType(protocol string, raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "tcp"
	}
	switch value {
	case "tcp":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc":
		return "grpc"
	case "http", "httpupgrade":
		if protocol == "trojan" {
			return "tcp"
		}
		return "httpupgrade"
	case "h2", "splithttp", "xhttp":
		if protocol == "trojan" {
			return "tcp"
		}
		return "splithttp"
	default:
		if protocol == "trojan" {
			return "tcp"
		}
		return value
	}
}

func normalizeHysteriaObfs(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "plain":
		return "plain"
	case "salamander":
		return "salamander"
	default:
		return "plain"
	}
}

func normalizeSSRSinglePortType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "obfs":
		return "obfs"
	default:
		return "protocol"
	}
}

func fillSSRConfigDefaults(cfg *sogaSSRConfig, raw json.RawMessage) {
	if cfg == nil {
		return
	}
	trim := func(v string) string {
		return strings.TrimSpace(v)
	}
	// 面板实现存在字段别名差异，这里尽量兜底兼容。
	if trim(cfg.Method) == "" || trim(cfg.Password) == "" || trim(cfg.Protocol) == "" || trim(cfg.Obfs) == "" {
		var row map[string]interface{}
		_ = json.Unmarshal(raw, &row)
		if trim(cfg.Method) == "" {
			cfg.Method = firstNonEmptyString(
				cfg.Method,
				stringFromAny(row["method"]),
				stringFromAny(row["cipher"]),
				stringFromAny(row["encrypt"]),
				stringFromAny(row["ssr_method"]),
			)
		}
		if trim(cfg.Password) == "" {
			cfg.Password = firstNonEmptyString(
				cfg.Password,
				stringFromAny(row["password"]),
				stringFromAny(row["passwd"]),
				stringFromAny(row["pass"]),
				stringFromAny(row["ssr_password"]),
			)
		}
		if trim(cfg.Protocol) == "" {
			cfg.Protocol = firstNonEmptyString(
				cfg.Protocol,
				stringFromAny(row["protocol"]),
				stringFromAny(row["ssr_protocol"]),
				stringFromAny(row["protocol_name"]),
			)
		}
		if trim(cfg.Obfs) == "" {
			cfg.Obfs = firstNonEmptyString(
				cfg.Obfs,
				stringFromAny(row["obfs"]),
				stringFromAny(row["ssr_obfs"]),
				stringFromAny(row["obfs_type"]),
			)
		}
		if trim(cfg.SinglePortType) == "" {
			cfg.SinglePortType = firstNonEmptyString(
				cfg.SinglePortType,
				stringFromAny(row["single_port_type"]),
				stringFromAny(row["singlePortType"]),
			)
		}
	}
	if trim(cfg.Protocol) == "" {
		cfg.Protocol = "origin"
	}
	if trim(cfg.Obfs) == "" {
		cfg.Obfs = "plain"
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeShadowsocksMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aead_aes_128_gcm":
		return "aes-128-gcm"
	case "aead_aes_192_gcm":
		return "aes-192-gcm"
	case "aead_aes_256_gcm":
		return "aes-256-gcm"
	case "chacha20-poly1305", "aead_chacha20_poly1305":
		return "chacha20-ietf-poly1305"
	default:
		return strings.ToLower(strings.TrimSpace(method))
	}
}

func isShadowsocks2022Method(method string) bool {
	switch normalizeShadowsocksMethod(method) {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	default:
		return false
	}
}

func resolveListenIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "0.0.0.0"
	}
	return value
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func splitDest(dest string) (string, string) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", ""
	}
	host, port, found := strings.Cut(dest, ":")
	if !found {
		return dest, ""
	}
	return strings.TrimSpace(host), strings.TrimSpace(port)
}

func chooseCertDomain(serverNames []string, fallback string) string {
	for _, name := range serverNames {
		name = strings.TrimSpace(name)
		if name != "" {
			return name
		}
	}
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		return fallback
	}
	return "localhost"
}

func boolToString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func dnsEnvToString(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return ""
	}
	sortStrings(keys)
	segments := make([]string, 0, len(keys))
	for _, k := range keys {
		segments = append(segments, fmt.Sprintf("%s=%s", k, strings.TrimSpace(env[k])))
	}
	return strings.Join(segments, ",")
}

func sortStrings(values []string) {
	if len(values) < 2 {
		return
	}
	for i := 0; i < len(values)-1; i++ {
		for j := i + 1; j < len(values); j++ {
			if values[i] > values[j] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

func sanitizeCertFileToken(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return ""
	}
	re := regexp.MustCompile(`[^a-z0-9._-]+`)
	return strings.Trim(re.ReplaceAllString(input, "_"), "_")
}

func sameCertPair(a *CertInfo, b *CertInfo) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.TrimSpace(a.CertFile) == strings.TrimSpace(b.CertFile) &&
		strings.TrimSpace(a.KeyFile) == strings.TrimSpace(b.KeyFile)
}

func buildNodeFallbackObject(src *conf.FallbackObject) (*FallbackObject, error) {
	fb := &FallbackObject{
		Dest: 80,
		Xver: 0,
	}
	if src != nil {
		fb.Name = strings.TrimSpace(src.Name)
		fb.Alpn = strings.TrimSpace(src.Alpn)
		fb.Path = strings.TrimSpace(src.Path)
		if src.Dest > 0 {
			fb.Dest = src.Dest
		}
		fb.Xver = src.Xver
	}

	if fb.Dest <= 0 || fb.Dest > 65535 {
		return nil, fmt.Errorf("invalid fallback dest: %d", fb.Dest)
	}
	if fb.Xver < 0 || fb.Xver > 2 {
		return nil, fmt.Errorf("invalid fallback xver: %d", fb.Xver)
	}
	if fb.Path != "" && !strings.HasPrefix(fb.Path, "/") {
		return nil, fmt.Errorf("invalid fallback path %q: must start with /", fb.Path)
	}
	return fb, nil
}

func cloneRoutes(src []Route) []Route {
	if len(src) == 0 {
		return nil
	}
	out := make([]Route, len(src))
	for i := range src {
		out[i] = Route{
			Id:         src[i].Id,
			Action:     src[i].Action,
			DetectRule: src[i].DetectRule,
		}
		if len(src[i].Match) > 0 {
			out[i].Match = append([]string(nil), src[i].Match...)
		}
		if src[i].ActionValue != nil {
			v := *src[i].ActionValue
			out[i].ActionValue = &v
		}
	}
	return out
}

func dedupeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stringFromAny(v interface{}) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func intFromAny(v interface{}) int {
	switch value := v.(type) {
	case nil:
		return 0
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float32:
		return int(value)
	case float64:
		return int(value)
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return int(i)
		}
		if f, err := value.Float64(); err == nil {
			return int(f)
		}
	case string:
		value = strings.TrimSpace(value)
		if value == "" {
			return 0
		}
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return int(f)
		}
	}
	return 0
}
