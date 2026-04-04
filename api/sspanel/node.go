package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
)

type NodeInfo struct {
	Id           int
	Type         string
	Security     int
	PushInterval time.Duration
	PullInterval time.Duration
	Tag          string
	Common       *CommonNode
}

type CommonNode struct {
	Protocol       string      `json:"protocol"`
	ListenIP       string      `json:"listen_ip"`
	ServerPort     int         `json:"server_port"`
	Routes         []Route     `json:"routes"`
	AuditWhiteList []string    `json:"audit_white_list,omitempty"`
	XrayRules      *XrayRules  `json:"xray_rules,omitempty"`
	BaseConfig     *BaseConfig `json:"base_config"`
	//vless vmess trojan
	Tls                int         `json:"tls"`
	TlsSettings        TlsSettings `json:"tls_settings"`
	CertInfo           *CertInfo
	ExtraCertInfos     []*CertInfo
	Network            string          `json:"network"`
	NetworkSettings    json.RawMessage `json:"network_settings"`
	Encryption         string          `json:"encryption"`
	EncryptionSettings EncSettings     `json:"encryption_settings"`
	ServerName         string          `json:"server_name"`
	Flow               string          `json:"flow"`
	EnableFallback     bool            `json:"enable_fallback"`
	FallbackObject     *FallbackObject `json:"fallback_object"`
	//shadowsocks
	Cipher                string `json:"cipher"`
	ServerKey             string `json:"server_key"`
	SSSinglePortMultiUser bool   `json:"ss_single_port_multi_user"`
	//shadowsocksr
	SSRMethod        string `json:"ssr_method"`
	SSRPassword      string `json:"ssr_password"`
	SSRMultiUserMode string `json:"ssr_multi_user_mode"`
	SSRProtocol      string `json:"ssr_protocol"`
	SSRProtocolParam string `json:"ssr_protocol_param"`
	SSROBFS          string `json:"ssr_obfs"`
	SSROBFSParam     string `json:"ssr_obfs_param"`
	SSObfsUDP        bool   `json:"ss_obfs_udp"`
	//tuic
	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
	//anytls
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	//hysteria hysteria2
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsPassword            string `json:"obfs-password"`
	Ignore_Client_Bandwidth bool   `json:"ignore_client_bandwidth"`
}

type Route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
	DetectRule  bool     `json:"-"`
}

type XrayRules struct {
	DNS       json.RawMessage `json:"dns,omitempty"`
	Routing   json.RawMessage `json:"routing,omitempty"`
	Outbounds json.RawMessage `json:"outbounds,omitempty"`
}

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string   `json:"server_name"`
	Dest             string   `json:"dest"`
	ServerPort       string   `json:"server_port"`
	ShortId          string   `json:"short_id"`
	ShortIds         []string `json:"short_ids,omitempty"`
	PrivateKey       string   `json:"private_key"`
	Mldsa65Seed      string   `json:"mldsa65Seed"`
	Xver             uint64   `json:"xver,string"`
	CertMode         string   `json:"cert_mode"`
	CertFile         string   `json:"cert_file"`
	KeyFile          string   `json:"key_file"`
	KeyType          string   `json:"key_type"`
	Provider         string   `json:"provider"`
	DNSEnv           string   `json:"dns_env"`
	RejectUnknownSni string   `json:"reject_unknown_sni"`
	EchServerKeys    string   `json:"echServerKeys"`
	EchForceQuery    string   `json:"echForceQuery"`
}

type CertInfo struct {
	CertMode         string
	CertFile         string
	KeyFile          string
	KeyType          string
	Email            string
	CertDomain       string
	DNSEnv           map[string]string
	Provider         string
	RejectUnknownSni bool
	EchServerKeys    string
	EchForceQuery    string
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

type FallbackObject struct {
	Name string `json:"name"`
	Alpn string `json:"alpn"`
	Path string `json:"path"`
	Dest int    `json:"dest"`
	Xver int    `json:"xver"`
}

type modMUNodeInfoResponse struct {
	Ret  int            `json:"ret"`
	Data *modMUNodeData `json:"data"`
}

type modMUNodeData struct {
	Sort           int    `json:"sort"`
	Type           string `json:"type"`
	Server         string `json:"server"`
	DisconnectTime int    `json:"disconnect_time"`
}

type modMUDetectRulesResponse struct {
	Ret  int               `json:"ret"`
	Data []json.RawMessage `json:"data"`
}

type vmessEndpoint struct {
	ListenIP     string
	ListenPort   int
	Network      string
	SecurityMode string
	Path         string
	Host         string
	ServerName   string
	ExtraParams  map[string]string
}

type trojanEndpoint struct {
	ListenIP    string
	ListenPort  int
	ConnectHost string
	ConnectPort int
	ServerName  string
	ExtraParams map[string]string
}

type anyTLSEndpoint struct {
	ListenIP    string
	ListenPort  int
	ConnectHost string
}

func (c *Client) GetNodeInfo() (*NodeInfo, error) {
	path := fmt.Sprintf("/mod_mu/nodes/%d/info", c.NodeId)
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	nodeChanged := false
	nodeData := c.cachedNodeData
	switch {
	case r.StatusCode() == 304:
		// no-op, use cached node data
	case r.StatusCode() >= 400:
		return nil, fmt.Errorf("get node info failed with status %d: %s", r.StatusCode(), string(r.Body()))
	default:
		hash := sha256.Sum256(r.Body())
		newBodyHash := hex.EncodeToString(hash[:])
		if c.responseBodyHash != newBodyHash {
			resp := &modMUNodeInfoResponse{}
			if err := json.Unmarshal(r.Body(), resp); err != nil {
				return nil, fmt.Errorf("decode mod_mu node info response error: %w", err)
			}
			if resp.Ret != 1 {
				return nil, fmt.Errorf("mod_mu node info ret=%d, body=%s", resp.Ret, string(r.Body()))
			}
			if resp.Data == nil {
				return nil, fmt.Errorf("node %d is unavailable", c.NodeId)
			}
			nodeData = cloneNodeData(resp.Data)
			c.cachedNodeData = nodeData
			c.responseBodyHash = newBodyHash
			nodeChanged = true
		}
		c.nodeEtag = r.Header().Get("ETag")
	}

	routes, routesChanged, err := c.getDetectRoutes()
	if err != nil {
		routes = cloneRoutes(c.cachedRoutes)
	}
	if !nodeChanged && !routesChanged {
		return nil, nil
	}
	if nodeData == nil {
		return nil, fmt.Errorf("node %d info cache is empty", c.NodeId)
	}

	node, err := buildModMUNodeInfo(c, nodeData, routes)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func buildModMUNodeInfo(client *Client, data *modMUNodeData, routes []Route) (*NodeInfo, error) {
	if client == nil {
		return nil, fmt.Errorf("nil api client")
	}
	protocol := strings.ToLower(strings.TrimSpace(client.NodeType))
	if protocol == "" {
		protocol = "vmess"
	}
	selectedMode := normalizeSSRSinglePortMode(client.SSRSinglePortMode)
	isSSR := isSSRNodeType(protocol)
	if isSSR && (selectedMode == "" || selectedMode == SSRSinglePortModeAuto) {
		_, selectedMode = parseSSRNodeType(protocol)
	}
	switch {
	case protocol == "vmess" || protocol == "vless":
		return buildModMUVmessNodeInfo(client, data, routes, protocol)
	case protocol == "trojan":
		return buildModMUTrojanNodeInfo(client, data, routes)
	case protocol == "anytls":
		return buildModMUAnyTLSNodeInfo(client, data, routes)
	case isShadowsocksNodeType(protocol):
		return buildModMUShadowsocksNodeInfo(client, data, routes)
	case isSSR:
		return buildModMUSSRNodeInfo(client, data, routes, selectedMode)
	default:
		return nil, fmt.Errorf("unsupported node type from config: %s", protocol)
	}
}

func buildModMUShadowsocksNodeInfo(client *Client, data *modMUNodeData, routes []Route) (*NodeInfo, error) {
	templateUser, err := client.fetchShadowsocksTemplateUser()
	if err != nil {
		return nil, err
	}

	serverPort := intFromAny(templateUser.Port)
	if serverPort <= 0 {
		return nil, fmt.Errorf("invalid shadowsocks template user port: %v", templateUser.Port)
	}

	method := normalizeShadowsocksMethod(templateUser.Method)
	if method == "" {
		return nil, fmt.Errorf("shadowsocks template user method is empty")
	}
	if !isShadowsocksSinglePortAEADMethod(method) {
		return nil, fmt.Errorf("unsupported shadowsocks single-port method: %s", method)
	}

	password := strings.TrimSpace(templateUser.Passwd)
	if isShadowsocks2022Method(method) && password == "" {
		return nil, fmt.Errorf("shadowsocks 2022 single-port template user password is empty")
	}

	interval := data.DisconnectTime
	if interval <= 0 {
		interval = 60
	}

	listenIP := resolveSSRListenIP(client.ListenIP, data.Server)
	serverKey := ""
	if isShadowsocks2022Method(method) {
		serverKey = password
	}

	common := &CommonNode{
		Protocol:              "shadowsocks",
		ListenIP:              listenIP,
		ServerPort:            serverPort,
		Routes:                cloneRoutes(routes),
		Cipher:                method,
		ServerKey:             serverKey,
		SSSinglePortMultiUser: true,
		BaseConfig: &BaseConfig{
			PushInterval:           interval,
			PullInterval:           interval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
	}

	return &NodeInfo{
		Id:           client.NodeId,
		Type:         "shadowsocks",
		Security:     None,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", client.APIHost, "shadowsocks", client.NodeId),
		Common:       common,
	}, nil
}

func buildModMUVmessNodeInfo(client *Client, data *modMUNodeData, routes []Route, protocol string) (*NodeInfo, error) {
	nodeID := client.NodeId
	endpoint, err := parseVMessEndpoint(data.Server)
	if err != nil {
		return nil, fmt.Errorf("parse node server field failed: %w", err)
	}

	if endpoint.Network != "tcp" && endpoint.Network != "ws" {
		return nil, fmt.Errorf("unsupported %s network: %s", protocol, endpoint.Network)
	}

	networkSettings, err := buildVMessNetworkSettings(endpoint, client.AcceptProxyProto)
	if err != nil {
		return nil, err
	}

	interval := data.DisconnectTime
	if interval <= 0 {
		interval = 60
	}

	listenIP := endpoint.ListenIP
	if strings.TrimSpace(client.ListenIP) != "" {
		listenIP = strings.TrimSpace(client.ListenIP)
	}

	common := &CommonNode{
		Protocol:        protocol,
		ListenIP:        listenIP,
		ServerPort:      endpoint.ListenPort,
		Routes:          cloneRoutes(routes),
		Network:         endpoint.Network,
		NetworkSettings: networkSettings,
		BaseConfig: &BaseConfig{
			PushInterval:           interval,
			PullInterval:           interval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
	}
	if protocol == "vless" {
		common.Flow = strings.TrimSpace(endpoint.ExtraParams["flow"])
	}

	if protocol == "vless" && client.EnableFallback {
		fb, err := buildNodeFallbackObject(client.FallbackObject)
		if err != nil {
			return nil, err
		}
		common.EnableFallback = true
		common.FallbackObject = fb
	}

	node := &NodeInfo{
		Id:           nodeID,
		Type:         protocol,
		Security:     None,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", client.APIHost, protocol, nodeID),
		Common:       common,
	}

	switch resolveVMessSecurityMode(endpoint) {
	case "reality":
		if protocol != "vless" {
			return nil, fmt.Errorf("security reality is not supported for protocol %s", protocol)
		}
		if err := applyModMUReality(common, node, endpoint); err != nil {
			return nil, err
		}
	case "tls":
		certInfo := resolveCertInfo(endpoint, client, common.Protocol, nodeID)
		common.Tls = Tls
		common.TlsSettings = TlsSettings{
			ServerName:       certInfo.CertDomain,
			CertMode:         certInfo.CertMode,
			CertFile:         certInfo.CertFile,
			KeyFile:          certInfo.KeyFile,
			KeyType:          certInfo.KeyType,
			Provider:         certInfo.Provider,
			DNSEnv:           dnsEnvToString(certInfo.DNSEnv),
			RejectUnknownSni: boolToString(certInfo.RejectUnknownSni),
			EchServerKeys:    certInfo.EchServerKeys,
			EchForceQuery:    certInfo.EchForceQuery,
		}
		common.CertInfo = certInfo
		if globalCertInfo := resolveGlobalCertInfo(client, certInfo.CertDomain); globalCertInfo != nil {
			if !sameCertPair(certInfo, globalCertInfo) {
				common.ExtraCertInfos = append(common.ExtraCertInfos, globalCertInfo)
			}
		}
		node.Security = Tls
	}

	return node, nil
}

func buildModMUTrojanNodeInfo(client *Client, data *modMUNodeData, routes []Route) (*NodeInfo, error) {
	nodeID := client.NodeId
	protocol := "trojan"

	endpoint, err := parseTrojanEndpoint(data.Server)
	if err != nil {
		return nil, fmt.Errorf("parse trojan server field failed: %w", err)
	}

	interval := data.DisconnectTime
	if interval <= 0 {
		interval = 60
	}

	listenIP := endpoint.ListenIP
	if strings.TrimSpace(client.ListenIP) != "" {
		listenIP = strings.TrimSpace(client.ListenIP)
	}

	networkSettings, err := buildProxyProtocolNetworkSettings(client.AcceptProxyProto)
	if err != nil {
		return nil, err
	}

	certInfo := resolveTrojanCertInfo(endpoint, client, protocol, nodeID)
	common := &CommonNode{
		Protocol:        protocol,
		ListenIP:        listenIP,
		ServerPort:      endpoint.ListenPort,
		Routes:          cloneRoutes(routes),
		Network:         "tcp",
		NetworkSettings: networkSettings,
		Tls:             Tls,
		TlsSettings: TlsSettings{
			ServerName:       certInfo.CertDomain,
			CertMode:         certInfo.CertMode,
			CertFile:         certInfo.CertFile,
			KeyFile:          certInfo.KeyFile,
			KeyType:          certInfo.KeyType,
			Provider:         certInfo.Provider,
			DNSEnv:           dnsEnvToString(certInfo.DNSEnv),
			RejectUnknownSni: boolToString(certInfo.RejectUnknownSni),
			EchServerKeys:    certInfo.EchServerKeys,
			EchForceQuery:    certInfo.EchForceQuery,
		},
		CertInfo: certInfo,
		BaseConfig: &BaseConfig{
			PushInterval:           interval,
			PullInterval:           interval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
	}

	if client.EnableFallback {
		fb, err := buildNodeFallbackObject(client.FallbackObject)
		if err != nil {
			return nil, err
		}
		common.EnableFallback = true
		common.FallbackObject = fb
	}

	if globalCertInfo := resolveGlobalCertInfo(client, certInfo.CertDomain); globalCertInfo != nil {
		if !sameCertPair(certInfo, globalCertInfo) {
			common.ExtraCertInfos = append(common.ExtraCertInfos, globalCertInfo)
		}
	}

	return &NodeInfo{
		Id:           nodeID,
		Type:         protocol,
		Security:     Tls,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", client.APIHost, protocol, nodeID),
		Common:       common,
	}, nil
}

func buildModMUAnyTLSNodeInfo(client *Client, data *modMUNodeData, routes []Route) (*NodeInfo, error) {
	nodeID := client.NodeId
	protocol := "anytls"

	endpoint, err := parseAnyTLSEndpoint(data.Server)
	if err != nil {
		return nil, fmt.Errorf("parse anytls server field failed: %w", err)
	}

	interval := data.DisconnectTime
	if interval <= 0 {
		interval = 60
	}

	listenIP := endpoint.ListenIP
	if strings.TrimSpace(client.ListenIP) != "" {
		listenIP = strings.TrimSpace(client.ListenIP)
	}

	networkSettings, err := buildProxyProtocolNetworkSettings(client.AcceptProxyProto)
	if err != nil {
		return nil, err
	}

	certInfo := resolveAnyTLSCertInfo(endpoint, client, protocol, nodeID)
	common := &CommonNode{
		Protocol:        protocol,
		ListenIP:        listenIP,
		ServerPort:      endpoint.ListenPort,
		Routes:          cloneRoutes(routes),
		PaddingScheme:   append([]string(nil), client.AnyTLSPaddingScheme...),
		Network:         "tcp",
		NetworkSettings: networkSettings,
		Tls:             Tls,
		TlsSettings: TlsSettings{
			ServerName:       certInfo.CertDomain,
			CertMode:         certInfo.CertMode,
			CertFile:         certInfo.CertFile,
			KeyFile:          certInfo.KeyFile,
			KeyType:          certInfo.KeyType,
			Provider:         certInfo.Provider,
			DNSEnv:           dnsEnvToString(certInfo.DNSEnv),
			RejectUnknownSni: boolToString(certInfo.RejectUnknownSni),
			EchServerKeys:    certInfo.EchServerKeys,
			EchForceQuery:    certInfo.EchForceQuery,
		},
		CertInfo: certInfo,
		BaseConfig: &BaseConfig{
			PushInterval:           interval,
			PullInterval:           interval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
	}

	if globalCertInfo := resolveGlobalCertInfo(client, certInfo.CertDomain); globalCertInfo != nil {
		if !sameCertPair(certInfo, globalCertInfo) {
			common.ExtraCertInfos = append(common.ExtraCertInfos, globalCertInfo)
		}
	}

	return &NodeInfo{
		Id:           nodeID,
		Type:         protocol,
		Security:     Tls,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", client.APIHost, protocol, nodeID),
		Common:       common,
	}, nil
}

func buildModMUSSRNodeInfo(client *Client, data *modMUNodeData, routes []Route, selectedMode string) (*NodeInfo, error) {
	templateUser, err := client.fetchSSRTemplateUser(selectedMode)
	if err != nil {
		return nil, err
	}
	serverPort := intFromAny(templateUser.Port)
	if serverPort <= 0 {
		return nil, fmt.Errorf("invalid ssr template user port: %v", templateUser.Port)
	}
	method := strings.TrimSpace(templateUser.Method)
	if method == "" {
		return nil, fmt.Errorf("ssr template user method is empty")
	}
	password := strings.TrimSpace(templateUser.Passwd)
	if password == "" {
		return nil, fmt.Errorf("ssr template user password is empty")
	}

	protocol := "shadowsocksr"
	multiUserMode := ssrSinglePortModeFromFlag(intFromAny(templateUser.IsMultiUser))
	if multiUserMode == "" {
		return nil, fmt.Errorf("unknown ssr single-port mode from is_multi_user=%v", templateUser.IsMultiUser)
	}
	interval := data.DisconnectTime
	if interval <= 0 {
		interval = 60
	}
	listenIP := resolveSSRListenIP(client.ListenIP, data.Server)
	common := &CommonNode{
		Protocol:         protocol,
		ListenIP:         listenIP,
		ServerPort:       serverPort,
		Routes:           cloneRoutes(routes),
		SSRMethod:        method,
		SSRPassword:      password,
		SSRMultiUserMode: multiUserMode,
		SSRProtocol:      strings.TrimSpace(templateUser.Protocol),
		SSRProtocolParam: strings.TrimSpace(templateUser.ProtocolParam),
		SSROBFS:          strings.TrimSpace(templateUser.Obfs),
		SSROBFSParam:     strings.TrimSpace(templateUser.ObfsParam),
		SSObfsUDP:        client.SSObfsUDP,
		BaseConfig: &BaseConfig{
			PushInterval:           interval,
			PullInterval:           interval,
			DeviceOnlineMinTraffic: 0,
			NodeReportMinTraffic:   0,
		},
	}

	return &NodeInfo{
		Id:           client.NodeId,
		Type:         protocol,
		Security:     None,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          buildSSRNodeTag(client.APIHost, protocol, client.NodeId, selectedMode),
		Common:       common,
	}, nil
}

func (c *Client) fetchSSRTemplateUser(selectedMode string) (*modMUUserRow, error) {
	selectedMode = normalizeSSRSinglePortMode(selectedMode)
	if selectedMode == "" {
		selectedMode = SSRSinglePortModeAuto
	}
	const path = "/mod_mu/users"
	r, err := c.client.R().Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("get user list for ssr node failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}
	resp := &modMUUsersResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return nil, fmt.Errorf("decode mod_mu user list error: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("mod_mu user list ret=%d, body=%s", resp.Ret, string(r.Body()))
	}
	templateUser, err := findSSRTemplateUser(resp.Data, selectedMode)
	if err != nil {
		return nil, err
	}
	return templateUser, nil
}

func (c *Client) fetchShadowsocksTemplateUser() (*modMUUserRow, error) {
	const path = "/mod_mu/users"
	r, err := c.client.R().Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("get user list for shadowsocks node failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	resp := &modMUUsersResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return nil, fmt.Errorf("decode mod_mu user list error: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("mod_mu user list ret=%d, body=%s", resp.Ret, string(r.Body()))
	}

	templateUser, err := findShadowsocksTemplateUser(resp.Data)
	if err != nil {
		return nil, err
	}
	return templateUser, nil
}

func parseSSRNodeType(nodeType string) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case "ssr", "shadowsocksr":
		return true, SSRSinglePortModeAuto
	case "ssr-protocol", "shadowsocksr-protocol":
		return true, SSRSinglePortModeProtocol
	case "ssr-obfs", "shadowsocksr-obfs", "ss":
		return true, SSRSinglePortModeObfs
	default:
		return false, ""
	}
}

func isSSRNodeType(nodeType string) bool {
	ok, _ := parseSSRNodeType(nodeType)
	return ok
}

func isShadowsocksNodeType(nodeType string) bool {
	return strings.EqualFold(strings.TrimSpace(nodeType), "shadowsocks")
}

func isAnyTLSNodeType(nodeType string) bool {
	return strings.EqualFold(strings.TrimSpace(nodeType), "anytls")
}

func buildSSRNodeTag(apiHost, protocol string, nodeID int, selectedMode string) string {
	selectedMode = normalizeSSRSinglePortMode(selectedMode)
	if selectedMode == SSRSinglePortModeAuto || selectedMode == "" {
		return fmt.Sprintf("[%s]-%s:%d", apiHost, protocol, nodeID)
	}
	return fmt.Sprintf("[%s]-%s-%s:%d", apiHost, protocol, selectedMode, nodeID)
}

func resolveSSRListenIP(configListenIP string, serverField string) string {
	if ip := strings.TrimSpace(configListenIP); ip != "" {
		return ip
	}
	parts := strings.SplitN(strings.TrimSpace(serverField), ";", 2)
	if len(parts) > 0 {
		if ip := strings.TrimSpace(parts[0]); ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
	}
	return "0.0.0.0"
}

func parseVMessEndpoint(server string) (*vmessEndpoint, error) {
	parts := strings.SplitN(strings.TrimSpace(server), ";", 6)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid server format: %s", server)
	}
	listenIP := strings.TrimSpace(parts[0])
	if listenIP == "" || net.ParseIP(listenIP) == nil {
		listenIP = "0.0.0.0"
	}
	listenPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || listenPort <= 0 {
		return nil, fmt.Errorf("invalid server port: %s", parts[1])
	}

	network := strings.ToLower(strings.TrimSpace(parts[3]))
	if network == "" {
		network = "tcp"
	}

	securityMode := ""
	if len(parts) >= 5 {
		securityMode = strings.ToLower(strings.TrimSpace(parts[4]))
	}

	extra := ""
	if len(parts) == 6 {
		extra = parts[5]
	}
	params := parseNodeExtraParams(extra)
	return &vmessEndpoint{
		ListenIP:     listenIP,
		ListenPort:   listenPort,
		Network:      network,
		SecurityMode: securityMode,
		Path:         strings.TrimSpace(params["path"]),
		Host:         strings.TrimSpace(params["host"]),
		ServerName:   firstNonEmpty(params["server"], params["sni"], params["servername"], params["server_name"]),
		ExtraParams:  params,
	}, nil
}

func resolveVMessSecurityMode(endpoint *vmessEndpoint) string {
	if endpoint == nil {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(endpoint.ExtraParams["security"]))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(endpoint.SecurityMode))
	}
	switch mode {
	case "none", "plain":
		return ""
	case "xtls":
		return "tls"
	default:
		return mode
	}
}

func applyModMUReality(common *CommonNode, node *NodeInfo, endpoint *vmessEndpoint) error {
	if common == nil || node == nil || endpoint == nil {
		return fmt.Errorf("invalid vless reality settings")
	}
	params := endpoint.ExtraParams
	serverName := firstNonEmpty(params["sni"], params["server_name"], params["servername"], endpoint.ServerName)
	destHost, destPort := splitDest(firstNonEmpty(params["target"], params["dest"]))
	if destPort == "" {
		destPort = "443"
	}
	if destHost == "" {
		destHost = serverName
	}
	if serverName == "" {
		serverName = destHost
	}
	privateKey := firstNonEmpty(params["privatekey"], params["private_key"])
	if privateKey == "" {
		return fmt.Errorf("vless reality private key is empty")
	}
	if destHost == "" {
		return fmt.Errorf("vless reality target is empty")
	}
	shortIDs := parseRealityShortIDs(params)
	shortID := ""
	if len(shortIDs) > 0 {
		shortID = shortIDs[0]
	}
	xver := uint64(0)
	if rawXver := strings.TrimSpace(params["xver"]); rawXver != "" {
		value, err := strconv.ParseUint(rawXver, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid vless reality xver: %s", rawXver)
		}
		xver = value
	}

	common.Tls = Reality
	common.TlsSettings = TlsSettings{
		ServerName:       serverName,
		Dest:             destHost,
		ServerPort:       destPort,
		ShortId:          shortID,
		ShortIds:         shortIDs,
		PrivateKey:       privateKey,
		Mldsa65Seed:      firstNonEmpty(params["mldsa65seed"], params["mldsa65_seed"]),
		Xver:             xver,
		RejectUnknownSni: "0",
	}
	node.Security = Reality
	return nil
}

func parseRealityShortIDs(params map[string]string) []string {
	if len(params) == 0 {
		return nil
	}
	segments := []string{
		params["shortids"],
		params["short_ids"],
		params["sid"],
		params["shortid"],
		params["short_id"],
	}
	shortIDs := make([]string, 0, len(segments))
	seen := make(map[string]struct{}, len(segments))
	for _, raw := range segments {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == '|' || r == ' ' || r == '\t'
		}) {
			shortID := strings.TrimSpace(token)
			if shortID == "" {
				continue
			}
			if _, ok := seen[shortID]; ok {
				continue
			}
			seen[shortID] = struct{}{}
			shortIDs = append(shortIDs, shortID)
		}
	}
	if len(shortIDs) == 0 {
		return nil
	}
	return shortIDs
}

func parseTrojanEndpoint(server string) (*trojanEndpoint, error) {
	parts := strings.SplitN(strings.TrimSpace(server), ";", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid trojan server format: %s", server)
	}

	connectHost := strings.TrimSpace(parts[0])
	if connectHost == "" {
		return nil, fmt.Errorf("trojan connect host is empty")
	}

	segments := strings.Split(strings.TrimSpace(parts[1]), "|")
	if len(segments) == 0 {
		return nil, fmt.Errorf("trojan server parameters are empty")
	}

	portSegment := strings.TrimSpace(segments[0])
	if !strings.HasPrefix(strings.ToLower(portSegment), "port=") {
		return nil, fmt.Errorf("trojan server requires port=... format: %s", server)
	}
	portValue := strings.TrimSpace(portSegment[len("port="):])
	if portValue == "" {
		return nil, fmt.Errorf("trojan port value is empty")
	}

	publicPortText := portValue
	listenPortText := ""
	if idx := strings.Index(portValue, "#"); idx >= 0 {
		publicPortText = strings.TrimSpace(portValue[:idx])
		listenPortText = strings.TrimSpace(portValue[idx+1:])
	}

	publicPort, err := parsePortValue(publicPortText)
	if err != nil {
		return nil, fmt.Errorf("invalid trojan public port: %w", err)
	}
	listenPort := publicPort
	if listenPortText != "" {
		listenPort, err = parsePortValue(listenPortText)
		if err != nil {
			return nil, fmt.Errorf("invalid trojan listen port offset: %w", err)
		}
	}

	extra := ""
	if len(segments) > 1 {
		extra = strings.Join(segments[1:], "|")
	}
	params := parseNodeExtraParams(extra)

	serverName := strings.TrimSpace(params["host"])
	if serverName == "" {
		serverName = strings.TrimSpace(params["server"])
	}
	if serverName == "" {
		serverName = connectHost
	}

	listenIP := "0.0.0.0"
	if ip := net.ParseIP(connectHost); ip != nil {
		listenIP = ip.String()
	}

	return &trojanEndpoint{
		ListenIP:    listenIP,
		ListenPort:  listenPort,
		ConnectHost: connectHost,
		ConnectPort: publicPort,
		ServerName:  serverName,
		ExtraParams: params,
	}, nil
}

func parseAnyTLSEndpoint(server string) (*anyTLSEndpoint, error) {
	parts := strings.SplitN(strings.TrimSpace(server), ";", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid anytls server format: %s", server)
	}

	connectHost := strings.TrimSpace(parts[0])
	if connectHost == "" {
		return nil, fmt.Errorf("anytls connect host is empty")
	}

	segments := strings.Split(strings.TrimSpace(parts[1]), "|")
	if len(segments) == 0 {
		return nil, fmt.Errorf("anytls server parameters are empty")
	}

	// Only the first `port=...` segment is used by server-side inbound config.
	// Extra client params like `sni` / `insecure` are intentionally ignored.
	portSegment := strings.TrimSpace(segments[0])
	if !strings.HasPrefix(strings.ToLower(portSegment), "port=") {
		return nil, fmt.Errorf("anytls server requires port=... format: %s", server)
	}
	portValue := strings.TrimSpace(portSegment[len("port="):])
	if portValue == "" {
		return nil, fmt.Errorf("anytls port value is empty")
	}

	publicPortText := portValue
	listenPortText := ""
	if idx := strings.Index(portValue, "#"); idx >= 0 {
		publicPortText = strings.TrimSpace(portValue[:idx])
		listenPortText = strings.TrimSpace(portValue[idx+1:])
	}

	publicPort, err := parsePortValue(publicPortText)
	if err != nil {
		return nil, fmt.Errorf("invalid anytls public port: %w", err)
	}
	listenPort := publicPort
	if listenPortText != "" {
		listenPort, err = parsePortValue(listenPortText)
		if err != nil {
			return nil, fmt.Errorf("invalid anytls listen port offset: %w", err)
		}
	}

	listenIP := "0.0.0.0"
	if ip := net.ParseIP(connectHost); ip != nil {
		listenIP = ip.String()
	}

	return &anyTLSEndpoint{
		ListenIP:    listenIP,
		ListenPort:  listenPort,
		ConnectHost: connectHost,
	}, nil
}

func parsePortValue(text string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", text)
	}
	return port, nil
}

func buildVMessNetworkSettings(endpoint *vmessEndpoint, acceptProxyProtocol bool) (json.RawMessage, error) {
	switch endpoint.Network {
	case "tcp":
		settings := map[string]interface{}{}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		if endpoint.SecurityMode == "http" {
			path := normalizePath(endpoint.Path)
			hosts := splitHosts(endpoint.Host)
			request := map[string]interface{}{
				"path": []string{path},
			}
			if len(hosts) > 0 {
				request["headers"] = map[string]interface{}{
					"Host": hosts,
				}
			}
			settings["header"] = map[string]interface{}{
				"type":    "http",
				"request": request,
			}
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return nil, fmt.Errorf("marshal tcp network settings error: %w", err)
		}
		return raw, nil
	case "ws":
		settings := map[string]interface{}{
			"path": normalizePath(endpoint.Path),
		}
		if acceptProxyProtocol {
			settings["acceptProxyProtocol"] = true
		}
		if hosts := splitHosts(endpoint.Host); len(hosts) > 0 {
			settings["headers"] = map[string]string{
				"Host": hosts[0],
			}
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return nil, fmt.Errorf("marshal ws network settings error: %w", err)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unsupported vmess network: %s", endpoint.Network)
	}
}

func parseNodeExtraParams(raw string) map[string]string {
	params := make(map[string]string)
	for _, segment := range strings.Split(raw, "|") {
		kv := strings.SplitN(strings.TrimSpace(segment), "=", 2)
		if len(kv) != 2 {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return params
}

func splitHosts(raw string) []string {
	var hosts []string
	for _, host := range strings.Split(raw, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
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

func chooseCertDomain(endpoint *vmessEndpoint) string {
	if hosts := splitHosts(endpoint.Host); len(hosts) > 0 {
		return hosts[0]
	}
	if endpoint.ServerName != "" {
		return endpoint.ServerName
	}
	return endpoint.ListenIP
}

func resolveCertInfo(endpoint *vmessEndpoint, client *Client, protocol string, nodeID int) *CertInfo {
	certMode := strings.ToLower(strings.TrimSpace(endpoint.ExtraParams["cert_mode"]))
	if certMode == "" {
		certMode = "self"
	}
	certDomain := chooseCertDomain(endpoint)
	certFile := strings.TrimSpace(endpoint.ExtraParams["cert_file"])
	keyFile := strings.TrimSpace(endpoint.ExtraParams["key_file"])
	keyType := strings.ToLower(strings.TrimSpace(endpoint.ExtraParams["key_type"]))
	provider := strings.TrimSpace(endpoint.ExtraParams["provider"])
	email := strings.TrimSpace(endpoint.ExtraParams["email"])
	dnsEnv := parseDNSEnv(strings.TrimSpace(endpoint.ExtraParams["dns_env"]))
	rejectUnknownSni := parseBool(endpoint.ExtraParams["reject_unknown_sni"])
	echServerKeys := strings.TrimSpace(endpoint.ExtraParams["echserverkeys"])
	if echServerKeys == "" {
		echServerKeys = strings.TrimSpace(endpoint.ExtraParams["ech_server_keys"])
	}
	echForceQuery := strings.TrimSpace(endpoint.ExtraParams["echforcequery"])
	if echForceQuery == "" {
		echForceQuery = strings.TrimSpace(endpoint.ExtraParams["ech_force_query"])
	}

	if client.CertFile != "" {
		certFile = strings.TrimSpace(client.CertFile)
	}
	if client.KeyFile != "" {
		keyFile = strings.TrimSpace(client.KeyFile)
	}

	if client.CertConfig != nil {
		local := client.CertConfig
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
				key := strings.TrimSpace(k)
				if key == "" {
					continue
				}
				dnsEnv[key] = strings.TrimSpace(v)
			}
		}
		rejectUnknownSni = local.RejectUnknownSni
		if v := strings.TrimSpace(local.EchServerKeys); v != "" {
			echServerKeys = v
		}
		if v := strings.TrimSpace(local.EchForceQuery); v != "" {
			echForceQuery = v
		}
	}
	if client.GlobalCertConfig != nil {
		if echServerKeys == "" {
			echServerKeys = strings.TrimSpace(client.GlobalCertConfig.EchServerKeys)
		}
		if echForceQuery == "" {
			echForceQuery = strings.TrimSpace(client.GlobalCertConfig.EchForceQuery)
		}
	}

	if certFile == "" {
		certFile = filepath.Join("/etc/v2node/", protocol+strconv.Itoa(nodeID)+".cer")
	}
	if keyFile == "" {
		keyFile = filepath.Join("/etc/v2node/", protocol+strconv.Itoa(nodeID)+".key")
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
		EchServerKeys:    echServerKeys,
		EchForceQuery:    echForceQuery,
	}
}

func resolveTrojanCertInfo(endpoint *trojanEndpoint, client *Client, protocol string, nodeID int) *CertInfo {
	host := strings.TrimSpace(endpoint.ServerName)
	if host == "" {
		host = strings.TrimSpace(endpoint.ConnectHost)
	}
	vmessLikeEndpoint := &vmessEndpoint{
		ListenIP:    strings.TrimSpace(endpoint.ConnectHost),
		Host:        host,
		ServerName:  host,
		ExtraParams: endpoint.ExtraParams,
	}
	return resolveCertInfo(vmessLikeEndpoint, client, protocol, nodeID)
}

func resolveAnyTLSCertInfo(endpoint *anyTLSEndpoint, client *Client, protocol string, nodeID int) *CertInfo {
	host := strings.TrimSpace(endpoint.ConnectHost)
	vmessLikeEndpoint := &vmessEndpoint{
		ListenIP:   host,
		Host:       host,
		ServerName: host,
	}
	return resolveCertInfo(vmessLikeEndpoint, client, protocol, nodeID)
}

func buildProxyProtocolNetworkSettings(acceptProxyProtocol bool) (json.RawMessage, error) {
	if !acceptProxyProtocol {
		return nil, nil
	}
	settings := map[string]interface{}{
		"acceptProxyProtocol": true,
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy protocol settings error: %w", err)
	}
	return raw, nil
}

func buildNodeFallbackObject(src *FallbackObject) (*FallbackObject, error) {
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

func resolveGlobalCertInfo(client *Client, defaultDomain string) *CertInfo {
	if client == nil || client.GlobalCertConfig == nil {
		return nil
	}
	global := client.GlobalCertConfig
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
		EchServerKeys:    strings.TrimSpace(global.EchServerKeys),
		EchForceQuery:    strings.TrimSpace(global.EchForceQuery),
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

func parseDNSEnv(raw string) map[string]string {
	out := map[string]string{}
	for _, segment := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(segment), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k != "" {
			out[k] = v
		}
	}
	return out
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
	sort.Strings(keys)
	segments := make([]string, 0, len(keys))
	for _, k := range keys {
		segments = append(segments, fmt.Sprintf("%s=%s", k, strings.TrimSpace(env[k])))
	}
	return strings.Join(segments, ",")
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func boolToString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
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

func (c *Client) getDetectRoutes() ([]Route, bool, error) {
	const path = "/mod_mu/func/detect_rules"
	r, err := c.client.R().
		SetHeader("If-None-Match", c.detectRuleEtag).
		Get(path)
	if err != nil {
		return cloneRoutes(c.cachedRoutes), false, err
	}
	if r == nil {
		return cloneRoutes(c.cachedRoutes), false, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return cloneRoutes(c.cachedRoutes), false, nil
	}
	if r.StatusCode() >= 400 {
		return cloneRoutes(c.cachedRoutes), false, fmt.Errorf("get detect rules failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	c.detectRuleEtag = r.Header().Get("ETag")
	if c.detectRuleHash == newBodyHash {
		return cloneRoutes(c.cachedRoutes), false, nil
	}
	resp := &modMUDetectRulesResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return cloneRoutes(c.cachedRoutes), false, fmt.Errorf("decode mod_mu detect rules error: %w", err)
	}
	if resp.Ret != 1 {
		return cloneRoutes(c.cachedRoutes), false, fmt.Errorf("mod_mu detect rules ret=%d, body=%s", resp.Ret, string(r.Body()))
	}
	routes := parseDetectRulesToRoutes(resp.Data)
	c.detectRuleHash = newBodyHash
	c.cachedRoutes = routes
	return cloneRoutes(routes), true, nil
}

func parseDetectRulesToRoutes(rawRules []json.RawMessage) []Route {
	routes := make([]Route, 0, len(rawRules))
	seen := make(map[string]struct{}, len(rawRules))
	for _, rawRule := range rawRules {
		id, pattern := parseDetectRulePattern(rawRule)
		if normalized, ok := normalizeDetectPattern(pattern); ok {
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
	return routes
}

func parseDetectRulePattern(raw json.RawMessage) (int, string) {
	var direct string
	if err := json.Unmarshal(raw, &direct); err == nil {
		return 0, strings.TrimSpace(direct)
	}
	var row map[string]interface{}
	if err := json.Unmarshal(raw, &row); err != nil {
		return 0, ""
	}
	id := intFromAny(row["id"])
	pattern := firstNonEmpty(
		stringFromAny(row["regex"]),
		stringFromAny(row["regexp"]),
		stringFromAny(row["pattern"]),
		stringFromAny(row["rule"]),
		stringFromAny(row["value"]),
		stringFromAny(row["name"]),
	)
	return id, pattern
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

func cloneNodeData(src *modMUNodeData) *modMUNodeData {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
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
