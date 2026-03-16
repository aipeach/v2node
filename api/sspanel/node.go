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
	Protocol   string      `json:"protocol"`
	ListenIP   string      `json:"listen_ip"`
	ServerPort int         `json:"server_port"`
	Routes     []Route     `json:"routes"`
	BaseConfig *BaseConfig `json:"base_config"`
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
	//shadowsocks
	Cipher    string `json:"cipher"`
	ServerKey string `json:"server_key"`
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

type BaseConfig struct {
	PushInterval           any `json:"push_interval"`
	PullInterval           any `json:"pull_interval"`
	DeviceOnlineMinTraffic int `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int `json:"node_report_min_traffic"`
}

type TlsSettings struct {
	ServerName       string `json:"server_name"`
	Dest             string `json:"dest"`
	ServerPort       string `json:"server_port"`
	ShortId          string `json:"short_id"`
	PrivateKey       string `json:"private_key"`
	Mldsa65Seed      string `json:"mldsa65Seed"`
	Xver             uint64 `json:"xver,string"`
	CertMode         string `json:"cert_mode"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	KeyType          string `json:"key_type"`
	Provider         string `json:"provider"`
	DNSEnv           string `json:"dns_env"`
	RejectUnknownSni string `json:"reject_unknown_sni"`
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
}

type EncSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
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
	case protocol == "vmess":
		return buildModMUVmessNodeInfo(client, data, routes)
	case isSSR:
		return buildModMUSSRNodeInfo(client, data, routes, selectedMode)
	default:
		return nil, fmt.Errorf("unsupported node type from config: %s", protocol)
	}
}

func buildModMUVmessNodeInfo(client *Client, data *modMUNodeData, routes []Route) (*NodeInfo, error) {
	nodeID := client.NodeId
	protocol := "vmess"
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

	node := &NodeInfo{
		Id:           nodeID,
		Type:         protocol,
		Security:     None,
		PushInterval: time.Duration(interval) * time.Second,
		PullInterval: time.Duration(interval) * time.Second,
		Tag:          fmt.Sprintf("[%s]-%s:%d", client.APIHost, protocol, nodeID),
		Common:       common,
	}

	if endpoint.SecurityMode == "tls" {
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
		ServerName:   strings.TrimSpace(params["server"]),
		ExtraParams:  params,
	}, nil
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
	email := firstNonEmpty(endpoint.ExtraParams["email"], "node@sspanel.local")
	dnsEnv := parseDNSEnv(strings.TrimSpace(endpoint.ExtraParams["dns_env"]))
	rejectUnknownSni := parseBool(endpoint.ExtraParams["reject_unknown_sni"])

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
	}
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
	if email == "" {
		email = "node@sspanel.local"
	}
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
