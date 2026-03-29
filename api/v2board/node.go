package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

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
	BaseConfig     *BaseConfig `json:"base_config"`

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

	Cipher                string `json:"cipher"`
	ServerKey             string `json:"server_key"`
	SSSinglePortMultiUser bool   `json:"ss_single_port_multi_user"`

	SSRMethod        string `json:"ssr_method"`
	SSRPassword      string `json:"ssr_password"`
	SSRMultiUserMode string `json:"ssr_multi_user_mode"`
	SSRProtocol      string `json:"ssr_protocol"`
	SSRProtocolParam string `json:"ssr_protocol_param"`
	SSROBFS          string `json:"ssr_obfs"`
	SSROBFSParam     string `json:"ssr_obfs_param"`
	SSObfsUDP        bool   `json:"ss_obfs_udp"`

	CongestionControl string `json:"congestion_control"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`

	PaddingScheme []string `json:"padding_scheme,omitempty"`

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
	EchServerKeys    string `json:"echServerKeys"`
	EchForceQuery    string `json:"echForceQuery"`
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

type FallbackObject struct {
	Name string `json:"name"`
	Alpn string `json:"alpn"`
	Path string `json:"path"`
	Dest int    `json:"dest"`
	Xver int    `json:"xver"`
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	if c != nil && c.sspanelClient != nil {
		info, err := c.sspanelClient.GetNodeInfo()
		if err != nil {
			return nil, err
		}
		return cloneNodeInfoFromSSPanel(info), nil
	}
	if c != nil && c.sogaClient != nil {
		info, err := c.sogaClient.GetNodeInfo()
		if err != nil {
			return nil, err
		}
		return cloneNodeInfoFromSSPanel(info), nil
	}

	const path = "/api/v2/server/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.StatusCode() == 304 {
		return nil, nil
	}
	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("get node config failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.nodeEtag = r.Header().Get("ETag")

	node = &NodeInfo{Id: c.NodeId}

	cm := &CommonNode{}
	if err := json.Unmarshal(r.Body(), cm); err != nil {
		return nil, fmt.Errorf("decode node config error: %s", err)
	}

	switch cm.Protocol {
	case "vmess", "trojan", "hysteria2", "tuic", "anytls", "vless":
		node.Type = cm.Protocol
		node.Security = cm.Tls
	case "shadowsocks", "shadowsocksr", "ssr":
		node.Type = cm.Protocol
		node.Security = None
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cm.Protocol)
	}

	node.Tag = fmt.Sprintf("[%s]-%s:%d", c.APIHost, node.Type, node.Id)

	cf := cm.TlsSettings.CertFile
	kf := cm.TlsSettings.KeyFile
	if cf == "" {
		cf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".cer")
	}
	if kf == "" {
		kf = filepath.Join("/etc/v2node/", cm.Protocol+strconv.Itoa(c.NodeId)+".key")
	}

	certInfo := &CertInfo{
		CertMode:         cm.TlsSettings.CertMode,
		CertFile:         cf,
		KeyFile:          kf,
		KeyType:          cm.TlsSettings.KeyType,
		Email:            "node@v2board.com",
		CertDomain:       cm.TlsSettings.ServerName,
		DNSEnv:           make(map[string]string),
		Provider:         cm.TlsSettings.Provider,
		RejectUnknownSni: cm.TlsSettings.RejectUnknownSni == "1",
	}
	if certInfo.CertMode == "dns" && cm.TlsSettings.DNSEnv != "" {
		envs := strings.Split(cm.TlsSettings.DNSEnv, ",")
		for _, env := range envs {
			kv := strings.SplitN(env, "=", 2)
			if len(kv) == 2 {
				certInfo.DNSEnv[kv[0]] = kv[1]
			}
		}
	}

	cm.CertInfo = certInfo

	if cm.BaseConfig == nil {
		cm.BaseConfig = &BaseConfig{}
	}
	node.PushInterval = intervalToTime(cm.BaseConfig.PushInterval)
	node.PullInterval = intervalToTime(cm.BaseConfig.PullInterval)

	node.Common = cm
	return node, nil
}

func intervalToTime(i interface{}) time.Duration {
	if i == nil {
		return 0
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}
