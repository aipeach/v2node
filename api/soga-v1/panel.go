package panel

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	sspanel "github.com/wyx2685/v2node/api/sspanel"
	"github.com/wyx2685/v2node/conf"
)

const PanelTypeSogaV1 = "soga-v1"

type Client struct {
	client *resty.Client

	APIHost        string
	Token          string
	NodeId         int
	NodeTypeRaw    string
	NodeType       string
	NodeTypeHeader string

	ListenIP             string
	SSObfsUDP            bool
	EnableFallback       bool
	FallbackObject       *conf.FallbackObject
	CertConfig           *conf.CertConfig
	GlobalCertConfig     *conf.CertConfig
	CertFile             string
	KeyFile              string
	AcceptProxyProto     bool
	startedAt            time.Time
	lastCPUIdle          uint64
	lastCPUTotal         uint64
	hasCPUStat           bool
	nodeEtag             string
	nodeBodyHash         string
	userEtag             string
	auditRuleEtag        string
	auditRuleBodyHash    string
	whiteListEtag        string
	whiteListBodyHash    string
	xrayRulesEtag        string
	cachedXrayRules      *sspanel.XrayRules
	effectiveXrayRules   *sspanel.XrayRules
	xrayRulesCachePath   string
	xrayRulesCacheLoaded bool
	cachedNodeData       *sogaNodeData
	cachedRoutes         []sspanel.Route
	cachedWhiteList      []string
	AliveMap             *sspanel.AliveMap
}

func New(c *conf.NodeConfig) (*Client, error) {
	client := resty.New()
	client.SetRetryCount(3)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			logrus.Error(v.Err)
		}
	})

	baseURL := strings.TrimSpace(c.APIHost)
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	client.SetBaseURL(baseURL)

	rawNodeType := strings.ToLower(strings.TrimSpace(c.NodeType))
	if rawNodeType == "" {
		rawNodeType = "vmess"
	}
	nodeType := normalizeNodeType(rawNodeType)
	headerType := nodeTypeToHeader(rawNodeType, nodeType)
	client.SetHeaders(map[string]string{
		"API-KEY":   strings.TrimSpace(c.Key),
		"NODE-ID":   strconv.Itoa(c.NodeID),
		"NODE-TYPE": headerType,
	})

	return &Client{
		client:             client,
		APIHost:            c.APIHost,
		Token:              c.Key,
		NodeId:             c.NodeID,
		NodeTypeRaw:        rawNodeType,
		NodeType:           nodeType,
		NodeTypeHeader:     headerType,
		ListenIP:           c.ListenIP,
		SSObfsUDP:          c.SSObfsUDP,
		EnableFallback:     c.EnableFallback,
		FallbackObject:     cloneConfigFallbackObject(c.FallbackObject),
		CertConfig:         cloneCertConfig(c.CertConfig),
		GlobalCertConfig:   cloneCertConfig(c.GlobalCertConfig),
		CertFile:           strings.TrimSpace(c.CertFile),
		KeyFile:            strings.TrimSpace(c.KeyFile),
		AcceptProxyProto:   c.AcceptProxyProtocol,
		xrayRulesCachePath: buildXrayRulesCachePath(c.APIHost, c.NodeID, headerType),
		startedAt:          time.Now(),
		AliveMap:           &sspanel.AliveMap{Alive: map[int]int{}},
	}, nil
}

func normalizeNodeType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "vmess":
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "ssr", "shadowsocksr":
		return "shadowsocksr"
	case "hysteria", "hysteria2":
		return "hysteria2"
	case "anytls":
		return "anytls"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func nodeTypeToHeader(rawNodeType string, nodeType string) string {
	rawNodeType = strings.ToLower(strings.TrimSpace(rawNodeType))
	switch nodeType {
	case "hysteria2":
		return "hysteria"
	case "shadowsocksr":
		if rawNodeType == "ssr" || rawNodeType == "shadowsocksr" {
			return rawNodeType
		}
		return "shadowsocksr"
	case "shadowsocks":
		if rawNodeType == "ss" || rawNodeType == "shadowsocks" {
			return rawNodeType
		}
		return "shadowsocks"
	default:
		return nodeType
	}
}

func cloneConfigFallbackObject(src *conf.FallbackObject) *conf.FallbackObject {
	if src == nil {
		return nil
	}
	dst := *src
	return &dst
}

func cloneCertConfig(src *conf.CertConfig) *conf.CertConfig {
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
