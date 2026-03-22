package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"gopkg.in/yaml.v3"
)

const auditRuleTagPrefix = "audit:"
const auditWhiteListAllowOutboundTag = "Default"

var privateIPCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func buildBaseOutbounds(c *conf.Conf) ([]*core.OutboundHandlerConfig, error) {
	autoOutIP := c != nil && c.AutoOutIP
	if c != nil && strings.TrimSpace(c.Outbounds.File) != "" {
		return loadOutboundsConfig(c.Outbounds.File, autoOutIP)
	}
	defaultOutbound, err := buildDefaultOutbound(autoOutIP)
	if err != nil {
		return nil, err
	}
	blockOutbound, err := buildBlockOutbound()
	if err != nil {
		return nil, err
	}
	dnsOutbound, err := buildDnsOutbound()
	if err != nil {
		return nil, err
	}
	return []*core.OutboundHandlerConfig{defaultOutbound, blockOutbound, dnsOutbound}, nil
}

func buildDefaultRoutingConfig() *coreConf.RouterConfig {
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	return &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}
}

func buildBaseRouting(c *conf.Conf) (*coreConf.RouterConfig, error) {
	if c != nil && strings.TrimSpace(c.Routing.File) != "" {
		return loadRoutingConfig(c.Routing.File)
	}
	return buildDefaultRoutingConfig(), nil
}

func GetCustomConfig(c *conf.Conf, infos []*panel.NodeInfo) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	geoData := newGeoDataResolver(c)
	auditWhiteList, err := loadAuditWhiteListConfig(c)
	if err != nil {
		return nil, nil, nil, err
	}
	//dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
	if c != nil && strings.TrimSpace(c.DNS.File) != "" {
		customDNSConfig, err := loadDNSConfig(c.DNS.File)
		if err != nil {
			return nil, nil, nil, err
		}
		coreDnsConfig = customDNSConfig
		if strings.TrimSpace(coreDnsConfig.QueryStrategy) == "" {
			coreDnsConfig.QueryStrategy = queryStrategy
		}
		if len(coreDnsConfig.Servers) == 0 {
			coreDnsConfig.Servers = []*coreConf.NameServerConfig{
				{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress("localhost"),
					},
				},
			}
		}
	}
	//outbound
	coreOutboundConfig, err := buildBaseOutbounds(c)
	if err != nil {
		return nil, nil, nil, err
	}

	//route
	coreRouterConfig, err := buildBaseRouting(c)
	if err != nil {
		return nil, nil, nil, err
	}
	inboundTags := collectInboundTags(infos)
	if len(inboundTags) > 0 {
		forbiddenPorts := parseAuditWhiteListPortRules("")
		if c != nil {
			forbiddenPorts = parseAuditWhiteListPortRules(c.ForbiddenPorts)
		}
		appendForbiddenPortRules(coreRouterConfig, inboundTags, forbiddenPorts)
		if c != nil && c.BanPrivateIP {
			appendBanPrivateIPRules(coreRouterConfig, inboundTags)
		}
		if c != nil && c.ForbiddenBitTorrent {
			appendForbiddenProtocolRules(coreRouterConfig, inboundTags, []string{"bittorrent"})
		}
	}

	for _, info := range infos {
		if info == nil || info.Common == nil || len(info.Common.Routes) == 0 {
			continue
		}
		mergedAuditWhiteList := mergeAuditWhiteListConfig(auditWhiteList, info.Common.AuditWhiteList)
		auditWhiteListAppended := false
		for _, route := range info.Common.Routes {
			if route.DetectRule && !auditWhiteListAppended {
				appendAuditWhiteListRules(coreRouterConfig, info.Tag, mergedAuditWhiteList, geoData)
				auditWhiteListAppended = true
			}
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					continue
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				domains := sanitizeDomainRules(route.Match, geoData)
				if len(route.Match) > 0 && len(domains) == 0 {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      domains,
					"outboundTag": "block",
				}
				if route.DetectRule && route.Id > 0 {
					rule["ruleTag"] = auditRuleTagPrefix + strconv.Itoa(route.Id)
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				ips := sanitizeIPRules(route.Match, geoData)
				if len(route.Match) > 0 && len(ips) == 0 {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          ips,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				if route.ActionValue == nil {
					continue
				}
				domains := sanitizeDomainRules(route.Match, geoData)
				if len(route.Match) > 0 && len(domains) == 0 {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      domains,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_ip":
				if route.ActionValue == nil {
					continue
				}
				ips := sanitizeIPRules(route.Match, geoData)
				if len(route.Match) > 0 && len(ips) == 0 {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          ips,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "default_out":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			default:
				continue
			}
		}
	}
	coreDnsConfig = sanitizeDNSConfig(coreDnsConfig, geoData)
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}

type geoDataResolver struct {
	geositeFile string
	geoipFile   string
	hasGeosite  bool
	hasGeoip    bool
}

type auditWhiteListConfig struct {
	DomainRules []string
	IPRules     []string
	PortRules   []string
}

func newGeoDataResolver(c *conf.Conf) geoDataResolver {
	resolver := geoDataResolver{}
	if c == nil {
		return resolver
	}
	resolver.geositeFile = strings.TrimSpace(c.GeositeFile)
	resolver.geoipFile = strings.TrimSpace(c.GeoipFile)
	if resolver.geositeFile != "" {
		if fi, err := os.Stat(resolver.geositeFile); err == nil && !fi.IsDir() {
			resolver.hasGeosite = true
		}
	}
	if resolver.geoipFile != "" {
		if fi, err := os.Stat(resolver.geoipFile); err == nil && !fi.IsDir() {
			resolver.hasGeoip = true
		}
	}
	return resolver
}

func sanitizeDNSConfig(cfg *coreConf.DNSConfig, resolver geoDataResolver) *coreConf.DNSConfig {
	if cfg == nil {
		return cfg
	}
	if len(cfg.Servers) > 0 {
		servers := make([]*coreConf.NameServerConfig, 0, len(cfg.Servers))
		for _, server := range cfg.Servers {
			if server == nil {
				continue
			}
			originalDomains := len(server.Domains)
			server.Domains = sanitizeDomainRules(server.Domains, resolver)
			if originalDomains > 0 && len(server.Domains) == 0 {
				continue
			}
			server.ExpectedIPs = coreConf.StringList(sanitizeIPRules([]string(server.ExpectedIPs), resolver))
			server.ExpectIPs = coreConf.StringList(sanitizeIPRules([]string(server.ExpectIPs), resolver))
			server.UnexpectedIPs = coreConf.StringList(sanitizeIPRules([]string(server.UnexpectedIPs), resolver))
			servers = append(servers, server)
		}
		cfg.Servers = servers
	}
	if cfg.Hosts != nil && cfg.Hosts.Hosts != nil {
		hosts := make(map[string]*coreConf.HostAddress, len(cfg.Hosts.Hosts))
		for domain, hostAddr := range cfg.Hosts.Hosts {
			domain, ok := rewriteDomainRule(domain, resolver)
			if !ok {
				continue
			}
			hosts[domain] = hostAddr
		}
		cfg.Hosts.Hosts = hosts
	}
	return cfg
}

func sanitizeDomainRules(rules []string, resolver geoDataResolver) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule, ok := rewriteDomainRule(rule, resolver)
		if !ok {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func sanitizeIPRules(rules []string, resolver geoDataResolver) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule, ok := rewriteIPRule(rule, resolver)
		if !ok {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func rewriteDomainRule(rule string, resolver geoDataResolver) (string, bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", false
	}
	lowerRule := strings.ToLower(rule)
	if strings.HasPrefix(lowerRule, "geosite:") {
		if !resolver.hasGeosite {
			return "", false
		}
		return "ext:" + resolver.geositeFile + ":" + rule[len("geosite:"):], true
	}
	return rule, true
}

func rewriteIPRule(rule string, resolver geoDataResolver) (string, bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", false
	}
	lowerRule := strings.ToLower(rule)
	if strings.HasPrefix(lowerRule, "geoip:") {
		if !resolver.hasGeoip {
			return "", false
		}
		return "ext:" + resolver.geoipFile + ":" + rule[len("geoip:"):], true
	}
	return rule, true
}

func loadAuditWhiteListConfig(c *conf.Conf) (auditWhiteListConfig, error) {
	cfg := auditWhiteListConfig{}
	if c == nil {
		return cfg, nil
	}
	filePath := strings.TrimSpace(c.AuditWhiteListFile)
	if filePath == "" {
		return cfg, nil
	}
	rawBytes, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read audit whitelist file %s error: %w", filePath, err)
	}
	rawBytes = bytes.TrimPrefix(rawBytes, []byte{0xEF, 0xBB, 0xBF})
	content := strings.ReplaceAll(string(rawBytes), "\r\n", "\n")
	for _, line := range strings.Split(content, "\n") {
		parseAuditWhiteListLine(line, &cfg)
	}
	cfg.DomainRules = dedupeStrings(cfg.DomainRules)
	cfg.IPRules = dedupeStrings(cfg.IPRules)
	cfg.PortRules = dedupeStrings(cfg.PortRules)
	return cfg, nil
}

func parseAuditWhiteListLine(line string, cfg *auditWhiteListConfig) {
	if cfg == nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return
	}
	line = stripInlineHashComment(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return
	}
	lowerLine := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lowerLine, "regexp:"):
		pattern := strings.TrimSpace(line[len("regexp:"):])
		if pattern == "" {
			return
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return
		}
		cfg.DomainRules = append(cfg.DomainRules, "regexp:"+pattern)
	case strings.HasPrefix(lowerLine, "domain:"):
		value := strings.TrimSpace(line[len("domain:"):])
		if value == "" {
			return
		}
		cfg.DomainRules = append(cfg.DomainRules, "domain:"+value)
	case strings.HasPrefix(lowerLine, "full:"):
		value := strings.TrimSpace(line[len("full:"):])
		if value == "" {
			return
		}
		cfg.DomainRules = append(cfg.DomainRules, "full:"+value)
	case strings.HasPrefix(lowerLine, "geosite:"):
		value := strings.TrimSpace(line[len("geosite:"):])
		if value == "" {
			return
		}
		cfg.DomainRules = append(cfg.DomainRules, "geosite:"+value)
	case strings.HasPrefix(lowerLine, "geoip:"):
		value := strings.TrimSpace(line[len("geoip:"):])
		if value == "" {
			return
		}
		cfg.IPRules = append(cfg.IPRules, "geoip:"+value)
	case strings.HasPrefix(lowerLine, "ip:"):
		value := strings.TrimSpace(line[len("ip:"):])
		cfg.IPRules = append(cfg.IPRules, parseAuditWhiteListIPRules(value)...)
	case strings.HasPrefix(lowerLine, "port:"):
		value := strings.TrimSpace(line[len("port:"):])
		cfg.PortRules = append(cfg.PortRules, parseAuditWhiteListPortRules(value)...)
	default:
		cfg.DomainRules = append(cfg.DomainRules, line)
	}
}

func stripInlineHashComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		// Keep literal '#' in tokens like regexp:a#b, only treat whitespace-prefixed '#' as comment.
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func parseAuditWhiteListIPRules(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			out = append(out, part)
			continue
		}
		if _, _, err := net.ParseCIDR(part); err == nil {
			out = append(out, part)
		}
	}
	return out
}

func parseAuditWhiteListPortRules(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				continue
			}
			start, errStart := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, errEnd := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if errStart != nil || errEnd != nil || start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
				continue
			}
			out = append(out, strconv.Itoa(start)+"-"+strconv.Itoa(end))
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value <= 0 || value > 65535 {
			continue
		}
		out = append(out, strconv.Itoa(value))
	}
	return out
}

func dedupeStrings(values []string) []string {
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
	return out
}

func mergeAuditWhiteListConfig(base auditWhiteListConfig, extra []string) auditWhiteListConfig {
	merged := auditWhiteListConfig{
		DomainRules: append([]string(nil), base.DomainRules...),
		IPRules:     append([]string(nil), base.IPRules...),
		PortRules:   append([]string(nil), base.PortRules...),
	}
	for _, line := range extra {
		parseAuditWhiteListLine(line, &merged)
	}
	merged.DomainRules = dedupeStrings(merged.DomainRules)
	merged.IPRules = dedupeStrings(merged.IPRules)
	merged.PortRules = dedupeStrings(merged.PortRules)
	return merged
}

func appendAuditWhiteListRules(coreRouterConfig *coreConf.RouterConfig, inboundTag string, rules auditWhiteListConfig, resolver geoDataResolver) {
	if coreRouterConfig == nil || strings.TrimSpace(inboundTag) == "" {
		return
	}
	domainRules := sanitizeDomainRules(rules.DomainRules, resolver)
	if len(domainRules) > 0 {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"domain":      domainRules,
			"outboundTag": auditWhiteListAllowOutboundTag,
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
	ipRules := sanitizeIPRules(rules.IPRules, resolver)
	if len(ipRules) > 0 {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"ip":          ipRules,
			"outboundTag": auditWhiteListAllowOutboundTag,
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
	if len(rules.PortRules) > 0 {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"port":        strings.Join(rules.PortRules, ","),
			"outboundTag": auditWhiteListAllowOutboundTag,
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
}

func collectInboundTags(infos []*panel.NodeInfo) []string {
	if len(infos) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(infos))
	tags := make([]string, 0, len(infos))
	for _, info := range infos {
		if info == nil {
			continue
		}
		tag := strings.TrimSpace(info.Tag)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	return tags
}

func appendForbiddenPortRules(coreRouterConfig *coreConf.RouterConfig, inboundTags []string, ports []string) {
	if coreRouterConfig == nil || len(inboundTags) == 0 || len(ports) == 0 {
		return
	}
	portExpr := strings.Join(ports, ",")
	for _, inboundTag := range inboundTags {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"port":        portExpr,
			"outboundTag": "block",
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
}

func appendBanPrivateIPRules(coreRouterConfig *coreConf.RouterConfig, inboundTags []string) {
	if coreRouterConfig == nil || len(inboundTags) == 0 {
		return
	}
	for _, inboundTag := range inboundTags {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"ip":          privateIPCIDRs,
			"outboundTag": "block",
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
}

func appendForbiddenProtocolRules(coreRouterConfig *coreConf.RouterConfig, inboundTags []string, protocols []string) {
	if coreRouterConfig == nil || len(inboundTags) == 0 || len(protocols) == 0 {
		return
	}
	for _, inboundTag := range inboundTags {
		rule := map[string]interface{}{
			"inboundTag":  inboundTag,
			"protocol":    protocols,
			"outboundTag": "block",
		}
		if rawRule, err := json.Marshal(rule); err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}
}

type outboundsFileConfig struct {
	Outbounds []*coreConf.OutboundDetourConfig `json:"outbounds"`
}

type routingFileConfig struct {
	Routing *coreConf.RouterConfig `json:"routing"`
}

func readConfigFile(filePath string) ([]byte, error) {
	rawBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	// Handle UTF-8 BOM to avoid parser errors for files edited on some platforms.
	return bytes.TrimPrefix(rawBytes, []byte{0xEF, 0xBB, 0xBF}), nil
}

func unmarshalJSONOrYAML(rawBytes []byte, out interface{}) error {
	// Try JSON first.
	if err := json.Unmarshal(rawBytes, out); err == nil {
		return nil
	}
	// Fallback to YAML, then convert to JSON and unmarshal using xray's JSON rules.
	var yamlObj interface{}
	if err := yaml.Unmarshal(rawBytes, &yamlObj); err != nil {
		return err
	}
	rawJSON, err := json.Marshal(normalizeYAMLObject(yamlObj))
	if err != nil {
		return err
	}
	return json.Unmarshal(rawJSON, out)
}

func loadDNSConfig(filePath string) (*coreConf.DNSConfig, error) {
	rawBytes, err := readConfigFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read dns config file error: %w", err)
	}
	cfg := &coreConf.DNSConfig{}
	if err := unmarshalJSONOrYAML(rawBytes, cfg); err != nil {
		return nil, fmt.Errorf("parse dns config file %s error: %w", filePath, err)
	}
	return cfg, nil
}

func loadRoutingConfig(filePath string) (*coreConf.RouterConfig, error) {
	rawBytes, err := readConfigFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read routing config file error: %w", err)
	}
	cfg := &coreConf.RouterConfig{}
	if err := unmarshalJSONOrYAML(rawBytes, cfg); err != nil {
		return nil, fmt.Errorf("parse routing config file %s error: %w", filePath, err)
	}
	if isRouterConfigEmpty(cfg) {
		wrapped := routingFileConfig{}
		if err := unmarshalJSONOrYAML(rawBytes, &wrapped); err == nil && wrapped.Routing != nil {
			cfg = wrapped.Routing
		}
	}
	if cfg.RuleList == nil {
		cfg.RuleList = []json.RawMessage{}
	}
	if cfg.DomainStrategy == nil || strings.TrimSpace(*cfg.DomainStrategy) == "" {
		domainStrategy := "AsIs"
		cfg.DomainStrategy = &domainStrategy
	}
	return cfg, nil
}

func loadOutboundsConfig(filePath string, autoOutIP bool) ([]*core.OutboundHandlerConfig, error) {
	rawBytes, err := readConfigFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read outbounds config file error: %w", err)
	}
	var outbounds []*coreConf.OutboundDetourConfig
	if err := unmarshalJSONOrYAML(rawBytes, &outbounds); err != nil {
		wrapped := outboundsFileConfig{}
		if wrapErr := unmarshalJSONOrYAML(rawBytes, &wrapped); wrapErr != nil {
			return nil, fmt.Errorf("parse outbounds config file %s error: %w", filePath, err)
		}
		outbounds = wrapped.Outbounds
	}
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("outbounds config file %s has no outbounds", filePath)
	}
	result := make([]*core.OutboundHandlerConfig, 0, len(outbounds))
	for i, outbound := range outbounds {
		if outbound == nil {
			continue
		}
		applyAutoOutIPToOutbound(outbound, autoOutIP)
		built, err := outbound.Build()
		if err != nil {
			return nil, fmt.Errorf("build outbounds config file %s item %d error: %w", filePath, i, err)
		}
		result = append(result, built)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("outbounds config file %s has no valid outbounds", filePath)
	}
	return result, nil
}

func applyAutoOutIPToOutbound(outbound *coreConf.OutboundDetourConfig, autoOutIP bool) {
	if !autoOutIP || outbound == nil {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(outbound.Protocol), "freedom") {
		return
	}
	if outbound.SendThrough != nil && strings.TrimSpace(*outbound.SendThrough) != "" {
		return
	}
	sendThrough := "origin"
	outbound.SendThrough = &sendThrough
}

func isRouterConfigEmpty(cfg *coreConf.RouterConfig) bool {
	if cfg == nil {
		return true
	}
	if len(cfg.RuleList) > 0 {
		return false
	}
	if len(cfg.Balancers) > 0 {
		return false
	}
	return cfg.DomainStrategy == nil || strings.TrimSpace(*cfg.DomainStrategy) == ""
}

func normalizeYAMLObject(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, inner := range val {
			out[k] = normalizeYAMLObject(inner)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, inner := range val {
			out[fmt.Sprint(k)] = normalizeYAMLObject(inner)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, inner := range val {
			out[i] = normalizeYAMLObject(inner)
		}
		return out
	default:
		return val
	}
}
