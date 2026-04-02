package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	sspanel "github.com/wyx2685/v2node/api/sspanel"
)

const sogaXrayRulesCacheDir = "/etc/v2node"

type sogaXrayRulesResponse struct {
	DNS       json.RawMessage `json:"dns"`
	Routing   json.RawMessage `json:"routing"`
	Outbounds json.RawMessage `json:"outbounds"`
}

type sogaXrayRulesCache struct {
	ETag  string             `json:"etag,omitempty"`
	Rules *sspanel.XrayRules `json:"rules,omitempty"`
}

func buildXrayRulesCachePath(apiHost string, nodeID int, nodeTypeHeader string) string {
	cacheKey := fmt.Sprintf("%s|%d|%s", strings.TrimSpace(apiHost), nodeID, strings.ToLower(strings.TrimSpace(nodeTypeHeader)))
	hash := sha256.Sum256([]byte(cacheKey))
	shortHash := hex.EncodeToString(hash[:8])
	fileName := fmt.Sprintf("soga-v1-xray-rules-%d-%s.json", nodeID, shortHash)
	return filepath.Join(sogaXrayRulesCacheDir, fileName)
}

func (c *Client) refreshXrayRules() (bool, error) {
	if err := c.ensureXrayRulesCacheLoaded(); err != nil {
		log.WithError(err).WithField("path", c.xrayRulesCachePath).Warn("load xray rules cache failed")
	}

	previous := cloneXrayRules(c.effectiveXrayRules)

	req := c.client.R().ForceContentType("application/json")
	if etag := strings.TrimSpace(c.xrayRulesEtag); etag != "" {
		req.SetHeader("If-None-Match", etag)
	}

	r, err := req.Get("api/v1/xray_rules")
	if err != nil {
		c.effectiveXrayRules = nil
		return !xrayRulesEqual(previous, c.effectiveXrayRules), err
	}
	if r == nil {
		c.effectiveXrayRules = nil
		return !xrayRulesEqual(previous, c.effectiveXrayRules), fmt.Errorf("received nil response")
	}

	switch {
	case r.StatusCode() == 304:
		c.applyCachedXrayRulesAsEffective()
		return !xrayRulesEqual(previous, c.effectiveXrayRules), nil
	case r.StatusCode() >= 400:
		c.effectiveXrayRules = nil
		return !xrayRulesEqual(previous, c.effectiveXrayRules), fmt.Errorf("get xray rules failed with status %d: %s", r.StatusCode(), string(r.Body()))
	default:
		rules, err := parseSogaXrayRules(r.Body())
		if err != nil {
			c.effectiveXrayRules = nil
			return !xrayRulesEqual(previous, c.effectiveXrayRules), fmt.Errorf("decode xray rules error: %w", err)
		}
		c.xrayRulesEtag = strings.TrimSpace(r.Header().Get("ETag"))
		c.cachedXrayRules = normalizeXrayRules(rules)
		c.applyCachedXrayRulesAsEffective()
		if err := c.persistXrayRulesCache(); err != nil {
			log.WithError(err).WithField("path", c.xrayRulesCachePath).Warn("persist xray rules cache failed")
		}
		return !xrayRulesEqual(previous, c.effectiveXrayRules), nil
	}
}

func (c *Client) ensureXrayRulesCacheLoaded() error {
	if c == nil || c.xrayRulesCacheLoaded {
		return nil
	}
	c.xrayRulesCacheLoaded = true

	path := strings.TrimSpace(c.xrayRulesCachePath)
	if path == "" {
		return nil
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	rawBytes = bytes.TrimPrefix(rawBytes, []byte{0xEF, 0xBB, 0xBF})

	cached := &sogaXrayRulesCache{}
	if err := json.Unmarshal(rawBytes, cached); err != nil {
		return err
	}
	c.xrayRulesEtag = strings.TrimSpace(cached.ETag)
	c.cachedXrayRules = normalizeXrayRules(cached.Rules)
	return nil
}

func (c *Client) applyCachedXrayRulesAsEffective() {
	if hasXrayRules(c.cachedXrayRules) {
		c.effectiveXrayRules = cloneXrayRules(c.cachedXrayRules)
		return
	}
	c.effectiveXrayRules = nil
}

func (c *Client) persistXrayRulesCache() error {
	if c == nil {
		return nil
	}
	path := strings.TrimSpace(c.xrayRulesCachePath)
	if path == "" {
		return nil
	}
	payload, err := json.Marshal(&sogaXrayRulesCache{
		ETag:  strings.TrimSpace(c.xrayRulesEtag),
		Rules: cloneXrayRules(c.cachedXrayRules),
	})
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload)
}

func parseSogaXrayRules(rawBytes []byte) (*sspanel.XrayRules, error) {
	rawBytes = bytes.TrimSpace(rawBytes)
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	payload := &sogaXrayRulesResponse{}
	if err := json.Unmarshal(rawBytes, payload); err != nil {
		return nil, err
	}

	dnsRaw, err := normalizeRuleSection(payload.DNS, true)
	if err != nil {
		return nil, fmt.Errorf("invalid dns field: %w", err)
	}
	routingRaw, err := normalizeRuleSection(payload.Routing, true)
	if err != nil {
		return nil, fmt.Errorf("invalid routing field: %w", err)
	}
	outboundsRaw, err := normalizeRuleSection(payload.Outbounds, false)
	if err != nil {
		return nil, fmt.Errorf("invalid outbounds field: %w", err)
	}

	return normalizeXrayRules(&sspanel.XrayRules{
		DNS:       dnsRaw,
		Routing:   routingRaw,
		Outbounds: outboundsRaw,
	}), nil
}

func normalizeRuleSection(raw json.RawMessage, expectObject bool) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.EqualFold(raw, []byte("null")) {
		return nil, nil
	}
	if expectObject {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, err
		}
		if len(object) == 0 {
			return nil, nil
		}
	} else {
		var array []json.RawMessage
		if err := json.Unmarshal(raw, &array); err != nil {
			return nil, err
		}
		if len(array) == 0 {
			return nil, nil
		}
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, err
	}
	if compact.Len() == 0 {
		return nil, nil
	}
	return json.RawMessage(append([]byte(nil), compact.Bytes()...)), nil
}

func hasXrayRules(rules *sspanel.XrayRules) bool {
	if rules == nil {
		return false
	}
	return len(rules.DNS) > 0 || len(rules.Routing) > 0 || len(rules.Outbounds) > 0
}

func normalizeXrayRules(rules *sspanel.XrayRules) *sspanel.XrayRules {
	if rules == nil {
		return nil
	}
	clone := &sspanel.XrayRules{}
	if len(rules.DNS) > 0 {
		clone.DNS = json.RawMessage(append([]byte(nil), rules.DNS...))
	}
	if len(rules.Routing) > 0 {
		clone.Routing = json.RawMessage(append([]byte(nil), rules.Routing...))
	}
	if len(rules.Outbounds) > 0 {
		clone.Outbounds = json.RawMessage(append([]byte(nil), rules.Outbounds...))
	}
	if !hasXrayRules(clone) {
		return nil
	}
	return clone
}

func cloneXrayRules(rules *sspanel.XrayRules) *sspanel.XrayRules {
	return normalizeXrayRules(rules)
}

func xrayRulesEqual(a, b *sspanel.XrayRules) bool {
	a = normalizeXrayRules(a)
	b = normalizeXrayRules(b)
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return bytes.Equal(a.DNS, b.DNS) &&
		bytes.Equal(a.Routing, b.Routing) &&
		bytes.Equal(a.Outbounds, b.Outbounds)
}

func writeFileAtomic(path string, content []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
