package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func (v *V2Core) AddNode(tag string, info *panel.NodeInfo) error {
	inBoundConfig, detourConfig, err := buildInbound(info, tag, nil)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	if err := v.dumpInboundConfig(tag, info, nil, detourConfig); err != nil {
		log.WithFields(log.Fields{
			"tag":  tag,
			"file": v.Config.DumpInboundsFile,
			"err":  err,
		}).Warn("failed to dump inbound config")
	}
	return nil
}

func (v *V2Core) AddNodeWithUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error {
	inBoundConfig, detourConfig, err := buildInbound(info, tag, users)
	if err != nil {
		return fmt.Errorf("build inbound error: %s", err)
	}
	err = v.addInbound(inBoundConfig)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	if err := v.dumpInboundConfig(tag, info, users, detourConfig); err != nil {
		log.WithFields(log.Fields{
			"tag":  tag,
			"file": v.Config.DumpInboundsFile,
			"err":  err,
		}).Warn("failed to dump inbound config")
	}
	return nil
}

func (v *V2Core) DelNode(tag string) error {
	err := v.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	if v.dispatcher != nil {
		v.dispatcher.AuditCounter.Delete(tag)
	}
	return nil
}

type inboundDumpEntry struct {
	Tag         string          `json:"tag"`
	NodeID      int             `json:"node_id"`
	NodeType    string          `json:"node_type"`
	ServerPort  int             `json:"server_port"`
	UserCount   int             `json:"user_count"`
	Inbound     json.RawMessage `json:"inbound"`
	GeneratedAt string          `json:"generated_at"`
}

type inboundDumpFile struct {
	GeneratedAt string             `json:"generated_at"`
	Count       int                `json:"count"`
	Inbounds    []inboundDumpEntry `json:"inbounds"`
}

func (v *V2Core) dumpInboundConfig(tag string, info *panel.NodeInfo, users []panel.UserInfo, detourConfig *coreConf.InboundDetourConfig) error {
	if v == nil || v.Config == nil || detourConfig == nil {
		return nil
	}
	path := strings.TrimSpace(v.Config.DumpInboundsFile)
	if path == "" {
		return nil
	}

	rawInbound, err := marshalCompactInboundDetour(detourConfig)
	if err != nil {
		return err
	}
	entry := inboundDumpEntry{
		Tag:         tag,
		UserCount:   len(users),
		Inbound:     rawInbound,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}
	if info != nil {
		entry.NodeID = info.Id
		entry.NodeType = info.Type
		if info.Common != nil {
			entry.ServerPort = info.Common.ServerPort
		}
	}

	v.inboundDumpLock.Lock()
	if v.inboundDump == nil {
		v.inboundDump = make(map[string]inboundDumpEntry)
	}
	v.inboundDump[tag] = entry
	entries := make([]inboundDumpEntry, 0, len(v.inboundDump))
	for _, item := range v.inboundDump {
		entries = append(entries, item)
	}
	v.inboundDumpLock.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].NodeID != entries[j].NodeID {
			return entries[i].NodeID < entries[j].NodeID
		}
		return entries[i].Tag < entries[j].Tag
	})

	out := inboundDumpFile{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Count:       len(entries),
		Inbounds:    entries,
	}
	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inbound dump file failed: %w", err)
	}
	if err := writeFileAtomic(path, content); err != nil {
		return err
	}
	return nil
}

func marshalCompactInboundDetour(detourConfig *coreConf.InboundDetourConfig) (json.RawMessage, error) {
	if detourConfig == nil {
		return nil, fmt.Errorf("inbound detour is nil")
	}
	raw, err := json.Marshal(detourConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal inbound detour failed: %w", err)
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshal inbound detour failed: %w", err)
	}
	cleaned, ok := sanitizeInboundJSONValue(decoded)
	if !ok {
		return nil, fmt.Errorf("inbound detour becomes empty after sanitize")
	}
	compact, err := json.Marshal(cleaned)
	if err != nil {
		return nil, fmt.Errorf("marshal compact inbound detour failed: %w", err)
	}
	return compact, nil
}

func sanitizeInboundJSONValue(value interface{}) (interface{}, bool) {
	switch v := value.(type) {
	case nil:
		return nil, false
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, false
		}
		return v, true
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			if cleaned, ok := sanitizeInboundJSONValue(item); ok {
				out = append(out, cleaned)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, item := range v {
			if cleaned, ok := sanitizeInboundJSONValue(item); ok {
				out[k] = cleaned
			}
		}
		normalizeAliasField(out, "protocolParam", "protocolparam")
		normalizeAliasField(out, "obfsParam", "obfsparam")
		sanitizeClientParams(out)
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return value, true
	}
}

func sanitizeClientParams(m map[string]interface{}) {
	if m == nil {
		return
	}
	rawClients, ok := m["clients"]
	if !ok {
		return
	}
	clients, ok := rawClients.([]interface{})
	if !ok {
		return
	}
	filtered := make([]interface{}, 0, len(clients))
	for _, item := range clients {
		client, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		normalizeAliasField(client, "protocolParam", "protocolparam")
		normalizeAliasField(client, "obfsParam", "obfsparam")
		out := make(map[string]interface{}, 5)
		copyNonEmptyStringField(client, out, "protocolParam")
		copyNonEmptyStringField(client, out, "obfsParam")
		copyNonEmptyStringField(client, out, "password")
		copyNonEmptyStringField(client, out, "method")
		copyNonEmptyStringField(client, out, "email")
		if len(out) > 0 {
			filtered = append(filtered, out)
		}
	}
	if len(filtered) == 0 {
		delete(m, "clients")
		return
	}
	m["clients"] = filtered
}

func copyNonEmptyStringField(src, dst map[string]interface{}, field string) {
	if src == nil || dst == nil {
		return
	}
	v, ok := src[field].(string)
	if !ok {
		return
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	dst[field] = v
}

func normalizeAliasField(m map[string]interface{}, canonical, alias string) {
	if m == nil {
		return
	}
	aliasValue, hasAlias := m[alias]
	if !hasAlias {
		return
	}
	if canonicalValue, hasCanonical := m[canonical]; hasCanonical {
		if !isNonEmptyJSONString(canonicalValue) && isNonEmptyJSONString(aliasValue) {
			m[canonical] = strings.TrimSpace(aliasValue.(string))
		}
		delete(m, alias)
		return
	}
	if isNonEmptyJSONString(aliasValue) {
		m[canonical] = strings.TrimSpace(aliasValue.(string))
	}
	delete(m, alias)
}

func isNonEmptyJSONString(value interface{}) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	return strings.TrimSpace(text) != ""
}

func writeFileAtomic(path string, content []byte) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dump directory failed: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return fmt.Errorf("write dump tmp file failed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename dump file failed: %w", err)
	}
	return nil
}
