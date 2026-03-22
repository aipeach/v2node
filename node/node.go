package node

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
)

type Node struct {
	controllers []*Controller
	NodeInfos   []*panel.NodeInfo
	configs     []conf.NodeConfig
}

func New(nodes []conf.NodeConfig) (*Node, error) {
	n := &Node{
		controllers: make([]*Controller, 0, len(nodes)),
		NodeInfos:   make([]*panel.NodeInfo, 0, len(nodes)),
		configs:     make([]conf.NodeConfig, 0, len(nodes)),
	}
	seenTags := make(map[string]struct{}, len(nodes)*2)
	for _, node := range nodes {
		expanded, err := expandNodeConfig(node)
		if err != nil {
			return nil, err
		}
		if isSSRNodeType(node.NodeType) {
			log.WithFields(log.Fields{
				"apiHost":       node.APIHost,
				"nodeID":        node.NodeID,
				"nodeType":      node.NodeType,
				"expandedCount": len(expanded),
			}).Info("SSR node config expanded")
		}
		added := 0
		for _, cfg := range expanded {
			p, err := panel.New(&cfg)
			if err != nil {
				return nil, err
			}
			info, err := p.GetNodeInfo()
			if err != nil {
				if isSSRTemplateNotFoundErr(err) && isSSRNodeType(node.NodeType) {
					log.WithFields(log.Fields{
						"apiHost": node.APIHost,
						"nodeID":  node.NodeID,
						"mode":    cfg.SSRSinglePortMode,
						"err":     err,
					}).Info("SSR single-port template not found, skip this mode")
					continue
				}
				return nil, err
			}
			if isSSRNodeType(node.NodeType) {
				expectedTag := buildExpectedSSRTag(cfg, info)
				if expectedTag != "" && info.Tag != expectedTag {
					log.WithFields(log.Fields{
						"apiHost":      node.APIHost,
						"nodeID":       node.NodeID,
						"mode":         cfg.SSRSinglePortMode,
						"returnedTag":  info.Tag,
						"expectedTag":  expectedTag,
						"serverPort":   info.Common.ServerPort,
						"ssrMultiMode": info.Common.SSRMultiUserMode,
					}).Warn("SSR node returned unexpected tag, override with mode-specific tag")
					info.Tag = expectedTag
				}
			}
			if _, exists := seenTags[info.Tag]; exists {
				return nil, fmt.Errorf("duplicate inbound tag generated: %s (node=%d mode=%s)", info.Tag, node.NodeID, cfg.SSRSinglePortMode)
			}
			seenTags[info.Tag] = struct{}{}
			if isSSRNodeType(node.NodeType) {
				port := 0
				ssrMode := ""
				if info.Common != nil {
					port = info.Common.ServerPort
					ssrMode = info.Common.SSRMultiUserMode
				}
				log.WithFields(log.Fields{
					"apiHost":      node.APIHost,
					"nodeID":       node.NodeID,
					"mode":         cfg.SSRSinglePortMode,
					"tag":          info.Tag,
					"serverPort":   port,
					"ssrMultiMode": ssrMode,
				}).Info("SSR inbound profile prepared")
			}
			cfgCopy := cfg
			n.controllers = append(n.controllers, NewController(p, &cfgCopy, info))
			n.NodeInfos = append(n.NodeInfos, info)
			n.configs = append(n.configs, cfgCopy)
			added++
		}
		if added == 0 && isSSRNodeType(node.NodeType) {
			return nil, fmt.Errorf("no ssr single-port template found for node %d", node.NodeID)
		}
		if isSSRNodeType(node.NodeType) {
			log.WithFields(log.Fields{
				"apiHost": node.APIHost,
				"nodeID":  node.NodeID,
				"added":   added,
			}).Info("SSR node profiles ready")
		}
	}
	return n, nil
}

func (n *Node) Start(nodes []conf.NodeConfig, core *core.V2Core) error {
	for i, node := range n.configs {
		err := n.controllers[i].Start(core)
		if err != nil {
			return fmt.Errorf("start node controller [%s-%d] error: %s",
				node.APIHost,
				node.NodeID,
				err)
		}
	}
	return nil
}

func (n *Node) Close() error {
	var err error
	for _, c := range n.controllers {
		if err = c.Close(); err != nil {
			log.Errorf("close controller failed: %v", err)
			return err
		}
	}
	n.controllers = nil
	return nil
}

func expandNodeConfig(node conf.NodeConfig) ([]conf.NodeConfig, error) {
	panelType := strings.ToLower(strings.TrimSpace(node.PanelType))
	if panelType == panel.PanelTypeSogaV1 || panelType == "soga_v1" || panelType == "sogav1" {
		return []conf.NodeConfig{node}, nil
	}

	normalizedType := strings.ToLower(strings.TrimSpace(node.NodeType))
	if normalizedType != "ssr" && normalizedType != "shadowsocksr" {
		return []conf.NodeConfig{node}, nil
	}
	// Respect explicit mode if already set (e.g. internal reload state).
	if node.SSRSinglePortMode == panel.SSRSinglePortModeProtocol || node.SSRSinglePortMode == panel.SSRSinglePortModeObfs {
		return []conf.NodeConfig{node}, nil
	}
	return []conf.NodeConfig{
		withSSRMode(node, panel.SSRSinglePortModeProtocol),
		withSSRMode(node, panel.SSRSinglePortModeObfs),
	}, nil
}

func withSSRMode(node conf.NodeConfig, mode string) conf.NodeConfig {
	cfg := node
	cfg.SSRSinglePortMode = mode
	return cfg
}

func isSSRNodeType(nodeType string) bool {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case "ssr", "shadowsocksr":
		return true
	default:
		return false
	}
}

func isSSRTemplateNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "single-port template user not found")
}

func buildExpectedSSRTag(cfg conf.NodeConfig, info *panel.NodeInfo) string {
	if info == nil {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.SSRSinglePortMode))
	switch mode {
	case panel.SSRSinglePortModeProtocol, panel.SSRSinglePortModeObfs:
		return fmt.Sprintf("[%s]-%s-%s:%d", cfg.APIHost, info.Type, mode, cfg.NodeID)
	default:
		return fmt.Sprintf("[%s]-%s:%d", cfg.APIHost, info.Type, cfg.NodeID)
	}
}
