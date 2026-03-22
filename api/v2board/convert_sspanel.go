package panel

import (
	"encoding/json"

	sspanel "github.com/wyx2685/v2node/api/sspanel"
)

func cloneNodeInfoFromSSPanel(src *sspanel.NodeInfo) *NodeInfo {
	if src == nil {
		return nil
	}
	return &NodeInfo{
		Id:           src.Id,
		Type:         src.Type,
		Security:     src.Security,
		PushInterval: src.PushInterval,
		PullInterval: src.PullInterval,
		Tag:          src.Tag,
		Common:       cloneCommonNodeFromSSPanel(src.Common),
	}
}

func cloneCommonNodeFromSSPanel(src *sspanel.CommonNode) *CommonNode {
	if src == nil {
		return nil
	}
	dst := &CommonNode{
		Protocol:                src.Protocol,
		ListenIP:                src.ListenIP,
		ServerPort:              src.ServerPort,
		Routes:                  cloneRoutesFromSSPanel(src.Routes),
		AuditWhiteList:          append([]string(nil), src.AuditWhiteList...),
		BaseConfig:              cloneBaseConfigFromSSPanel(src.BaseConfig),
		Tls:                     src.Tls,
		TlsSettings:             TlsSettings(src.TlsSettings),
		CertInfo:                cloneCertInfoFromSSPanel(src.CertInfo),
		ExtraCertInfos:          cloneCertInfosFromSSPanel(src.ExtraCertInfos),
		Network:                 src.Network,
		Encryption:              src.Encryption,
		EncryptionSettings:      EncSettings(src.EncryptionSettings),
		ServerName:              src.ServerName,
		Flow:                    src.Flow,
		EnableFallback:          src.EnableFallback,
		FallbackObject:          cloneFallbackObjectFromSSPanel(src.FallbackObject),
		Cipher:                  src.Cipher,
		ServerKey:               src.ServerKey,
		SSSinglePortMultiUser:   src.SSSinglePortMultiUser,
		SSRMethod:               src.SSRMethod,
		SSRPassword:             src.SSRPassword,
		SSRMultiUserMode:        src.SSRMultiUserMode,
		SSRProtocol:             src.SSRProtocol,
		SSRProtocolParam:        src.SSRProtocolParam,
		SSROBFS:                 src.SSROBFS,
		SSROBFSParam:            src.SSROBFSParam,
		SSObfsUDP:               src.SSObfsUDP,
		CongestionControl:       src.CongestionControl,
		ZeroRTTHandshake:        src.ZeroRTTHandshake,
		PaddingScheme:           append([]string(nil), src.PaddingScheme...),
		UpMbps:                  src.UpMbps,
		DownMbps:                src.DownMbps,
		Obfs:                    src.Obfs,
		ObfsPassword:            src.ObfsPassword,
		Ignore_Client_Bandwidth: src.Ignore_Client_Bandwidth,
	}
	if len(src.NetworkSettings) > 0 {
		dst.NetworkSettings = json.RawMessage(append([]byte(nil), src.NetworkSettings...))
	}
	return dst
}

func cloneRoutesFromSSPanel(src []sspanel.Route) []Route {
	if len(src) == 0 {
		return nil
	}
	dst := make([]Route, 0, len(src))
	for _, item := range src {
		r := Route{
			Id:         item.Id,
			Match:      append([]string(nil), item.Match...),
			Action:     item.Action,
			DetectRule: item.DetectRule,
		}
		if item.ActionValue != nil {
			value := *item.ActionValue
			r.ActionValue = &value
		}
		dst = append(dst, r)
	}
	return dst
}

func cloneBaseConfigFromSSPanel(src *sspanel.BaseConfig) *BaseConfig {
	if src == nil {
		return nil
	}
	dst := BaseConfig(*src)
	return &dst
}

func cloneCertInfoFromSSPanel(src *sspanel.CertInfo) *CertInfo {
	if src == nil {
		return nil
	}
	dst := &CertInfo{
		CertMode:         src.CertMode,
		CertFile:         src.CertFile,
		KeyFile:          src.KeyFile,
		KeyType:          src.KeyType,
		Email:            src.Email,
		CertDomain:       src.CertDomain,
		Provider:         src.Provider,
		RejectUnknownSni: src.RejectUnknownSni,
	}
	if len(src.DNSEnv) > 0 {
		dst.DNSEnv = make(map[string]string, len(src.DNSEnv))
		for k, v := range src.DNSEnv {
			dst.DNSEnv[k] = v
		}
	}
	return dst
}

func cloneCertInfosFromSSPanel(src []*sspanel.CertInfo) []*CertInfo {
	if len(src) == 0 {
		return nil
	}
	dst := make([]*CertInfo, 0, len(src))
	for _, item := range src {
		dst = append(dst, cloneCertInfoFromSSPanel(item))
	}
	return dst
}

func cloneFallbackObjectFromSSPanel(src *sspanel.FallbackObject) *FallbackObject {
	if src == nil {
		return nil
	}
	dst := FallbackObject(*src)
	return &dst
}

func cloneUserListFromSSPanel(src []sspanel.UserInfo) []UserInfo {
	if len(src) == 0 {
		return nil
	}
	dst := make([]UserInfo, 0, len(src))
	for _, user := range src {
		dst = append(dst, UserInfo{
			Id:                user.Id,
			Uuid:              user.Uuid,
			SpeedLimit:        user.SpeedLimit,
			DeviceLimit:       user.DeviceLimit,
			SSClientPassword:  user.SSClientPassword,
			SSRClientPassword: user.SSRClientPassword,
			SSRProtocolParam:  user.SSRProtocolParam,
			SSROBFSParam:      user.SSROBFSParam,
		})
	}
	return dst
}

func cloneUserTrafficToSSPanel(src []UserTraffic) []sspanel.UserTraffic {
	if len(src) == 0 {
		return nil
	}
	dst := make([]sspanel.UserTraffic, 0, len(src))
	for _, traffic := range src {
		dst = append(dst, sspanel.UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download,
		})
	}
	return dst
}

func cloneDetectLogsToSSPanel(src []DetectLog) []sspanel.DetectLog {
	if len(src) == 0 {
		return nil
	}
	dst := make([]sspanel.DetectLog, 0, len(src))
	for _, log := range src {
		dst = append(dst, sspanel.DetectLog{
			UID:    log.UID,
			ListID: log.ListID,
		})
	}
	return dst
}
