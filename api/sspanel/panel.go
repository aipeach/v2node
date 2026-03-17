package panel

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	"github.com/wyx2685/v2node/conf"
)

type Client struct {
	client            *resty.Client
	APIHost           string
	Token             string
	NodeId            int
	NodeType          string
	SSRSinglePortMode string
	ListenIP          string
	MUSuffix          string
	MURegex           string
	SSObfsUDP         bool
	EnableFallback    bool
	FallbackObject    *FallbackObject
	CertConfig        *conf.CertConfig
	GlobalCertConfig  *conf.CertConfig
	CertFile          string
	KeyFile           string
	AcceptProxyProto  bool
	nodeEtag          string
	detectRuleEtag    string
	userEtag          string
	responseBodyHash  string
	detectRuleHash    string
	cachedNodeData    *modMUNodeData
	cachedRoutes      []Route
	UserList          *UserListBody
	AliveMap          *AliveMap
}

func New(c *conf.NodeConfig) (*Client, error) {
	muSuffix, muRegex := normalizeSSRMUSettings(c.MUSuffix, c.MURegex)

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
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	// set common query params for mod_mu api
	client.SetQueryParams(map[string]string{
		"key":     c.Key,
		"node_id": strconv.Itoa(c.NodeID),
	})
	return &Client{
		client:            client,
		Token:             c.Key,
		APIHost:           c.APIHost,
		NodeId:            c.NodeID,
		NodeType:          c.NodeType,
		SSRSinglePortMode: c.SSRSinglePortMode,
		ListenIP:          c.ListenIP,
		MUSuffix:          muSuffix,
		MURegex:           muRegex,
		SSObfsUDP:         c.SSObfsUDP,
		EnableFallback:    c.EnableFallback,
		FallbackObject:    clonePanelFallbackObject(c.FallbackObject),
		CertConfig:        c.CertConfig,
		GlobalCertConfig:  c.GlobalCertConfig,
		CertFile:          c.CertFile,
		KeyFile:           c.KeyFile,
		AcceptProxyProto:  c.AcceptProxyProtocol,
		UserList:          &UserListBody{},
		AliveMap:          &AliveMap{},
	}, nil
}

func clonePanelFallbackObject(src *conf.FallbackObject) *FallbackObject {
	if src == nil {
		return nil
	}
	return &FallbackObject{
		Name: strings.TrimSpace(src.Name),
		Alpn: strings.TrimSpace(src.Alpn),
		Path: strings.TrimSpace(src.Path),
		Dest: src.Dest,
		Xver: src.Xver,
	}
}
