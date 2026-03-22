package panel

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	sogav1 "github.com/wyx2685/v2node/api/soga-v1"
	sspanel "github.com/wyx2685/v2node/api/sspanel"
	"github.com/wyx2685/v2node/conf"
)

const (
	PanelTypeXiaoV2board = "xiaov2board"
	PanelTypeSSPanel     = "sspanel"
	PanelTypeSogaV1      = "soga-v1"
)

type Client struct {
	sspanelClient *sspanel.Client
	sogaClient    *sogav1.Client

	client           *resty.Client
	APIHost          string
	Token            string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
}

func New(c *conf.NodeConfig) (*Client, error) {
	panelType := normalizePanelType(c.PanelType)
	switch panelType {
	case PanelTypeSSPanel:
		client, err := sspanel.New(c)
		if err != nil {
			return nil, err
		}
		return &Client{
			sspanelClient: client,
		}, nil
	case PanelTypeSogaV1:
		client, err := sogav1.New(c)
		if err != nil {
			return nil, err
		}
		return &Client{
			sogaClient: client,
		}, nil
	case PanelTypeXiaoV2board:
	default:
		return nil, fmt.Errorf("unsupported panel type: %s", c.PanelType)
	}

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
	client.SetBaseURL(c.APIHost)
	client.SetQueryParams(map[string]string{
		"node_type": "v2node",
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})

	return &Client{
		client:   client,
		Token:    c.Key,
		APIHost:  c.APIHost,
		NodeId:   c.NodeID,
		UserList: &UserListBody{},
		AliveMap: &AliveMap{},
	}, nil
}

func normalizePanelType(panelType string) string {
	switch strings.ToLower(strings.TrimSpace(panelType)) {
	case "", "sspanel", "sspanel-uim", "sspanel_uim", "sspaneluim":
		return PanelTypeSSPanel
	case "v2board", "xiao-v2board", "xiao_v2board", PanelTypeXiaoV2board:
		return PanelTypeXiaoV2board
	case "soga-v1", "soga_v1", "sogav1":
		return PanelTypeSogaV1
	default:
		return strings.ToLower(strings.TrimSpace(panelType))
	}
}
