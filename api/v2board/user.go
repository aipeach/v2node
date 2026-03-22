package panel

import (
	"encoding/json"
	"fmt"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id                int    `json:"id" msgpack:"id"`
	Uuid              string `json:"uuid" msgpack:"uuid"`
	SpeedLimit        int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit       int    `json:"device_limit" msgpack:"device_limit"`
	SSClientPassword  string `json:"-" msgpack:"-"`
	SSRClientPassword string `json:"-" msgpack:"-"`
	SSRProtocolParam  string `json:"-" msgpack:"-"`
	SSROBFSParam      string `json:"-" msgpack:"-"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

const (
	SSRSinglePortModeAuto     = "auto"
	SSRSinglePortModeProtocol = "protocol"
	SSRSinglePortModeObfs     = "obfs"
)

func (c *Client) GetUserList() ([]UserInfo, error) {
	if c != nil && c.sspanelClient != nil {
		users, err := c.sspanelClient.GetUserList()
		if err != nil {
			return nil, err
		}
		return cloneUserListFromSSPanel(users), nil
	}
	if c != nil && c.sogaClient != nil {
		users, err := c.sogaClient.GetUserList()
		if err != nil {
			return nil, err
		}
		return cloneUserListFromSSPanel(users), nil
	}

	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
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
		return nil, fmt.Errorf("get user list failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}

	payload := &UserListBody{}
	if err := json.Unmarshal(r.Body(), payload); err != nil {
		var users []UserInfo
		if err2 := json.Unmarshal(r.Body(), &users); err2 != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		payload.Users = users
	}

	c.userEtag = r.Header().Get("ETag")
	return payload.Users, nil
}

func (c *Client) GetUserAlive() (map[int]int, error) {
	if c != nil && c.sspanelClient != nil {
		return c.sspanelClient.GetUserAlive()
	}
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.GetUserAlive()
	}

	empty := map[int]int{}
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return empty, nil
	}
	if r == nil || r.StatusCode() >= 400 {
		return empty, nil
	}

	payload := &AliveMap{}
	if err := json.Unmarshal(r.Body(), payload); err == nil && payload.Alive != nil {
		return payload.Alive, nil
	}

	var direct map[int]int
	if err := json.Unmarshal(r.Body(), &direct); err == nil && direct != nil {
		return direct, nil
	}

	return empty, nil
}

func (c *Client) GetSSRSinglePortModes() ([]string, error) {
	if c != nil && c.sspanelClient != nil {
		return c.sspanelClient.GetSSRSinglePortModes()
	}
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.GetSSRSinglePortModes()
	}
	return nil, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

type DetectLog struct {
	UID    int
	ListID int
}

func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	if c != nil && c.sspanelClient != nil {
		return c.sspanelClient.ReportUserTraffic(cloneUserTrafficToSSPanel(userTraffic))
	}
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.ReportUserTraffic(cloneUserTrafficToSSPanel(userTraffic))
	}
	if len(userTraffic) == 0 {
		return nil
	}

	data := make(map[int][]int64, len(userTraffic))
	for _, traffic := range userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	const path = "/api/v1/server/UniProxy/push"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	if r != nil && r.StatusCode() >= 400 {
		return fmt.Errorf("report user traffic failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}
	return nil
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	if c != nil && c.sspanelClient != nil {
		return c.sspanelClient.ReportNodeOnlineUsers(data)
	}
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.ReportNodeOnlineUsers(data)
	}
	if data == nil || len(*data) == 0 {
		return nil
	}

	const path = "/api/v1/server/UniProxy/alive"
	r, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	if r != nil && r.StatusCode() >= 400 {
		return fmt.Errorf("report online users failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}
	return nil
}

func (c *Client) ReportUserDetectLogs(logs []DetectLog) error {
	if c != nil && c.sspanelClient != nil {
		return c.sspanelClient.ReportUserDetectLogs(cloneDetectLogsToSSPanel(logs))
	}
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.ReportUserDetectLogs(cloneDetectLogsToSSPanel(logs))
	}
	return nil
}

func (c *Client) ReportNodeStatus() error {
	if c != nil && c.sogaClient != nil {
		return c.sogaClient.ReportNodeStatus()
	}
	return nil
}
