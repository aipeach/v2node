package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

type modMUUsersResponse struct {
	Ret  int            `json:"ret"`
	Data []modMUUserRow `json:"data"`
}

type modMUUserRow struct {
	ID             int         `json:"id"`
	UUID           string      `json:"uuid"`
	Passwd         string      `json:"passwd"`
	NodeSpeedlimit interface{} `json:"node_speedlimit"`
	NodeConnector  interface{} `json:"node_connector"`
	AliveIP        interface{} `json:"alive_ip"`
}

type modMURetResponse struct {
	Ret  int         `json:"ret"`
	Data interface{} `json:"data"`
}

// GetUserList pulls user list from SSPANEL mod_mu api.
func (c *Client) GetUserList() ([]UserInfo, error) {
	const path = "/mod_mu/users"
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
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

	resp := &modMUUsersResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return nil, fmt.Errorf("decode mod_mu user list error: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("mod_mu user list ret=%d, body=%s", resp.Ret, string(r.Body()))
	}

	users := make([]UserInfo, 0, len(resp.Data))
	alive := make(map[int]int, len(resp.Data))
	for _, row := range resp.Data {
		uuid := strings.TrimSpace(row.UUID)
		if uuid == "" {
			uuid = strings.TrimSpace(row.Passwd)
		}
		if uuid == "" || row.ID <= 0 {
			continue
		}
		users = append(users, UserInfo{
			Id:          row.ID,
			Uuid:        uuid,
			SpeedLimit:  intFromAny(row.NodeSpeedlimit),
			DeviceLimit: intFromAny(row.NodeConnector),
		})
		alive[row.ID] = intFromAny(row.AliveIP)
	}
	c.AliveMap = &AliveMap{Alive: alive}
	c.userEtag = r.Header().Get("ETag")
	return users, nil
}

// GetUserAlive returns alive_ip count from latest user list pull.
func (c *Client) GetUserAlive() (map[int]int, error) {
	if c.AliveMap == nil {
		c.AliveMap = &AliveMap{Alive: map[int]int{}}
	}
	if c.AliveMap.Alive == nil {
		c.AliveMap.Alive = map[int]int{}
	}
	return c.AliveMap.Alive, nil
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

type modMUTrafficRow struct {
	UserID int   `json:"user_id"`
	U      int64 `json:"u"`
	D      int64 `json:"d"`
}

type modMUDetectLogRow struct {
	UserID int `json:"user_id"`
	ListID int `json:"list_id"`
}

type modMUAliveIPRow struct {
	UserID int    `json:"user_id"`
	IP     string `json:"ip"`
}

// ReportUserTraffic reports the user traffic to SSPANEL mod_mu.
func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	if len(userTraffic) == 0 {
		return nil
	}
	rows := make([]modMUTrafficRow, 0, len(userTraffic))
	for _, traffic := range userTraffic {
		rows = append(rows, modMUTrafficRow{
			UserID: traffic.UID,
			U:      traffic.Upload,
			D:      traffic.Download,
		})
	}
	const path = "/mod_mu/users/traffic"
	r, err := c.client.R().
		SetBody(map[string]interface{}{
			"data": rows,
		}).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	return ensureModMURetOK("report user traffic", r)
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	if data == nil || len(*data) == 0 {
		return nil
	}

	rows := make([]modMUAliveIPRow, 0)
	for uid, ips := range *data {
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			rows = append(rows, modMUAliveIPRow{
				UserID: uid,
				IP:     ip,
			})
		}
	}
	if len(rows) == 0 {
		return nil
	}

	const path = "/mod_mu/users/aliveip"
	r, err := c.client.R().
		SetBody(map[string]interface{}{
			"data": rows,
		}).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	return ensureModMURetOK("report user alive ip", r)
}

func (c *Client) ReportUserDetectLogs(logs []DetectLog) error {
	if len(logs) == 0 {
		return nil
	}
	rows := make([]modMUDetectLogRow, 0, len(logs))
	for _, hit := range logs {
		if hit.UID <= 0 || hit.ListID <= 0 {
			continue
		}
		rows = append(rows, modMUDetectLogRow{
			UserID: hit.UID,
			ListID: hit.ListID,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	const path = "/mod_mu/users/detectlog"
	r, err := c.client.R().
		SetBody(map[string]interface{}{
			"data": rows,
		}).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	return ensureModMURetOK("report user detect log", r)
}

func ensureModMURetOK(action string, r interface {
	StatusCode() int
	Body() []byte
}) error {
	if r == nil {
		return fmt.Errorf("%s failed: nil response", action)
	}
	if r.StatusCode() >= 400 {
		return fmt.Errorf("%s failed with status %d: %s", action, r.StatusCode(), string(r.Body()))
	}
	if len(r.Body()) == 0 {
		return nil
	}
	resp := &modMURetResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return fmt.Errorf("%s decode response error: %w", action, err)
	}
	if resp.Ret != 1 {
		return fmt.Errorf("%s failed, ret=%d body=%s", action, resp.Ret, string(r.Body()))
	}
	return nil
}
