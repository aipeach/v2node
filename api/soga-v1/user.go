package panel

import (
	"encoding/json"
	"fmt"
	"strings"

	sspanel "github.com/wyx2685/v2node/api/sspanel"
)

type OnlineUser = sspanel.OnlineUser
type UserInfo = sspanel.UserInfo
type UserListBody = sspanel.UserListBody
type AliveMap = sspanel.AliveMap
type UserTraffic = sspanel.UserTraffic
type DetectLog = sspanel.DetectLog

type sogaUserRow struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	Password    string `json:"password"`
	SpeedLimit  any    `json:"speed_limit"`
	DeviceLimit any    `json:"device_limit"`
}

type sogaTrafficRow struct {
	ID int   `json:"id"`
	U  int64 `json:"u"`
	D  int64 `json:"d"`
}

type sogaAliveIPRow struct {
	ID  int      `json:"id"`
	IPs []string `json:"ips"`
}

type sogaAuditLogRow struct {
	UserID  int `json:"user_id"`
	AuditID int `json:"audit_id"`
}

type sogaCodeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) GetUserList() ([]UserInfo, error) {
	r, err := c.client.R().
		SetHeader("If-None-Match", c.userEtag).
		ForceContentType("application/json").
		Get("api/v1/users")
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

	var rows []sogaUserRow
	if err := json.Unmarshal(r.Body(), &rows); err != nil {
		return nil, fmt.Errorf("decode soga user list error: %w", err)
	}
	c.userEtag = r.Header().Get("ETag")

	users := make([]UserInfo, 0, len(rows))
	for _, row := range rows {
		if row.ID <= 0 {
			continue
		}
		user := UserInfo{
			Id:          row.ID,
			SpeedLimit:  intFromAny(row.SpeedLimit),
			DeviceLimit: intFromAny(row.DeviceLimit),
		}

		switch c.NodeType {
		case "vmess", "vless":
			user.Uuid = strings.TrimSpace(row.UUID)
		case "shadowsocks":
			password := strings.TrimSpace(row.Password)
			if password == "" {
				continue
			}
			user.Uuid = fmt.Sprintf("%d:%s", row.ID, password)
			user.SSClientPassword = password
		case "shadowsocksr":
			password := strings.TrimSpace(row.Password)
			if password == "" {
				continue
			}
			mode := normalizeSSRSinglePortType("")
			if c.cachedNodeData != nil {
				cfg := &sogaSSRConfig{}
				if err := json.Unmarshal(c.cachedNodeData.Config, cfg); err == nil {
					mode = normalizeSSRSinglePortType(cfg.SinglePortType)
				}
			}
			user.Uuid = fmt.Sprintf("%d:%s", row.ID, password)
			user.SSRClientPassword = password
			if mode == "obfs" {
				user.SSROBFSParam = fmt.Sprintf("%d:%s", row.ID, password)
			} else {
				user.SSRProtocolParam = fmt.Sprintf("%d:%s", row.ID, password)
			}
		default:
			user.Uuid = strings.TrimSpace(row.Password)
		}
		if user.Uuid == "" {
			continue
		}
		users = append(users, user)
	}

	if c.AliveMap == nil {
		c.AliveMap = &AliveMap{Alive: map[int]int{}}
	}
	if c.AliveMap.Alive == nil {
		c.AliveMap.Alive = map[int]int{}
	} else {
		for uid := range c.AliveMap.Alive {
			delete(c.AliveMap.Alive, uid)
		}
	}
	return users, nil
}

func (c *Client) GetUserAlive() (map[int]int, error) {
	if c.AliveMap == nil {
		c.AliveMap = &AliveMap{Alive: map[int]int{}}
	}
	if c.AliveMap.Alive == nil {
		c.AliveMap.Alive = map[int]int{}
	}
	return c.AliveMap.Alive, nil
}

func (c *Client) GetSSRSinglePortModes() ([]string, error) {
	if c.NodeType != "shadowsocksr" {
		return nil, nil
	}
	return []string{"protocol", "obfs"}, nil
}

func (c *Client) ReportUserTraffic(userTraffic []UserTraffic) error {
	if len(userTraffic) == 0 {
		return nil
	}
	rows := make([]sogaTrafficRow, 0, len(userTraffic))
	for _, traffic := range userTraffic {
		if traffic.UID <= 0 {
			continue
		}
		rows = append(rows, sogaTrafficRow{
			ID: traffic.UID,
			U:  traffic.Upload,
			D:  traffic.Download,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	r, err := c.client.R().
		SetBody(rows).
		ForceContentType("application/json").
		Post("api/v1/traffic")
	if err != nil {
		return err
	}
	return ensureSogaCodeOK("report user traffic", r)
}

func (c *Client) ReportNodeOnlineUsers(data *map[int][]string) error {
	if data == nil || len(*data) == 0 {
		return nil
	}
	rows := make([]sogaAliveIPRow, 0, len(*data))
	for uid, ips := range *data {
		if uid <= 0 || len(ips) == 0 {
			continue
		}
		normalized := dedupeStringSlice(ips)
		if len(normalized) == 0 {
			continue
		}
		rows = append(rows, sogaAliveIPRow{
			ID:  uid,
			IPs: normalized,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	r, err := c.client.R().
		SetBody(rows).
		ForceContentType("application/json").
		Post("api/v1/alive_ip")
	if err != nil {
		return err
	}
	return ensureSogaCodeOK("report online users", r)
}

func (c *Client) ReportUserDetectLogs(logs []DetectLog) error {
	if len(logs) == 0 {
		return nil
	}
	rows := make([]sogaAuditLogRow, 0, len(logs))
	seen := make(map[string]struct{}, len(logs))
	for _, log := range logs {
		if log.UID <= 0 || log.ListID <= 0 {
			continue
		}
		key := fmt.Sprintf("%d:%d", log.UID, log.ListID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		rows = append(rows, sogaAuditLogRow{
			UserID:  log.UID,
			AuditID: log.ListID,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	r, err := c.client.R().
		SetBody(rows).
		ForceContentType("application/json").
		Post("api/v1/audit_log")
	if err != nil {
		return err
	}
	return ensureSogaCodeOK("report audit logs", r)
}

func ensureSogaCodeOK(action string, r interface {
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
	resp := &sogaCodeResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return fmt.Errorf("%s decode response error: %w", action, err)
	}
	if resp.Code != 0 {
		msg := strings.TrimSpace(resp.Message)
		if msg == "" {
			msg = string(r.Body())
		}
		return fmt.Errorf("%s failed, code=%d message=%s", action, resp.Code, msg)
	}
	return nil
}
