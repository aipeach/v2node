package panel

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

type modMUUsersResponse struct {
	Ret  int            `json:"ret"`
	Data []modMUUserRow `json:"data"`
}

type modMUUserRow struct {
	ID             int         `json:"id"`
	UUID           string      `json:"uuid"`
	Passwd         string      `json:"passwd"`
	Port           interface{} `json:"port"`
	Method         string      `json:"method"`
	Protocol       string      `json:"protocol"`
	ProtocolParam  string      `json:"protocol_param"`
	Obfs           string      `json:"obfs"`
	ObfsParam      string      `json:"obfs_param"`
	IsMultiUser    interface{} `json:"is_multi_user"`
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
	if isSSRNodeType(c.NodeType) {
		var err error
		users, alive, err = c.buildSSRUsers(resp.Data)
		if err != nil {
			return nil, err
		}
	} else if isShadowsocksNodeType(c.NodeType) {
		var err error
		users, alive, err = c.buildShadowsocksUsers(resp.Data)
		if err != nil {
			return nil, err
		}
	} else if isAnyTLSNodeType(c.NodeType) {
		var err error
		users, alive, err = c.buildAnyTLSUsers(resp.Data)
		if err != nil {
			return nil, err
		}
	} else {
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

const (
	defaultSSRMUSuffix        = "microsoft.com"
	defaultSSRMURegex         = "%5m%id.%suffix"
	SSRSinglePortModeAuto     = "auto"
	SSRSinglePortModeProtocol = "protocol"
	SSRSinglePortModeObfs     = "obfs"
)

var ssrHashSlicePattern = regexp.MustCompile(`%(-?\d+)m`)

func normalizeSSRMUSettings(muSuffix, muRegex string) (string, string) {
	muSuffix = strings.TrimSpace(muSuffix)
	muRegex = strings.TrimSpace(muRegex)
	if muSuffix == "" {
		muSuffix = defaultSSRMUSuffix
	}
	if muRegex == "" {
		muRegex = defaultSSRMURegex
	}
	return muSuffix, muRegex
}

func normalizeSSRSinglePortMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return SSRSinglePortModeAuto
	case "protocol":
		return SSRSinglePortModeProtocol
	case "obfs":
		return SSRSinglePortModeObfs
	default:
		return ""
	}
}

// GetSSRSinglePortModes returns available single-port carrier modes from mod_mu users.
func (c *Client) GetSSRSinglePortModes() ([]string, error) {
	if !isSSRNodeType(c.NodeType) {
		return nil, nil
	}
	const path = "/mod_mu/users"
	r, err := c.client.R().Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("received nil response")
	}
	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("get user list for ssr modes failed with status %d: %s", r.StatusCode(), string(r.Body()))
	}
	resp := &modMUUsersResponse{}
	if err := json.Unmarshal(r.Body(), resp); err != nil {
		return nil, fmt.Errorf("decode mod_mu user list error: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("mod_mu user list ret=%d, body=%s", resp.Ret, string(r.Body()))
	}
	hasProtocol := false
	hasObfs := false
	for _, row := range resp.Data {
		switch intFromAny(row.IsMultiUser) {
		case 2:
			hasProtocol = true
		case 1:
			if isFilteredSSRObfsSinglePortTemplate(row) {
				continue
			}
			hasObfs = true
		}
	}
	modes := make([]string, 0, 2)
	if hasProtocol {
		modes = append(modes, SSRSinglePortModeProtocol)
	}
	if hasObfs {
		modes = append(modes, SSRSinglePortModeObfs)
	}
	return modes, nil
}

func (c *Client) buildShadowsocksUsers(rows []modMUUserRow) ([]UserInfo, map[int]int, error) {
	if _, err := findShadowsocksTemplateUser(rows); err != nil {
		return nil, nil, err
	}

	users := make([]UserInfo, 0, len(rows))
	alive := make(map[int]int, len(rows))
	for _, row := range rows {
		if row.ID <= 0 {
			continue
		}
		if intFromAny(row.IsMultiUser) != 0 {
			continue
		}

		passwd := strings.TrimSpace(row.Passwd)
		if passwd == "" {
			continue
		}

		// Use id:passwd to ensure uniqueness and detect password updates.
		uuid := fmt.Sprintf("%d:%s", row.ID, passwd)
		users = append(users, UserInfo{
			Id:               row.ID,
			Uuid:             uuid,
			SpeedLimit:       intFromAny(row.NodeSpeedlimit),
			DeviceLimit:      intFromAny(row.NodeConnector),
			SSClientPassword: passwd,
		})
		alive[row.ID] = intFromAny(row.AliveIP)
	}
	return users, alive, nil
}

func (c *Client) buildAnyTLSUsers(rows []modMUUserRow) ([]UserInfo, map[int]int, error) {
	users := make([]UserInfo, 0, len(rows))
	alive := make(map[int]int, len(rows))
	for _, row := range rows {
		if row.ID <= 0 {
			continue
		}
		uuid := strings.TrimSpace(row.UUID)
		if uuid == "" {
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
	return users, alive, nil
}

func (c *Client) buildSSRUsers(rows []modMUUserRow) ([]UserInfo, map[int]int, error) {
	selectedMode := normalizeSSRSinglePortMode(c.SSRSinglePortMode)
	if selectedMode == "" {
		_, selectedMode = parseSSRNodeType(c.NodeType)
	}
	templateUser, err := findSSRTemplateUser(rows, selectedMode)
	if err != nil {
		return nil, nil, err
	}
	mode := ssrSinglePortModeFromFlag(intFromAny(templateUser.IsMultiUser))
	if mode == "" {
		return nil, nil, fmt.Errorf("unknown ssr single-port mode from is_multi_user=%v", templateUser.IsMultiUser)
	}
	muSuffix, muRegex := normalizeSSRMUSettings(c.MUSuffix, c.MURegex)
	users := make([]UserInfo, 0, len(rows))
	alive := make(map[int]int, len(rows))
	for _, row := range rows {
		if row.ID <= 0 {
			continue
		}
		// is_multi_user=2 是 SSR 单端口承载用户；普通用户是 0。
		if intFromAny(row.IsMultiUser) != 0 {
			continue
		}

		passwd := strings.TrimSpace(row.Passwd)
		obfsParam := strings.TrimSpace(row.ObfsParam)
		protocolParam := ""
		uuid := ""
		switch mode {
		case SSRSinglePortModeProtocol:
			protocolParam = strings.TrimSpace(row.ProtocolParam)
			if passwd != "" {
				// SSR 协议式单端口：协议参数固定由 id:passwd 生成。
				protocolParam = fmt.Sprintf("%d:%s", row.ID, passwd)
			}
			if protocolParam == "" {
				continue
			}
			uuid = protocolParam
		case SSRSinglePortModeObfs:
			// SS 混淆式单端口：按 mu_regex + mu_suffix 规则生成混淆参数。
			obfsParam = buildSSRMultiUserObfsParam(muRegex, muSuffix, row)
			if obfsParam == "" {
				continue
			}
			// 使用 id + obfsParam，确保 email 唯一且在 obfsParam 变化时可触发更新。
			uuid = fmt.Sprintf("%d:%s", row.ID, obfsParam)
		default:
			return nil, nil, fmt.Errorf("unknown ssr single-port mode: %s", mode)
		}

		users = append(users, UserInfo{
			Id:                row.ID,
			Uuid:              uuid,
			SpeedLimit:        intFromAny(row.NodeSpeedlimit),
			DeviceLimit:       intFromAny(row.NodeConnector),
			SSRClientPassword: passwd,
			SSRProtocolParam:  protocolParam,
			SSROBFSParam:      obfsParam,
		})
		alive[row.ID] = intFromAny(row.AliveIP)
	}
	return users, alive, nil
}

func findSSRTemplateUser(rows []modMUUserRow, selectedMode string) (*modMUUserRow, error) {
	findByFlag := func(flag int, accept func(modMUUserRow) bool) *modMUUserRow {
		for i := range rows {
			if intFromAny(rows[i].IsMultiUser) != flag {
				continue
			}
			if accept != nil && !accept(rows[i]) {
				continue
			}
			return &rows[i]
		}
		return nil
	}
	acceptAny := func(_ modMUUserRow) bool {
		return true
	}
	acceptObfsTemplate := func(row modMUUserRow) bool {
		return !isFilteredSSRObfsSinglePortTemplate(row)
	}
	switch selectedMode {
	case SSRSinglePortModeProtocol:
		if user := findByFlag(2, acceptAny); user != nil {
			return user, nil
		}
		return nil, fmt.Errorf("ssr protocol single-port template user not found (is_multi_user=2)")
	case SSRSinglePortModeObfs:
		if user := findByFlag(1, acceptObfsTemplate); user != nil {
			return user, nil
		}
		return nil, fmt.Errorf("ssr obfs single-port template user not found (is_multi_user=1, excluding protocol=origin obfs=plain)")
	default:
		// auto: 优先协议式，再退回混淆式。
		if user := findByFlag(2, acceptAny); user != nil {
			return user, nil
		}
		if user := findByFlag(1, acceptObfsTemplate); user != nil {
			return user, nil
		}
		return nil, fmt.Errorf("ssr single-port template user not found (is_multi_user=2 or valid is_multi_user=1)")
	}
}

func isFilteredSSRObfsSinglePortTemplate(row modMUUserRow) bool {
	if intFromAny(row.IsMultiUser) != 1 {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(row.Protocol))
	obfs := strings.ToLower(strings.TrimSpace(row.Obfs))
	return proto == "origin" && obfs == "plain"
}

func findShadowsocksTemplateUser(rows []modMUUserRow) (*modMUUserRow, error) {
	for i := range rows {
		if isShadowsocksSinglePortTemplate(rows[i]) {
			return &rows[i], nil
		}
	}
	return nil, fmt.Errorf("shadowsocks single-port template user not found (is_multi_user=1 with aead method + protocol=origin + obfs=plain)")
}

func isShadowsocksSinglePortTemplate(row modMUUserRow) bool {
	if intFromAny(row.IsMultiUser) != 1 {
		return false
	}
	method := normalizeShadowsocksMethod(row.Method)
	if !isShadowsocksSinglePortAEADMethod(method) {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(row.Protocol))
	obfs := strings.ToLower(strings.TrimSpace(row.Obfs))
	return proto == "origin" && obfs == "plain"
}

func normalizeShadowsocksMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aead_aes_128_gcm":
		return "aes-128-gcm"
	case "aead_aes_192_gcm":
		return "aes-192-gcm"
	case "aead_aes_256_gcm":
		return "aes-256-gcm"
	case "chacha20-poly1305", "aead_chacha20_poly1305":
		return "chacha20-ietf-poly1305"
	default:
		return strings.ToLower(strings.TrimSpace(method))
	}
}

func isShadowsocksSinglePortAEADMethod(method string) bool {
	switch normalizeShadowsocksMethod(method) {
	case "aes-128-gcm",
		"aes-192-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm":
		return true
	default:
		return false
	}
}

func isShadowsocks2022Method(method string) bool {
	switch normalizeShadowsocksMethod(method) {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return true
	default:
		return false
	}
}

func ssrSinglePortModeFromFlag(v int) string {
	switch v {
	case 2:
		return SSRSinglePortModeProtocol
	case 1:
		return SSRSinglePortModeObfs
	default:
		return ""
	}
}

func buildSSRMultiUserObfsParam(pattern, suffix string, row modMUUserRow) string {
	feature := strconv.Itoa(row.ID) +
		strings.TrimSpace(row.Passwd) +
		strings.TrimSpace(row.Method) +
		strings.TrimSpace(row.Obfs) +
		strings.TrimSpace(row.Protocol)
	md5Sum := md5.Sum([]byte(feature))
	md5Hex := hex.EncodeToString(md5Sum[:])

	param := ssrHashSlicePattern.ReplaceAllStringFunc(pattern, func(token string) string {
		n, err := strconv.Atoi(token[1 : len(token)-1])
		if err != nil {
			return token
		}
		return sliceSSRHash(md5Hex, n)
	})
	param = strings.ReplaceAll(param, "%m", md5Hex)
	param = strings.ReplaceAll(param, "%id", strconv.Itoa(row.ID))
	param = strings.ReplaceAll(param, "%suffix", suffix)
	return strings.TrimSpace(param)
}

func sliceSSRHash(hash string, n int) string {
	if hash == "" || n == 0 {
		return hash
	}
	if n > 0 {
		if n >= len(hash) {
			return hash
		}
		return hash[:n]
	}
	count := -n
	if count >= len(hash) {
		return hash
	}
	return hash[len(hash)-count:]
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
