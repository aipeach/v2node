package limiter

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/rate"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter
var prefixLock sync.RWMutex
var userIPLimitCIDRPrefixV4 = 32
var userIPLimitCIDRPrefixV6 = 128

func Init() {
	limiter = map[string]*Limiter{}
}

func SetUserIPLimitCIDRPrefix(v4, v6 int) {
	prefixLock.Lock()
	defer prefixLock.Unlock()
	userIPLimitCIDRPrefixV4 = clampPrefix(v4, 0, 32)
	userIPLimitCIDRPrefixV6 = clampPrefix(v6, 0, 128)
}

type Limiter struct {
	DomainRules   []*regexp.Regexp
	ProtocolRules []string
	SpeedLimit    int
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Key: Ip, value: Uid
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UIDtoTagUUID  *sync.Map      // Key: Uid, value: TagUUID
	UserLimitInfo *sync.Map      // Key: TagUUID value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *rate.DynamicBucket
	AliveList     map[int]int    // Key: Uid, value: alive_ip
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func AddLimiter(tag string, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     aliveList,
		OldUserOnline: new(sync.Map),
		UIDtoTagUUID:  new(sync.Map),
	}
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		taguuid := format.UserTag(tag, users[i].Uuid)
		info.UserLimitInfo.Store(taguuid, userLimit)
		info.UIDtoTagUUID.Store(users[i].Id, taguuid)
	}
	info.UUIDtoUID = uuidmap
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	for i := range deleted {
		taguuid := format.UserTag(tag, deleted[i].Uuid)
		l.UserLimitInfo.Delete(taguuid)
		l.UserOnlineIP.Delete(taguuid)
		l.SpeedLimiter.Delete(taguuid)
		l.UIDtoTagUUID.Delete(deleted[i].Id)
		delete(l.UUIDtoUID, deleted[i].Uuid)
		delete(l.AliveList, deleted[i].Id)
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		taguuid := format.UserTag(tag, added[i].Uuid)
		l.UserLimitInfo.Store(taguuid, userLimit)
		l.UIDtoTagUUID.Store(added[i].Id, taguuid)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
	}
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	taguuid := format.UserTag(tag, uuid)
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		info := v.(*UserLimitInfo)
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
		l.SpeedLimiter.Delete(taguuid)
	} else {
		return errors.New("not found")
	}
	return nil
}

func (l *Limiter) UpdateDynamicSpeedLimitByUID(uid int, limit int, expire time.Time) error {
	taguuid, info, found := l.lookupUserLimitByUID(uid)
	if !found {
		return errors.New("not found")
	}
	info.DynamicSpeedLimit = limit
	info.ExpireTime = expire.Unix()
	l.SpeedLimiter.Delete(taguuid)
	return nil
}

func (l *Limiter) lookupUserLimitByUID(uid int) (string, *UserLimitInfo, bool) {
	if key, ok := l.UIDtoTagUUID.Load(uid); ok {
		taguuid := key.(string)
		if value, ok := l.UserLimitInfo.Load(taguuid); ok {
			info := value.(*UserLimitInfo)
			if info.UID == uid {
				return taguuid, info, true
			}
		}
		// stale mapping, fallback to full scan to self-heal
		l.UIDtoTagUUID.Delete(uid)
	}

	var taguuid string
	var foundInfo *UserLimitInfo
	l.UserLimitInfo.Range(func(key, value interface{}) bool {
		info := value.(*UserLimitInfo)
		if info.UID != uid {
			return true
		}
		taguuid = key.(string)
		foundInfo = info
		return false
	})
	if foundInfo == nil {
		return "", nil, false
	}
	l.UIDtoTagUUID.Store(uid, taguuid)
	return taguuid, foundInfo, true
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (dynamicBucket *rate.DynamicBucket, Reject bool) {
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")
	ip = normalizeUserIPByPrefix(ip)

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if syncGlobalDynamicSpeedLimit(uid, u) {
			l.SpeedLimiter.Delete(taguuid)
		}
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			if u.SpeedLimit != 0 {
				userLimit = u.SpeedLimit
				u.DynamicSpeedLimit = 0
				u.ExpireTime = 0
				l.SpeedLimiter.Delete(taguuid)
			} else {
				l.UserLimitInfo.Delete(taguuid)
				l.SpeedLimiter.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
		}
	} else {
		return nil, true
	}
	if noSSUDP {
		// Store online user for device limit
		newipMap := new(sync.Map)
		newipMap.Store(ip, uid)
		aliveIp := l.AliveList[uid]
		// If any device is online
		if v, loaded := l.UserOnlineIP.LoadOrStore(taguuid, newipMap); loaded {
			oldipMap := v.(*sync.Map)
			// If this is a new ip
			if _, loaded := oldipMap.LoadOrStore(ip, uid); !loaded {
				if v, loaded := l.OldUserOnline.Load(ip); loaded {
					if v.(int) == uid {
						l.OldUserOnline.Delete(ip)
					}
				} else if deviceLimit > 0 {
					if deviceLimit <= aliveIp {
						oldipMap.Delete(ip)
						return nil, true
					}
				}
			}
		} else if v, ok := l.OldUserOnline.Load(ip); ok {
			if v.(int) == uid {
				l.OldUserOnline.Delete(ip)
			}
		} else {
			if deviceLimit > 0 {
				if deviceLimit <= aliveIp {
					l.UserOnlineIP.Delete(taguuid)
					return nil, true
				}
			}
		}
		if checkGlobalDeviceLimit(uid, deviceLimit, ip) {
			return nil, true
		}
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8 // If you need the Speed limit
	if limit > 0 {
		if v, ok := l.SpeedLimiter.Load(taguuid); ok {
			return v.(*rate.DynamicBucket), false
		} else {
			d := rate.NewDynamicBucket(limit)
			l.SpeedLimiter.Store(taguuid, d)
			return d, false
		}
	} else {
		return nil, false
	}
}

func normalizeUserIPByPrefix(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip
	}
	prefixLock.RLock()
	v4Prefix := userIPLimitCIDRPrefixV4
	v6Prefix := userIPLimitCIDRPrefixV6
	prefixLock.RUnlock()

	if ipv4 := parsedIP.To4(); ipv4 != nil {
		return ipv4.Mask(net.CIDRMask(v4Prefix, 32)).String()
	}
	if normalized := parsedIP.Mask(net.CIDRMask(v6Prefix, 128)); normalized != nil {
		return normalized.String()
	}
	return ip
}

func clampPrefix(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	var onlineUser []panel.OnlineUser
	l.OldUserOnline = new(sync.Map)
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.OldUserOnline.Store(ip, uid)
			onlineUser = append(onlineUser, panel.OnlineUser{UID: uid, IP: ip})
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
