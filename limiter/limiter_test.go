package limiter

import (
	"testing"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

func TestUpdateDynamicSpeedLimitByUIDFastPath(t *testing.T) {
	Init()
	tag := "test-fast"
	users := []panel.UserInfo{
		{Id: 1001, Uuid: "uuid-1", SpeedLimit: 100},
		{Id: 1002, Uuid: "uuid-2", SpeedLimit: 100},
	}
	l := AddLimiter("v2ray", tag, users, map[int]int{})
	defer DeleteLimiter(tag)

	expire := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	if err := l.UpdateDynamicSpeedLimitByUID(1002, 25, expire); err != nil {
		t.Fatalf("UpdateDynamicSpeedLimitByUID returned error: %v", err)
	}

	taguuid := format.UserTag(tag, "uuid-2")
	value, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		t.Fatalf("missing user limit info for %s", taguuid)
	}
	info := value.(*UserLimitInfo)
	if info.DynamicSpeedLimit != 25 {
		t.Fatalf("unexpected dynamic speed: got %d want 25", info.DynamicSpeedLimit)
	}
	if info.ExpireTime != expire.Unix() {
		t.Fatalf("unexpected expire time: got %d want %d", info.ExpireTime, expire.Unix())
	}
}

func TestUpdateDynamicSpeedLimitByUIDStaleIndexFallback(t *testing.T) {
	Init()
	tag := "test-stale-index"
	users := []panel.UserInfo{
		{Id: 2001, Uuid: "uuid-a", SpeedLimit: 100},
		{Id: 2002, Uuid: "uuid-b", SpeedLimit: 100},
	}
	l := AddLimiter("v2ray", tag, users, map[int]int{})
	defer DeleteLimiter(tag)

	l.UIDtoTagUUID.Store(2002, "bad-key")
	expire := time.Now().Add(time.Minute).Truncate(time.Second)
	if err := l.UpdateDynamicSpeedLimitByUID(2002, 30, expire); err != nil {
		t.Fatalf("UpdateDynamicSpeedLimitByUID with stale index returned error: %v", err)
	}

	key, ok := l.UIDtoTagUUID.Load(2002)
	if !ok {
		t.Fatalf("uid index was not repaired")
	}
	want := format.UserTag(tag, "uuid-b")
	if key.(string) != want {
		t.Fatalf("unexpected uid index key: got %q want %q", key.(string), want)
	}
}
