package task

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestExecuteWithTimeoutAllowNilReload(t *testing.T) {
	tk := &Task{
		Name:     "nil-reload-timeout",
		Interval: 100 * time.Millisecond,
		Timeout:  20 * time.Millisecond,
		Execute: func() error {
			time.Sleep(80 * time.Millisecond)
			return nil
		},
	}

	start := time.Now()
	if err := tk.ExecuteWithTimeout(); err != nil {
		t.Fatalf("ExecuteWithTimeout returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("timeout did not take effect quickly enough, elapsed=%s", elapsed)
	}
}

func TestExecuteWithTimeoutUseConfiguredTimeout(t *testing.T) {
	var reloadCount atomic.Int32
	tk := &Task{
		Name:     "custom-timeout",
		Interval: 100 * time.Millisecond,
		Timeout:  30 * time.Millisecond,
		Execute: func() error {
			time.Sleep(120 * time.Millisecond)
			return nil
		},
		Reload: func() {
			reloadCount.Add(1)
		},
	}

	if err := tk.ExecuteWithTimeout(); err != nil {
		t.Fatalf("ExecuteWithTimeout returned error: %v", err)
	}
	if got := reloadCount.Load(); got != 1 {
		t.Fatalf("reload callback count mismatch: got %d want 1", got)
	}
}
