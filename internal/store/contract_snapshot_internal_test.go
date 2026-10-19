package store

import (
	"testing"
	"time"
)

// The plan's DB12: a number's state and reason. The mapping is total: a
// deleted number is deleted; a number Wappie captures nothing for (paused,
// logged out, banned, over its storage, in a workspace not active) is
// paused with a reason, the first that holds, never active; everything
// else is active.
func TestSnapshotState(t *testing.T) {
	type c struct {
		deleted, paused bool
		cause, status   string
		active, quota   bool
	}
	for _, x := range []struct {
		in            c
		state, reason string
	}{
		{c{false, false, "", "online", true, false}, SnapshotActive, ""},
		{c{false, false, "", "offline", true, false}, SnapshotActive, ""},
		{c{false, false, "", "new", true, false}, SnapshotActive, ""},
		{c{false, true, PauseByPerson, "online", true, false}, SnapshotSyncPaused, SnapshotByPerson},
		{c{false, true, PauseForMove, "online", true, false}, SnapshotSyncPaused, SnapshotError},
		{c{false, true, PauseForDeletion, "online", true, false}, SnapshotSyncPaused, SnapshotError},
		{c{false, true, "", "online", true, false}, SnapshotSyncPaused, SnapshotError},
		{c{false, false, "", "logged_out", true, false}, SnapshotSyncPaused, SnapshotNeedsReauth},
		{c{false, true, PauseByPerson, "logged_out", false, true}, SnapshotSyncPaused, SnapshotNeedsReauth},
		{c{false, false, "", "banned", true, false}, SnapshotSyncPaused, SnapshotError},
		{c{false, false, "", "online", false, false}, SnapshotSyncPaused, SnapshotError},
		{c{false, true, PauseByPerson, "online", false, true}, SnapshotSyncPaused, SnapshotError},
		{c{false, false, "", "online", true, true}, SnapshotSyncPaused, SnapshotQuota},
		{c{false, true, PauseByPerson, "offline", true, true}, SnapshotSyncPaused, SnapshotQuota},
		{c{true, true, PauseForDeletion, "logged_out", false, true}, SnapshotDeleted, ""},
		{c{true, true, PauseByPerson, "online", true, false}, SnapshotDeleted, ""},
	} {
		state, reason := snapshotState(x.in.deleted, x.in.paused, x.in.cause, x.in.status, x.in.active, x.in.quota)
		if state != x.state || reason != x.reason {
			t.Errorf("%+v: %s/%s, want %s/%s", x.in, state, reason, x.state, x.reason)
		}
	}
	// Every combination: never active while Wappie captures nothing, and a
	// paused item always says why.
	for _, deleted := range []bool{false, true} {
		for _, paused := range []bool{false, true} {
			for _, cause := range []string{"", PauseByPerson, PauseForMove, PauseForDeletion} {
				for _, status := range []string{"new", "pairing", "online", "offline", "logged_out", "banned"} {
					for _, active := range []bool{false, true} {
						for _, quota := range []bool{false, true} {
							state, reason := snapshotState(deleted, paused, cause, status, active, quota)
							capturing := !paused && status != "logged_out" && status != "banned" && active && !quota
							switch {
							case deleted && state != SnapshotDeleted,
								!deleted && capturing != (state == SnapshotActive),
								(state == SnapshotSyncPaused) != (reason != ""):
								t.Errorf("deleted=%v paused=%v cause=%q status=%s active=%v quota=%v: %s/%q",
									deleted, paused, cause, status, active, quota, state, reason)
							}
						}
					}
				}
			}
		}
	}
}

// The backoff after a snapshot not accepted: 5 s doubled with each failure
// in a row, up to an hour (the plan's 4.10).
func TestSnapshotBackoff(t *testing.T) {
	times := ContractSnapshotTimes{BackoffMin: 5 * time.Second, BackoffMax: time.Hour}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second}
	for tries, w := range want {
		if got := snapshotBackoff(tries, times); got != w {
			t.Errorf("after %d failures: %v, want %v", tries, got, w)
		}
	}
	for _, tries := range []int{10, 11, 40, 1000} {
		if got := snapshotBackoff(tries, times); got != time.Hour {
			t.Errorf("after %d failures: %v, want an hour", tries, got)
		}
	}
	if SnapshotNotFoundFor != 24*time.Hour {
		t.Errorf("a not_found parks after %v, want 24 hours (README 8)", SnapshotNotFoundFor)
	}
}
