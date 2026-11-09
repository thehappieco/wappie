package store

import (
	"context"
	"strings"
	"testing"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
)

// TestLogoutCauseReasonsMatch: 0052's trigger classes a logout by the
// reasons the deletion writes; a reason renamed here and not there would
// class a deletion's logout as the phone's.
func TestLogoutCauseReasonsMatch(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	var def string
	if err := pool.QueryRow(context.Background(), `SELECT pg_get_functiondef('devices_logout_cause'::regproc)`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{reasonNoSession, reasonUnlinkedWhenGone} {
		if !strings.Contains(def, "'"+reason+"'") {
			t.Errorf("devices_logout_cause does not name %q:\n%s", reason, def)
		}
	}
}
