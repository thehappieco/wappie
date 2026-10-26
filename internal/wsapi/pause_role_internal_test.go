package wsapi

import (
	"strings"
	"testing"

	"whatserver2/internal/store"
)

// Only device.stop and device.start moved to the role rule (the owner's
// answer of 2026-10-26): every other frame that managed a number still
// needs Manage.
func TestOnlyStopAndStartPauseByRole(t *testing.T) {
	for _, frame := range []string{TypeDeviceStop, TypeDeviceStart} {
		if got := frameAction(frame); got != store.ActionPause {
			t.Errorf("%s needs %s, want %s", frame, got, store.ActionPause)
		}
	}
	for _, frame := range []string{TypeGroupCreate, TypeGroupParticipants, TypeGroupLeave, TypeDeviceRename, TypeDeviceMode,
		TypeDeviceDelete, TypeBackfill, TypeGroupJoin, TypeReprojectPut, TypeGrantAdd, TypeGrantRevoke,
		TypeDeviceDeleteCheck, TypeDevicesDeleted, TypeDeviceRecoverCheck, TypeDeviceRecover} {
		if got := frameAction(frame); got != store.ActionManage {
			t.Errorf("%s needs %s, want %s", frame, got, store.ActionManage)
		}
	}
}

// The refusal names the rule, by who asked.
func TestPauseRefusalNamesTheRule(t *testing.T) {
	for _, tc := range []struct {
		who  actor
		says string
	}{
		{actor{person: true, role: "member"}, "only an owner or an admin of this workspace"},
		{actor{service: true}, "acting as a service account with the number's Manage permission"},
		{actor{}, "needs an API key with full scope that reaches the number"},
	} {
		if got := refusal(tc.who, store.ActionPause); !strings.Contains(got, tc.says) {
			t.Errorf("%+v: %q", tc.who, got)
		}
	}
	if got := refusal(actor{person: true}, store.ActionManage); !strings.Contains(got, "manage permission") {
		t.Errorf("the other refusals changed: %q", got)
	}
}
