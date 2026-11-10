package wsapi

import (
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"

	"whatserver2/internal/store"
)

// serverFrames are the frame types only the server sends: replies and
// pushes. A client frame among them would reach a token unnoticed, so the
// list is checked against every Type constant of the package.
var serverFrames = []string{
	"TypeAPIKeyGone", "TypeAPIKeyNew", "TypeAPIKeys", "TypeAvatarFrame", "TypeBackfillSent", "TypeCallInviteResult",
	"TypeCallMediaResult", "TypeCallResult", "TypeCallsListResult", "TypeChatStarted", "TypeChatTimerSet", "TypeChatUpdate",
	"TypeChats", "TypeContactList", "TypeDeletedNumbers", "TypeDeviceDeleteChecked", "TypeDeviceDetail", "TypeDeviceGone",
	"TypeDeviceNotice", "TypeDeviceNotices", "TypeDeviceRecoverChecked", "TypeDeviceRecovered", "TypeDeviceRemoved",
	"TypeDeviceStats", "TypeDeviceStatus", "TypeDeviceTransferred", "TypeDevices", "TypeError", "TypeExpiredList", "TypeGrants",
	"TypeGroupChanged", "TypeGroupFrame", "TypeGroupJoined", "TypeHistoryFrame", "TypeKeys", "TypeLag", "TypeMessage",
	"TypeMessageFrame", "TypePage", "TypePairCode", "TypePairQR", "TypePairSuccess", "TypePairTimeout", "TypePong",
	"TypePresence", "TypeReaders", "TypeReceipt", "TypeReplayBegin", "TypeReplayEnd", "TypeReprojected", "TypeRetryQueued",
	"TypeSendResult", "TypeSubscriptionEnded", "TypeTokenGrantContextResult", "TypeTokenWaitingList", "TypeUnsupported", "TypeUsers",
	"TypeWelcome",
}

// TestEveryFrameHasATokenRule (the plan's 7.3): every case of dispatch
// has a rule for a token, and every Type constant of the package is a case
// of dispatch, the hello, or a frame only the server sends. So a new frame,
// or a new constant, cannot reach a token by frameAction's read default.
func TestEveryFrameHasATokenRule(t *testing.T) {
	dispatched := dispatchedFrames(t)
	if len(dispatched) < 60 {
		t.Fatalf("found %d dispatched frames; the switch was not parsed", len(dispatched))
	}
	for _, frame := range dispatched {
		if _, ok := tokenRules[frame]; !ok {
			t.Errorf("%q is dispatched with no token rule", frame)
		}
	}
	for frame := range tokenRules {
		if !slices.Contains(dispatched, frame) {
			t.Errorf("%q has a token rule and nothing dispatches it", frame)
		}
	}
	fset := token.NewFileSet()
	//nolint:staticcheck // This contract test intentionally scans all source files, independent of build tags.
	pkg, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, p := range pkg {
		for _, file := range p.Files {
			collectConstants(file, values)
		}
	}
	for name, value := range values {
		if !strings.HasPrefix(name, "Type") || name == "TypeHello" || slices.Contains(dispatched, value) || slices.Contains(serverFrames, name) {
			continue
		}
		t.Errorf("%s (%q) is neither dispatched nor a server frame: give it a token rule, or list it as the server's", name, value)
	}
}

// TestTokenRulesRefuseWhatATokenNeverDoes pins the rules that matter most:
// no pairing of any kind (F1), no calls, no reprojection (H4), nothing of
// accounts, keys, grants given or taken, the grant page, deletion or
// moving; reads need Read, its own grants.list among them, acts their own
// perm, groups and backfill Manage alone, and pausing Manage.
func TestTokenRulesRefuseWhatATokenNeverDoes(t *testing.T) {
	for _, kind := range []string{TypePair, TypePairCancel, TypeUsersList, TypeCallStart, TypeCallsList, TypeReprojectGet, TypeReprojectPut,
		TypeDeviceDelete, TypeDeviceRecover, TypeDeviceTransfer, TypeKeyCreate, TypeKeysList, TypeGrantAdd, TypeGrantRevoke, TypeReaderMode,
		TypeDeviceNoticeSeen, TypeTokenGrantContext, TypeTokenWaiting, TypeTokenGrant, "unknown.frame"} {
		if !ruleOf(kind).refused {
			t.Errorf("%s is not refused to a token", kind)
		}
	}
	for kind, want := range map[string]store.DeviceAction{
		TypeChatPage: store.ActionRead, TypeDeviceInfo: store.ActionView, TypeSend: store.ActionSend, TypeMarkRead: store.ActionSend,
		TypeGroupCreate: store.ActionManage, TypeBackfill: store.ActionManage, TypeDeviceStop: store.ActionPause,
		TypeDeviceStart: store.ActionPause, TypeDeviceRename: store.ActionManage, TypeDeviceMode: store.ActionManage,
		TypeGrantsList: store.ActionRead,
	} {
		if r := ruleOf(kind); r.refused || r.action != want {
			t.Errorf("%s: %+v, want %s", kind, r, want)
		}
	}
	if !ruleOf(TypeMediaRetry).media || !ruleOf(TypeMediaExpired).media || ruleOf(TypeChatPage).media {
		t.Error("the attachments switch gates the wrong frames")
	}
	for _, f := range tokenFeatures() {
		if strings.HasPrefix(f, "pair") || strings.HasPrefix(f, "call") || strings.HasPrefix(f, "apikeys") {
			t.Errorf("a token's welcome lists %q", f)
		}
	}
}
