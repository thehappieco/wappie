package store

import (
	"testing"
	"time"

	"whatserver2/internal/domain"
)

func TestDeletionAttributionUsesIdentityEvidence(t *testing.T) {
	const pn = "5511999999999@s.whatsapp.net"
	const lid = "91938170638392@lid"
	for _, tc := range []struct {
		name          string
		root, revoke  Row
		author, admin bool
	}{
		{"private changed addressing", Row{SenderKey: pn}, Row{SenderKey: lid}, true, false},
		{"private unknown sender", Row{}, Row{}, true, false},
		{"private outgoing revoked by other flag", Row{IsFromMe: true, SenderKey: pn}, Row{SenderKey: lid}, true, false},
		{"group same key", Row{IsGroup: true, SenderKey: lid}, Row{SenderKey: lid}, true, false},
		{"group matches phone alias", Row{IsGroup: true, SenderKey: pn}, Row{SenderKey: lid, SenderPN: pn}, true, false},
		{"group matches lid alias", Row{IsGroup: true, SenderKey: pn, SenderLID: lid}, Row{SenderKey: lid}, true, false},
		{"group strips device suffix", Row{IsGroup: true, SenderKey: "5511999999999:2@s.whatsapp.net"}, Row{SenderKey: pn}, true, false},
		{"group own message via another device", Row{IsGroup: true, IsFromMe: true, SenderKey: pn}, Row{IsFromMe: true, SenderKey: lid}, true, false},
		{"group different known phones", Row{IsGroup: true, SenderKey: pn}, Row{SenderKey: "5511888888888@s.whatsapp.net"}, false, true},
		{"group different known lids", Row{IsGroup: true, SenderKey: lid}, Row{SenderKey: "12345@lid"}, false, true},
		{"group own message deleted by other person", Row{IsGroup: true, IsFromMe: true, SenderKey: pn}, Row{SenderKey: lid}, false, true},
		{"group unrelated address namespaces stay unknown", Row{IsGroup: true, SenderKey: pn}, Row{SenderKey: lid}, false, false},
		{"group sender missing stays unknown", Row{IsGroup: true, SenderKey: pn}, Row{}, false, false},
		{"group malformed sender stays unknown", Row{IsGroup: true, SenderKey: pn}, Row{SenderKey: "invalid"}, false, false},
		{"group same alias wins over unmatched key", Row{IsGroup: true, SenderKey: lid, SenderPN: pn}, Row{SenderKey: "12345@lid", SenderPN: pn}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			author, admin := deletionAttribution(tc.root, tc.revoke)
			if author != tc.author || admin != tc.admin {
				t.Fatalf("author=%v admin=%v, want author=%v admin=%v", author, admin, tc.author, tc.admin)
			}
		})
	}
}

func TestDeletionAttributionUsesFirstMessageRevokeNotReactionWithdrawal(t *testing.T) {
	root := Row{IsGroup: true, SenderKey: "111@lid"}
	first := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	later := first.Add(time.Minute)
	got := deletionOf(root, []Row{
		{Seq: 9, Kind: domain.KindDelete, SenderKey: "111@lid", TS: &later},
		{Seq: 1, Kind: domain.KindDelete, TargetRel: domain.TargetReaction, SenderKey: "111@lid"},
		{Seq: 5, Kind: domain.KindDelete, SenderKey: "222@lid", TS: &first},
	})
	if got == nil || got.Row.Seq != 5 || got.ByAuthor || !got.ByAdmin || !got.At.Equal(first) {
		t.Fatalf("deletion=%+v, want first message revoke by another group member", got)
	}
	if got := deletionOf(root, []Row{{Kind: domain.KindDelete, TargetRel: domain.TargetReaction}}); got != nil {
		t.Fatalf("reaction withdrawal produced a message deletion: %+v", got)
	}
}
