package wa_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"

	"whatserver2/internal/wa"
)

// TestPairingRecordsLinkedAndPlacedAt's pairing half (E0 slice 19): a new
// pairing tells OnLinked once, with the paired session's own identity,
// before its success event, even when whatsmeow's QR channel says success
// before PairSuccess persisted the identity (the store has none yet).
func TestPairingRecordsLinkedAndPlacedAt(t *testing.T) {
	rig := newRelinkRig(t)
	var mu sync.Mutex
	var told []wa.Identity
	s, err := rig.r.StartPairing(context.Background(), relinkTenant, relinkDevice, wa.ReceiptPolicy{Mode: wa.ModePassive},
		wa.PairOptions{Method: wa.PairByQR, OnLinked: func(_ context.Context, linked wa.Identity) {
			mu.Lock()
			defer mu.Unlock()
			told = append(told, linked)
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Cancel(); rig.r.StopAll(context.Background()) })
	rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: fakeQR, Timeout: time.Minute})
	if e := next(t, s); e.Kind != wa.PairEventQR {
		t.Fatalf("first event %+v, want the QR", e)
	}
	// whatsmeow's order: the JIDs on the device, then success, with no
	// PairSuccess handled yet.
	rig.mu.Lock()
	ds := rig.ds
	rig.mu.Unlock()
	pn, lid := linkPN, linkLID
	ds.ID, ds.LID = &pn, lid
	rig.fake.PushQR(whatsmeow.QRChannelSuccess)
	if e := next(t, s); e.Kind != wa.PairEventSuccess {
		t.Fatalf("end %+v, want success", e)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(told) != 1 || told[0].PN != linkPN || told[0].LID != linkLID {
		t.Fatalf("OnLinked told %+v, want the session's identity once", told)
	}
	rig.st.mu.Lock()
	persisted := len(rig.st.identities)
	rig.st.mu.Unlock()
	if persisted != 0 {
		t.Fatalf("the store had %d identities before success", persisted)
	}
}

// A relink is no link: OnLinked is never told (the relink's own options
// carry none, and finishRelink attaches instead).
func TestRelinkNeverTellsOnLinked(t *testing.T) {
	opts := wa.PairOptions{Method: wa.PairByQR, Relink: &wa.Relink{Expect: wa.Identity{PN: relinkPN, LID: relinkLID}},
		OnLinked: func(context.Context, wa.Identity) { t.Fatal("a relink told OnLinked") }}
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
}
