package wsapi

import (
	"testing"

	"whatserver2/internal/store"
)

// The replay merge, tested directly. Reaching the paging boundary through the
// public interface would take a database, a websocket and more than five
// hundred rows; the ordering rule it is protecting is worth a test that runs in
// microseconds.

func rowsAt(seqs ...int64) []store.Row {
	out := make([]store.Row, 0, len(seqs))
	for _, s := range seqs {
		out = append(out, store.Row{Seq: s})
	}
	return out
}

func acksAt(seqs ...int64) []store.ReceiptBatch {
	out := make([]store.ReceiptBatch, 0, len(seqs))
	for _, s := range seqs {
		out = append(out, store.ReceiptBatch{Seq: s})
	}
	return out
}

// collect runs the merge and records what was emitted, as "m7" / "r8".
func collect(rows []store.Row, acks []store.ReceiptBatch, horizon int64) ([]int64, []string, int) {
	var seqs []int64
	var kinds []string
	n := mergeReplay(rows, acks, horizon,
		func(r store.Row) { seqs = append(seqs, r.Seq); kinds = append(kinds, "m") },
		func(b store.ReceiptBatch) { seqs = append(seqs, b.Seq); kinds = append(kinds, "r") })
	return seqs, kinds, n
}

// TestTheTwoStreamsComeOutInSequenceOrder is the guarantee the whole merge
// exists for. A receipt delivered before its message is a client drawing a tick
// on something it has not been told about.
func TestTheTwoStreamsComeOutInSequenceOrder(t *testing.T) {
	seqs, kinds, n := collect(rowsAt(1, 3, 6), acksAt(2, 4, 5), 100)
	if n != 6 {
		t.Fatalf("emitted %d, want 6", n)
	}
	want := []int64{1, 2, 3, 4, 5, 6}
	for i, s := range seqs {
		if s != want[i] {
			t.Fatalf("order was %v, want %v", seqs, want)
		}
	}
	wantKinds := []string{"m", "r", "m", "r", "r", "m"}
	for i, k := range kinds {
		if k != wantKinds[i] {
			t.Fatalf("kinds were %v, want %v", kinds, wantKinds)
		}
	}
}

// TestNothingIsEmittedPastTheHorizon.
//
// The horizon is the highest sequence both reads actually cover. Emitting a
// receipt at sequence 9 when messages were only read up to 5 would leave the
// client's cursor at 9 with messages 6 to 8 never delivered — and nothing in
// the protocol would ever mention them again.
func TestNothingIsEmittedPastTheHorizon(t *testing.T) {
	seqs, _, n := collect(rowsAt(1, 3, 5), acksAt(2, 9, 10), 5)
	if n != 4 {
		t.Fatalf("emitted %d, want 4 (1, 2, 3, 5)", n)
	}
	for _, s := range seqs {
		if s > 5 {
			t.Fatalf("emitted sequence %d past the horizon of 5; order was %v", s, seqs)
		}
	}
}

// TestAStreamPastTheHorizonDoesNotBlockTheOther. Once one stream runs past the
// cutoff the other must still drain up to it, or a whole page is silently lost.
func TestAStreamPastTheHorizonDoesNotBlockTheOther(t *testing.T) {
	seqs, kinds, n := collect(rowsAt(9, 10), acksAt(1, 2, 3), 5)
	if n != 3 {
		t.Fatalf("emitted %d, want the three receipts below the horizon", n)
	}
	for i, k := range kinds {
		if k != "r" {
			t.Fatalf("emitted a %s at position %d; sequences were %v", k, i, seqs)
		}
	}
}

func TestEitherStreamMayBeEmpty(t *testing.T) {
	if _, _, n := collect(rowsAt(1, 2), nil, 100); n != 2 {
		t.Fatalf("messages alone emitted %d, want 2", n)
	}
	if _, _, n := collect(nil, acksAt(1, 2), 100); n != 2 {
		t.Fatalf("receipts alone emitted %d, want 2", n)
	}
	if _, _, n := collect(nil, nil, 100); n != 0 {
		t.Fatalf("two empty streams emitted %d", n)
	}
}
