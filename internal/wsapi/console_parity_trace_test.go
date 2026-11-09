package wsapi_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/wsapi"
)

// pauseTrace is everything a stop or a resume wrote of one number but its
// ids and times: each event and each notice whole, as JSON, the number's
// own label written "<own>", a hint "<hint>" (the twins' numbers differ),
// and whether a notice is resumed, seen or folded.
type pauseTrace struct {
	Events  []map[string]any
	Notices []map[string]any
	Row     numberRow
}

func (p *parity) pauseTrace(t *testing.T, device uuid.UUID) pauseTrace {
	t.Helper()
	ctx := context.Background()
	var own string
	var events, notices [][]byte
	var flags [][3]bool
	p.scoped(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT label FROM devices WHERE id = $1`, device).Scan(&own); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT to_jsonb(e) FROM item_events e WHERE item_id = $1 ORDER BY seq`, device)
		if err != nil {
			return err
		}
		if events, err = pgx.CollectRows(rows, pgx.RowTo[[]byte]); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT to_jsonb(n), resumed_at IS NOT NULL, seen_at IS NOT NULL, last_raised_at IS NOT NULL
			FROM device_notices n WHERE device_id = $1 ORDER BY user_id, kind`, device)
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw []byte
			var f [3]bool
			if err := rows.Scan(&raw, &f[0], &f[1], &f[2]); err != nil {
				return err
			}
			notices, flags = append(notices, raw), append(flags, f)
		}
		return rows.Err()
	})
	hints := map[any]bool{}
	norm := func(raw []byte, drop ...string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range m {
			switch {
			case strings.HasSuffix(k, "_at") || slices.Contains(drop, k):
				delete(m, k)
			case k == "label" && v == own:
				m[k] = "<own>"
			case k == "hint" && v != nil:
				hints[v] = true
				m[k] = "<hint>"
			}
			if list, ok := v.([]any); ok {
				slices.SortFunc(list, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
			}
		}
		return m
	}
	out := pauseTrace{Row: p.numberRow(t, device)}
	out.Row.Label = ""
	for _, raw := range events {
		out.Events = append(out.Events, norm(raw, "seq", "event_id", "item_id", "dedupe_key", "purge_after"))
	}
	for i, raw := range notices {
		n := norm(raw, "id", "device_id")
		n["resumed"], n["seen"], n["folded"] = flags[i][0], flags[i][1], flags[i][2]
		out.Notices = append(out.Notices, n)
	}
	if len(hints) > 1 {
		t.Fatalf("%s's rows carry %d hints", device, len(hints))
	}
	return out
}

// sameTrace fails unless the frame's number and the runner's carry the
// same trace.
func (p *parity) sameTrace(t *testing.T, step string, frame, console uuid.UUID) pauseTrace {
	t.Helper()
	f, c := p.pauseTrace(t, frame), p.pauseTrace(t, console)
	if !reflect.DeepEqual(f, c) {
		fj, _ := json.MarshalIndent(f, "", " ")
		cj, _ := json.MarshalIndent(c, "", " ")
		t.Fatalf("%s: the frame's\n%s\nthe runner's\n%s", step, fj, cj)
	}
	return f
}

// TestConsoleParityPauseTrace: a stop, a resume and a stop by another
// admin, by the frame on one twin and the runner on the other, leave the
// same events and notices field by field (the event's type, actor kind,
// sub and account, readers' subs and accounts, label and hint; each
// notice's person, kind, label, hint, raiser and their kind, pauses,
// several actors, resumed, seen and folded), not only their counts: the
// runner's pause is a copy of the frame's (consolePauseTx).
func TestConsoleParityPauseTrace(t *testing.T) {
	p := newParity(t)
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	reader, _ := p.person(t, "caio", "member")
	p.link(t, reader, "member")
	dora, doraToken := p.person(t, "dora", "admin")
	doraSub := p.link(t, dora, "admin")
	frame, console := p.linkedDevice(t, "Twin"), p.linkedDevice(t, "Twin")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		p.reads(t, reader, d)
		p.reads(t, dora, d)
	}
	ref := wsapi.DeviceRef{DeviceID: frame.String()}

	if fo, co := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStop, ref), wsapi.TypeDeviceStatus),
		p.outcome(p.runnerStop(t, admin, adminSub, console)); fo != "ok" || co != "ok" {
		t.Fatalf("the first stop: the frame %s, the runner %s", fo, co)
	}
	tr := p.sameTrace(t, "after a stop", frame, console)
	if len(tr.Events) != 1 || len(tr.Notices) != 3 || tr.Events[0]["label"] != "<own>" || tr.Events[0]["actor_sub"] != adminSub.String() {
		t.Fatalf("after a stop: %+v", tr)
	}

	if fo, co := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceStart, ref), wsapi.TypeDeviceStatus),
		p.outcome(p.runnerResume(t, admin, adminSub, console)); fo != "ok" || co != "ok" {
		t.Fatalf("the resume: the frame %s, the runner %s", fo, co)
	}
	tr = p.sameTrace(t, "after a resume", frame, console)
	for _, n := range tr.Notices {
		if n["resumed"] != true {
			t.Fatalf("after a resume: %+v", n)
		}
	}

	// Another admin stops again: the unseen notices fold, open again, and
	// name several actors.
	if fo, co := frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: doraToken}, wsapi.TypeDeviceStop, ref), wsapi.TypeDeviceStatus),
		p.outcome(p.runnerStop(t, dora, doraSub, console)); fo != "ok" || co != "ok" {
		t.Fatalf("the second stop: the frame %s, the runner %s", fo, co)
	}
	tr = p.sameTrace(t, "after a stop, a resume and another's stop", frame, console)
	if len(tr.Events) != 2 || len(tr.Notices) != 3 {
		t.Fatalf("after the fold: %+v", tr)
	}
	for _, n := range tr.Notices {
		// The second stop's actor is told nothing: theirs stays as the
		// resume left it.
		if n["user_id"] == dora.String() {
			if n["resumed"] != true || n["pauses"] != float64(1) {
				t.Fatalf("the second stop's actor's notice: %+v", n)
			}
			continue
		}
		if n["resumed"] != false || n["folded"] != true || n["pauses"] != float64(2) || n["several_actors"] != true ||
			n["raised_by"] != dora.String() {
			t.Fatalf("a folded notice: %+v", n)
		}
	}
}
