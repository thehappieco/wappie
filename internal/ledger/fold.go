package ledger

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
)

// What a restore must make of a number, from all of its lines.
const (
	StateLive     = "live"
	StateExcluded = "excluded"
	StatePurged   = "purged"
)

// Reversal is a deletion a recovery undid.
type Reversal struct {
	DeletedAt time.Time
	// EventID is the recovered line's.
	EventID    uuid.UUID
	OccurredAt time.Time
}

// Device is one number's final state, folded from its lines.
type Device struct {
	DeviceID uuid.UUID
	// Workspace is where the number is: the destination of its last move,
	// or else the workspace of its lines.
	Workspace uuid.UUID
	// Moved is a number that moved at least once.
	Moved bool
	State string
	// DeletedAt, PurgeAfter, DeletedBy, EventID and OccurredAt are the
	// unreversed deletion's (excluded) or the purge's (purged).
	DeletedAt, PurgeAfter time.Time
	DeletedBy             *uuid.UUID
	EventID               uuid.UUID
	OccurredAt            time.Time
	// Reversed are the deletions recoveries undid.
	Reversed []Reversal
}

// Problem is a number whose lines cannot be folded into one state: lines
// were lost, or the file is not what Export writes. A replay stops on it.
type Problem struct {
	DeviceID uuid.UUID
	Reason   string
}

func (p Problem) String() string { return p.DeviceID.String() + ": " + p.Reason }

// Fold reads every line of each number and says what it must be, by cause
// and never by time: the database's clock steps back under load, and a
// duplicated deleted line can follow the recovered line that undid it.
//
//   - A purged line is final.
//   - Otherwise a deletion is reversed exactly when a recovered line names
//     its deleted_at. With none left, the number is live; with one, it is
//     excluded with that deletion's dates; with more, lines were lost.
//
// Its workspace is the destination of its last move, followed from move to
// move, or else the one its lines name.
func Fold(lines []Line) ([]Device, []Problem) {
	byDevice := map[uuid.UUID][]Line{}
	var order []uuid.UUID
	for _, l := range lines {
		if _, ok := byDevice[l.DeviceID]; !ok {
			order = append(order, l.DeviceID)
		}
		byDevice[l.DeviceID] = append(byDevice[l.DeviceID], l)
	}
	var out []Device
	var problems []Problem
	for _, id := range order {
		d, err := fold(id, byDevice[id])
		if err != nil {
			problems = append(problems, Problem{DeviceID: id, Reason: err.Error()})
			continue
		}
		out = append(out, d)
	}
	return out, problems
}

func fold(id uuid.UUID, lines []Line) (Device, error) {
	d := Device{DeviceID: id}
	workspace, moved, err := whereIs(lines)
	if err != nil {
		return d, err
	}
	d.Workspace, d.Moved = workspace, moved

	var purged *Line
	for i := range lines {
		l := &lines[i]
		if l.Type == TypePurged && (purged == nil || l.PurgeAfter.Before(*purged.PurgeAfter)) {
			purged = l
		}
	}
	if purged != nil {
		d.State, d.DeletedAt, d.PurgeAfter = StatePurged, *purged.DeletedAt, *purged.PurgeAfter
		d.EventID, d.OccurredAt = purged.EventID, purged.OccurredAt
		return d, nil
	}

	recovered := map[time.Time]Line{}
	for _, l := range lines {
		if l.Type == TypeRecovered {
			recovered[l.DeletedAt.UTC()] = l
		}
	}
	var open []Line
	seen := map[time.Time]bool{}
	for _, l := range lines {
		if l.Type != TypeDeleted {
			continue
		}
		at := l.DeletedAt.UTC()
		if seen[at] {
			// The same deletion twice, under two event ids.
			continue
		}
		seen[at] = true
		if r, ok := recovered[at]; ok {
			d.Reversed = append(d.Reversed, Reversal{DeletedAt: at, EventID: r.EventID, OccurredAt: r.OccurredAt})
			continue
		}
		open = append(open, l)
	}
	switch len(open) {
	case 0:
		d.State = StateLive
	case 1:
		l := open[0]
		d.State, d.DeletedAt, d.PurgeAfter, d.DeletedBy = StateExcluded, *l.DeletedAt, *l.PurgeAfter, l.DeletedBy
		d.EventID, d.OccurredAt = l.EventID, l.OccurredAt
	default:
		var at []string
		for _, l := range open {
			at = append(at, l.DeletedAt.UTC().Format(time.RFC3339Nano))
		}
		return d, fmt.Errorf("%d deletions with no recovery (%v): lines were lost", len(open), at)
	}
	return d, nil
}

// whereIs is the number's workspace: with moves, the end of the chain of
// moves (a destination no move leaves), or of the latest move when the
// chain has no single end; without, the one workspace its lines name.
func whereIs(lines []Line) (uuid.UUID, bool, error) {
	var moves []Line
	for _, l := range lines {
		if l.Type == TypeMovedOut {
			moves = append(moves, l)
		}
	}
	if len(moves) == 0 {
		var ws []uuid.UUID
		for _, l := range lines {
			if !slices.Contains(ws, l.WorkspaceID) {
				ws = append(ws, l.WorkspaceID)
			}
		}
		if len(ws) != 1 {
			return uuid.Nil, false, fmt.Errorf("its lines name %d workspaces and no move", len(ws))
		}
		return ws[0], false, nil
	}
	sources := map[uuid.UUID]bool{}
	for _, m := range moves {
		sources[m.WorkspaceID] = true
	}
	var ends []uuid.UUID
	for _, m := range moves {
		if !sources[*m.ToWorkspaceID] && !slices.Contains(ends, *m.ToWorkspaceID) {
			ends = append(ends, *m.ToWorkspaceID)
		}
	}
	if len(ends) == 1 {
		return ends[0], true, nil
	}
	sort.SliceStable(moves, func(i, j int) bool { return moves[i].OccurredAt.Before(moves[j].OccurredAt) })
	return *moves[len(moves)-1].ToWorkspaceID, true, nil
}
