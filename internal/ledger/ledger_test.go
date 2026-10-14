package ledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func plus30(t *time.Time) *time.Time {
	p := t.Add(30 * 24 * time.Hour)
	return &p
}

var team, personal = uuid.MustParse("00000000-0000-0000-0000-00000000000a"), uuid.MustParse("00000000-0000-0000-0000-00000000000b")

func deleted(device uuid.UUID, when string) Line {
	d := at(when)
	return Line{V: Version, EventID: uuid.New(), Type: TypeDeleted, WorkspaceID: team, DeviceID: device,
		DeletedAt: d, PurgeAfter: plus30(d), OccurredAt: *d}
}

func recovered(device uuid.UUID, when, occurred string) Line {
	return Line{V: Version, EventID: uuid.New(), Type: TypeRecovered, WorkspaceID: team, DeviceID: device,
		DeletedAt: at(when), OccurredAt: *at(occurred)}
}

func readAll(t *testing.T, path string) ReadReport {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A line is written whole and synced, in a file only its owner reads; a
// line that is not one Export writes is refused before anything is written.
func TestExportWritesWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deletion-ledger.jsonl")
	f := &File{Path: path}
	device := uuid.New()
	lines := []Line{deleted(device, "2026-10-14T10:00:00.123456Z"), recovered(device, "2026-10-14T10:00:00.123456Z", "2026-10-15T09:00:00Z")}
	if err := f.Export(func(write func([]Line) error) error { return write(lines) }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the ledger's mode: %v %v", info.Mode(), err)
	}
	got := readAll(t, path)
	if len(got.Lines) != 2 || got.Lines[0].EventID != lines[0].EventID || !got.Lines[0].DeletedAt.Equal(*lines[0].DeletedAt) ||
		got.Lines[1].Type != TypeRecovered || got.TornTail {
		t.Fatalf("read back %+v", got)
	}
	raw, _ := os.ReadFile(path)
	for _, key := range []string{`"deleted_by":null`, `"to_workspace_id":null`, `"v":1`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Fatalf("a line lacks %s: %s", key, raw)
		}
	}
	bad := deleted(device, "2026-10-14T10:00:00Z")
	bad.PurgeAfter = nil
	if err := f.Export(func(write func([]Line) error) error { return write([]Line{bad}) }); err == nil {
		t.Fatal("a deleted line with no purge_after was written")
	}
	if again := readAll(t, path); len(again.Lines) != 2 {
		t.Fatalf("a refused write changed the file: %+v", again)
	}
}

// failing is a ledger file whose Write or Sync fails.
type failing struct {
	*os.File
	write, sync bool
}

func (f failing) Write(b []byte) (int, error) {
	if f.write {
		// Half a line reaches the file, as a full disk leaves it.
		n, _ := f.File.Write(b[:len(b)/2])
		return n, errors.New("no space left on device")
	}
	return f.File.Write(b)
}

func (f failing) Sync() error {
	if f.sync {
		return errors.New("input/output error")
	}
	return f.File.Sync()
}

// A write that fails takes its half line back, and a tail a crash tore is
// cut by the next export before it appends, so the file is whole lines
// again; a reader skips a torn tail.
func TestTornTailIsCut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	fail := false
	f := &File{Path: path, Open: func(p string) (WriteFile, error) {
		file, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
		return failing{File: file, write: fail}, err
	}}
	device := uuid.New()
	first := deleted(device, "2026-10-14T10:00:00Z")
	if err := f.Export(func(write func([]Line) error) error { return write([]Line{first}) }); err != nil {
		t.Fatal(err)
	}
	torn := deleted(uuid.New(), "2026-10-14T11:00:00Z")
	fail = true
	if err := f.Export(func(write func([]Line) error) error { return write([]Line{torn}) }); err == nil {
		t.Fatal("a failed write reported success")
	}
	// The failed write took its half line back.
	r := readAll(t, path)
	if len(r.Lines) != 1 || r.TornTail {
		t.Fatalf("after a failed write: %+v", r)
	}
	// A crash leaves one, which the next export cuts.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"v":1,"event_id":"`); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if r := readAll(t, path); len(r.Lines) != 1 || !r.TornTail {
		t.Fatalf("after a crash: %+v", r)
	}
	fail = false
	if err := f.Export(func(write func([]Line) error) error { return write([]Line{torn}) }); err != nil {
		t.Fatal(err)
	}
	r = readAll(t, path)
	if len(r.Lines) != 2 || r.TornTail || r.Lines[1].EventID != torn.EventID {
		t.Fatalf("after the retry: %+v", r)
	}
}

// Read keeps the first line of each event, skips a torn last line, and
// stops on a damaged line that valid ones follow, or a line that parses but
// is not a ledger line.
func TestRead(t *testing.T) {
	device := uuid.New()
	a, b := deleted(device, "2026-10-14T10:00:00Z"), recovered(device, "2026-10-14T10:00:00Z", "2026-10-15T00:00:00Z")
	line := func(l Line) string {
		raw, err := l.marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	r, err := Read(strings.NewReader(line(a) + line(b) + line(a) + `{"v":1,"event_id":"`))
	if err != nil || len(r.Lines) != 2 || r.Duplicates != 1 || !r.TornTail {
		t.Fatalf("dedupe and a torn tail: %+v %v", r, err)
	}
	if _, err := Read(strings.NewReader(line(a) + "not json\n" + line(b))); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("a damaged line before valid ones: %v", err)
	}
	if _, err := Read(strings.NewReader(line(a) + `{"v":1,"type":"stranded"}` + "\n")); err == nil {
		t.Fatal("a line of an unknown type was read")
	}
	if _, err := Read(strings.NewReader(line(a) + `{"v":1,"event_id":"` + uuid.NewString() + `","extra":1}` + "\n" + line(b))); err == nil {
		t.Fatal("a line with a field Export never writes was read")
	}
}

// The fold goes by cause, not by time: a recovery whose clock stepped
// back, and a duplicated deleted line after its recovery, still leave the
// number live; two deletions with no recovery are lines lost.
func TestFoldByCause(t *testing.T) {
	device := uuid.New()
	d1 := deleted(device, "2026-10-14T10:00:00Z")
	r1 := recovered(device, "2026-10-14T10:00:00Z", "2026-10-14T09:59:00Z") // the clock stepped back
	dup := d1
	dup.EventID = uuid.New()
	devices, problems := Fold([]Line{r1, d1, dup})
	if len(problems) != 0 || len(devices) != 1 || devices[0].State != StateLive || len(devices[0].Reversed) != 1 ||
		devices[0].Reversed[0].EventID != r1.EventID {
		t.Fatalf("a recovered deletion: %+v %v", devices, problems)
	}
	d2 := deleted(device, "2026-10-20T10:00:00Z")
	devices, _ = Fold([]Line{d1, r1, d2})
	if devices[0].State != StateExcluded || !devices[0].DeletedAt.Equal(*d2.DeletedAt) || devices[0].EventID != d2.EventID {
		t.Fatalf("deleted again: %+v", devices)
	}
	d3 := deleted(device, "2026-10-21T10:00:00Z")
	if _, problems := Fold([]Line{d2, d3}); len(problems) != 1 || !strings.Contains(problems[0].Reason, "lines were lost") {
		t.Fatalf("two open deletions: %v", problems)
	}
	// A purge is final, whatever came around it.
	p := Line{V: Version, EventID: uuid.New(), Type: TypePurged, WorkspaceID: team, DeviceID: device,
		DeletedAt: d2.DeletedAt, PurgeAfter: d2.PurgeAfter, OccurredAt: *d2.PurgeAfter}
	if devices, _ := Fold([]Line{d2, p, r1}); devices[0].State != StatePurged || devices[0].EventID != p.EventID {
		t.Fatalf("purged: %+v", devices)
	}
}

// A moved number's workspace is its last move's destination; without a
// move, its lines must agree on one.
func TestFoldFollowsMoves(t *testing.T) {
	device := uuid.New()
	move := Line{V: Version, EventID: uuid.New(), Type: TypeMovedOut, WorkspaceID: team, DeviceID: device,
		ToWorkspaceID: &personal, OccurredAt: *at("2026-10-14T10:00:00Z")}
	d := deleted(device, "2026-10-15T10:00:00Z")
	d.WorkspaceID = personal
	devices, problems := Fold([]Line{move, d})
	if len(problems) != 0 || devices[0].Workspace != personal || !devices[0].Moved || devices[0].State != StateExcluded {
		t.Fatalf("moved, then deleted: %+v %v", devices, problems)
	}
	stray := deleted(device, "2026-10-16T10:00:00Z")
	stray.WorkspaceID = personal
	other := recovered(device, "2026-10-16T10:00:00Z", "2026-10-16T11:00:00Z")
	if _, problems := Fold([]Line{stray, other}); len(problems) != 1 {
		t.Fatalf("lines in two workspaces and no move: %v", problems)
	}
}

// Compaction drops the lines of every number whose newest line is older
// than the backups can be, through a file it syncs and renames; a number
// with one old and one young line keeps both. An export at the same moment
// waits on the lock and loses no line.
func TestCompaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	f := &File{Path: path}
	now := *at("2027-03-01T00:00:00Z")
	old, young, mixed := uuid.New(), uuid.New(), uuid.New()
	oldLine := deleted(old, "2026-10-14T10:00:00Z")
	mixedOld, mixedYoung := deleted(mixed, "2026-10-14T10:00:00Z"), recovered(mixed, "2026-10-14T10:00:00Z", "2027-02-20T00:00:00Z")
	youngLine := deleted(young, "2027-02-25T00:00:00Z")
	if err := f.Export(func(write func([]Line) error) error {
		return write([]Line{oldLine, mixedOld, youngLine, mixedYoung, oldLine})
	}); err != nil {
		t.Fatal(err)
	}

	// An export blocked on the lock while the compaction holds it.
	unlock, err := lock(f.LockPath())
	if err != nil {
		t.Fatal(err)
	}
	late := deleted(uuid.New(), "2027-02-28T00:00:00Z")
	var wg sync.WaitGroup
	wg.Add(1)
	exported := make(chan error, 1)
	go func() {
		defer wg.Done()
		exported <- f.Export(func(write func([]Line) error) error { return write([]Line{late}) })
	}()
	select {
	case err := <-exported:
		t.Fatalf("the export did not wait for the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	wg.Wait()
	if err := <-exported; err != nil {
		t.Fatal(err)
	}

	before := readAll(t, path)
	res, err := f.Compact(now, 91*24*time.Hour)
	if err != nil || !res.Rewritten || res.Dropped != 1 || res.Kept != 4 {
		t.Fatalf("compaction: %+v %v", res, err)
	}
	got := readAll(t, path)
	// Every number a backup younger than 90 days could hold folds the same
	// from the compacted file.
	folded := func(lines []Line) map[uuid.UUID]Device {
		devices, problems := Fold(lines)
		if len(problems) != 0 {
			t.Fatalf("the fold: %v", problems)
		}
		out := map[uuid.UUID]Device{}
		for _, d := range devices {
			out[d.DeviceID] = d
		}
		return out
	}
	was, is := folded(before.Lines), folded(got.Lines)
	for _, id := range []uuid.UUID{young, mixed, late.DeviceID} {
		if was[id].State != is[id].State || was[id].EventID != is[id].EventID || !was[id].DeletedAt.Equal(is[id].DeletedAt) ||
			len(was[id].Reversed) != len(is[id].Reversed) {
			t.Fatalf("%s folds to %+v after the compaction, %+v before", id, is[id], was[id])
		}
	}
	if _, ok := is[old]; ok {
		t.Fatal("the old number is still in the ledger")
	}
	var ids []uuid.UUID
	for _, l := range got.Lines {
		ids = append(ids, l.EventID)
	}
	want := []uuid.UUID{mixedOld.EventID, youngLine.EventID, mixedYoung.EventID, late.EventID}
	if len(ids) != len(want) {
		t.Fatalf("kept %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("kept %v, want %v", ids, want)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the compacted ledger's mode: %v %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".compact-") {
			t.Fatalf("a temporary file was left: %s", e.Name())
		}
	}
	// Nothing more to drop: the file is left alone.
	if res, err := f.Compact(now, 91*24*time.Hour); err != nil || res.Rewritten {
		t.Fatalf("a second compaction: %+v %v", res, err)
	}
	// A damaged file is never rewritten.
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append([]byte("damaged\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Compact(now.Add(365*24*time.Hour), 91*24*time.Hour); err == nil {
		t.Fatal("a damaged ledger was compacted")
	}
	if after, _ := os.ReadFile(path); !bytes.HasPrefix(after, []byte("damaged\n")) {
		t.Fatal("a refused compaction changed the file")
	}
}

// CheckWritable creates a missing ledger and its lock with mode 0600, and
// fails where nothing can be written.
func TestCheckWritable(t *testing.T) {
	dir := t.TempDir()
	f := &File{Path: filepath.Join(dir, "ledger.jsonl")}
	if err := f.CheckWritable(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{f.Path, f.LockPath()} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	if err := (&File{Path: filepath.Join(dir, "missing", "ledger.jsonl")}).CheckWritable(); err == nil {
		t.Fatal("a ledger in a missing directory was writable")
	}
}
