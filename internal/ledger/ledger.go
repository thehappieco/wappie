// Package ledger keeps the deletion ledger: an append-only file, outside the
// database, of every deletion, recovery, purge and move of a number
// (decision 0038's plan, section 8). A restore replays it over an older
// snapshot, so a number deleted, purged or moved after the snapshot was
// taken never comes back as it was (section 9).
//
// The file holds one JSON line per event and nothing that names a person
// outside this host: no label, no hint, no phone number. The database marks
// an event exported only after its line was written and synced, so the
// export is at least once: a line may appear twice, never zero times, and a
// reader keeps the first of each event id. Export and compaction hold an
// exclusive lock on a file beside the ledger, and an export opens the file
// afresh each time, so nothing ever appends to a file a compaction renamed
// away.
package ledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// Version is the line format this package writes.
const Version = 1

// Event types a line carries.
const (
	TypeDeleted   = "deleted"
	TypeRecovered = "recovered"
	TypePurged    = "purged"
	TypeMovedOut  = "moved_out"
)

// Line is one event. Every key is always written, null when it does not
// apply, so every line has one shape. Times are the database's, in UTC.
type Line struct {
	V           int        `json:"v"`
	EventID     uuid.UUID  `json:"event_id"`
	Type        string     `json:"type"`
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	DeviceID    uuid.UUID  `json:"device_id"`
	DeletedAt   *time.Time `json:"deleted_at"`
	PurgeAfter  *time.Time `json:"purge_after"`
	// DeletedBy is the local id of the owner who deleted: a deleted line
	// only. It never leaves this host and its backups.
	DeletedBy *uuid.UUID `json:"deleted_by"`
	// ToWorkspaceID is where a moved_out number went.
	ToWorkspaceID *uuid.UUID `json:"to_workspace_id"`
	OccurredAt    time.Time  `json:"occurred_at"`
}

// check is a line's own consistency: a known type with what that type
// carries. A line that fails it was not written by Export.
func (l Line) check() error {
	if l.V != Version {
		return fmt.Errorf("version %d", l.V)
	}
	if l.EventID == uuid.Nil || l.WorkspaceID == uuid.Nil || l.DeviceID == uuid.Nil || l.OccurredAt.IsZero() {
		return errors.New("an id or its time is missing")
	}
	switch l.Type {
	case TypeDeleted, TypePurged:
		if l.DeletedAt == nil || l.PurgeAfter == nil {
			return fmt.Errorf("a %s line without its dates", l.Type)
		}
	case TypeRecovered:
		if l.DeletedAt == nil {
			return errors.New("a recovered line without the deletion it reverses")
		}
	case TypeMovedOut:
		if l.ToWorkspaceID == nil {
			return errors.New("a moved_out line without its destination")
		}
	default:
		return fmt.Errorf("unknown type %q", l.Type)
	}
	return nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// marshal is one line, newline included.
func (l Line) marshal() ([]byte, error) {
	l.V = Version
	l.DeletedAt, l.PurgeAfter, l.OccurredAt = utc(l.DeletedAt), utc(l.PurgeAfter), l.OccurredAt.UTC()
	if err := l.check(); err != nil {
		return nil, fmt.Errorf("ledger: refusing to write a bad line: %w", err)
	}
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteFile is what the ledger needs of an open file. *os.File is one; a
// test passes one whose Write or Sync fails.
type WriteFile interface {
	io.Writer
	io.ReaderAt
	Sync() error
	Close() error
	Stat() (os.FileInfo, error)
	Truncate(size int64) error
}

// File is the ledger at Path.
type File struct {
	Path string
	// Open opens the ledger to append to it, creating it with mode 0600;
	// nil is the file system.
	Open func(path string) (WriteFile, error)
}

func (f *File) open() (WriteFile, error) {
	if f.Open != nil {
		return f.Open(f.Path)
	}
	return os.OpenFile(f.Path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
}

// LockPath is the file whose exclusive lock export and compaction hold.
func (f *File) LockPath() string { return f.Path + ".lock" }

// Export runs fn with the ledger's lock held; fn appends through write,
// which returns only once the lines are written and synced. fn marks the
// events exported after write returns, so a failed write or sync leaves
// them to the next export.
func (f *File) Export(fn func(write func([]Line) error) error) error {
	unlock, err := lock(f.LockPath())
	if err != nil {
		return fmt.Errorf("ledger: lock %s: %w", f.LockPath(), err)
	}
	defer unlock()
	return fn(f.appendLines)
}

// appendLines writes lines in one write and syncs the file, and the
// directory when the file was just created. The file is opened afresh, so
// a compaction's rename is always seen. A tail torn by a crash, a last line
// with no newline, was never synced as a whole, so none of its events was
// marked exported: it is cut before the new lines, which would otherwise
// run into it.
func (f *File) appendLines(lines []Line) error {
	if len(lines) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, l := range lines {
		b, err := l.marshal()
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	_, statErr := os.Stat(f.Path)
	created := errors.Is(statErr, os.ErrNotExist)
	file, err := f.open()
	if err != nil {
		return fmt.Errorf("ledger: open %s: %w", f.Path, err)
	}
	defer file.Close() //nolint:errcheck // the sync below is what reports
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	size := info.Size()
	if size > 0 {
		if err := cutTornTail(file, size); err != nil {
			return err
		}
		if info, err = file.Stat(); err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
		size = info.Size()
	}
	// A write or a sync that fails takes its lines back, best effort: their
	// events stay unexported, and the next export writes them once. If the
	// truncation fails too, the next export finds a torn tail, or the lines
	// twice, which a reader folds.
	if _, err := file.Write(buf.Bytes()); err != nil {
		file.Truncate(size) //nolint:errcheck,gosec // best effort, as above
		return fmt.Errorf("ledger: write %s: %w", f.Path, err)
	}
	if err := file.Sync(); err != nil {
		file.Truncate(size) //nolint:errcheck,gosec // best effort, as above
		return fmt.Errorf("ledger: sync %s: %w", f.Path, err)
	}
	if created {
		if err := syncDir(filepath.Dir(f.Path)); err != nil {
			return err
		}
	}
	return file.Close()
}

// cutTornTail truncates a file whose last byte is not a newline back to
// its last newline.
func cutTornTail(file WriteFile, size int64) error {
	last := make([]byte, 1)
	if _, err := file.ReadAt(last, size-1); err != nil {
		return fmt.Errorf("ledger: read the tail: %w", err)
	}
	if last[0] == '\n' {
		return nil
	}
	const chunk = 64 << 10
	keep := int64(0)
	for end := size; end > 0 && keep == 0; {
		start := max(end-chunk, 0)
		buf := make([]byte, end-start)
		if _, err := file.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("ledger: read the tail: %w", err)
		}
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			keep = start + int64(i) + 1
		}
		end = start
	}
	if err := file.Truncate(keep); err != nil {
		return fmt.Errorf("ledger: cut a torn tail: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the ledger's own directory
	if err != nil {
		return fmt.Errorf("ledger: open %s: %w", dir, err)
	}
	defer d.Close() //nolint:errcheck // read-only handle
	if err := d.Sync(); err != nil {
		return fmt.Errorf("ledger: sync %s: %w", dir, err)
	}
	return nil
}

// CheckWritable opens the ledger and its lock file for writing, creating
// each with mode 0600 when it is missing, and changes nothing else.
func (f *File) CheckWritable() error {
	_, statErr := os.Stat(f.Path)
	created := errors.Is(statErr, os.ErrNotExist)
	file, err := f.open()
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if created {
		if err := syncDir(filepath.Dir(f.Path)); err != nil {
			return err
		}
	}
	l, err := os.OpenFile(f.LockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return l.Close()
}

// ReadReport is what Read found.
type ReadReport struct {
	// Lines are the events, the first line of each event id, in file order.
	Lines []Line
	// Duplicates counts the lines that repeated an event id.
	Duplicates int
	// TornTail is a last line that did not parse, skipped: a write a crash
	// cut short, never marked exported.
	TornTail bool
}

// Read reads a ledger. A last line that does not parse is skipped and
// reported; anything else that does not parse, or a line that parses but
// is not one Export writes, stops the read: the file is damaged, and a
// replay must not guess.
func Read(r io.Reader) (ReadReport, error) {
	var out ReadReport
	seen := map[uuid.UUID]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var bad error
	badLine := 0
	n := 0
	for sc.Scan() {
		n++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		if bad != nil {
			return out, fmt.Errorf("ledger: line %d does not parse and valid lines follow it, so the file is damaged: %w", badLine, bad)
		}
		var l Line
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&l); err != nil {
			bad, badLine = err, n
			continue
		}
		if err := l.check(); err != nil {
			return out, fmt.Errorf("ledger: line %d is not a ledger line: %w", n, err)
		}
		if seen[l.EventID] {
			out.Duplicates++
			continue
		}
		seen[l.EventID] = true
		out.Lines = append(out.Lines, l)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	out.TornTail = bad != nil
	return out, nil
}

// CompactResult is what a compaction did.
type CompactResult struct {
	Kept, Dropped int
	// Rewritten is false when nothing was dropped and the file was left
	// alone.
	Rewritten bool
}

// Compact drops the lines of every device whose newest line is older than
// keep at now: no restorable backup can need them (decision 0027: backups
// for 90 days at most). It writes what it keeps to a file beside the
// ledger, syncs it, renames it over the ledger and syncs the directory, all
// under the ledger's lock, so an export waits and loses no line. A
// duplicated event keeps its first line. A damaged file is left alone.
func (f *File) Compact(now time.Time, keep time.Duration) (CompactResult, error) {
	var out CompactResult
	unlock, err := lock(f.LockPath())
	if err != nil {
		return out, fmt.Errorf("ledger: lock %s: %w", f.LockPath(), err)
	}
	defer unlock()
	src, err := os.Open(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	report, err := Read(src)
	src.Close() //nolint:errcheck,gosec // read-only handle
	if err != nil {
		return out, err
	}
	newest := map[uuid.UUID]time.Time{}
	for _, l := range report.Lines {
		if l.OccurredAt.After(newest[l.DeviceID]) {
			newest[l.DeviceID] = l.OccurredAt
		}
	}
	cutoff := now.Add(-keep)
	var buf bytes.Buffer
	for _, l := range report.Lines {
		if newest[l.DeviceID].Before(cutoff) {
			out.Dropped++
			continue
		}
		b, err := l.marshal()
		if err != nil {
			return out, err
		}
		buf.Write(b)
		out.Kept++
	}
	if out.Dropped == 0 && report.Duplicates == 0 && !report.TornTail {
		return out, nil
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.Path)+".compact-*")
	if err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()           //nolint:errcheck,gosec // abandoned on an error already returned
			os.Remove(tmp.Name()) //nolint:errcheck,gosec // as above
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return out, fmt.Errorf("ledger: write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		return out, fmt.Errorf("ledger: sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return out, fmt.Errorf("ledger: %w", err)
	}
	done = true
	out.Rewritten = true
	return out, syncDir(dir)
}
