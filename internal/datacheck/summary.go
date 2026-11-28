package datacheck

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// WriteSummary writes a short human reading of m: counts and ids only.
func WriteSummary(w io.Writer, m *Manifest) error {
	var b bytes.Buffer
	newest := 0
	for v := range m.Schema {
		if n, err := strconv.Atoi(v); err == nil && n > newest {
			newest = n
		}
	}
	fmt.Fprintf(&b, "datacheck %s at %s, scope %s, schema %d migrations (newest %d)\n",
		m.Format, m.TakenAt, m.Scope, len(m.Schema), newest)
	for _, t := range sortedKeys(m.Digests) {
		if a := m.Digests[t].Absent; len(a) > 0 {
			fmt.Fprintf(&b, "schema: %s lacks %d columns this binary knows (no digest covers them)\n", t, len(a))
		}
	}
	for _, id := range sortedKeys(m.Workspaces) {
		ws := m.Workspaces[id]
		fmt.Fprintf(&b, "workspace %s: %d numbers, %d accounts, %d storage objects (%d bytes), read check: %d keyless, %d orphan\n",
			id, len(ws.Devices), len(ws.Users), ws.StorageObjects.Count, ws.StorageObjects.Bytes,
			len(ws.ReadCheck.Keyless), len(ws.ReadCheck.Orphan))
		for _, did := range sortedKeys(ws.Devices) {
			d := ws.Devices[did]
			var msgs int64
			for _, n := range d.Messages.ByKind {
				msgs += n
			}
			var media int64
			for _, t := range d.Media {
				media += t.Count
			}
			epoch, paused, deleted := "-", "-", "no"
			if d.Fields != nil {
				if v := d.Fields["current_epoch"]; v != nil {
					epoch = *v
				}
				if v := d.Fields["paused"]; v != nil {
					paused = *v
				}
				if v := d.Fields["deleted_at"]; v != nil {
					deleted = "yes"
				}
			}
			present := ""
			if !d.Present {
				present = " (no devices row here)"
			}
			fmt.Fprintf(&b, "  number %s%s: epoch %s, paused %s, deleted %s, %d messages (%d without ts), %d chats, %d contacts, %d media, %d grants, %d content keys epochs\n",
				did, present, epoch, paused, deleted, msgs, d.Messages.NullTS, count(d.Tables["chats"]), count(d.Tables["contacts"]),
				media, len(d.Grants), len(d.ContentKeys))
		}
		for _, t := range sortedKeys(ws.Unowned) {
			fmt.Fprintf(&b, "  %d %s rows with no number\n", ws.Unowned[t].Count, t)
		}
	}
	for _, name := range sortedKeys(m.Files) {
		f := m.Files[name]
		if f.Present {
			fmt.Fprintf(&b, "file %s: %d lines, sha256 %s\n", name, f.Lines, f.SHA256)
		} else {
			fmt.Fprintf(&b, "WARNING file %s: absent (a backup or restore must carry it; -require-files fails on this)\n", name)
		}
	}
	if o := m.Objects; o != nil {
		fmt.Fprintf(&b, "objects under %q: %d (%d bytes)\n", o.Prefix, o.Total.Count, o.Total.Bytes)
		sets := map[string]*ObjectSet{}
		for id, s := range o.Workspaces {
			sets["workspace "+id] = s
		}
		if o.Other != nil {
			sets["under no workspace"] = o.Other
		}
		for _, name := range sortedKeys(sets) {
			s := sets[name]
			fmt.Fprintf(&b, "  %s: %d objects, %d bytes; %d hash mismatches, %d unchecked, %d unrecognised, %d not in the database, %d missing, %d size mismatches, %d media keys without a storage row, %d storage rows without media, %d keys outside the prefix\n",
				name, s.Count, s.Bytes, s.HashMismatch, s.Unchecked, s.Unrecognised, s.NotInDatabase, s.Missing,
				s.SizeMismatch, s.NoStorageRow, s.NoMediaRow, s.OutsidePrefix)
		}
		fmt.Fprintf(&b, "objects: %d problems\n", o.Problems())
	}
	_, err := w.Write(b.Bytes())
	return err
}

// Problems sums every set's problems.
func (o *Objects) Problems() int64 {
	if o == nil {
		return 0
	}
	n := o.Other.Problems()
	for _, s := range o.Workspaces {
		n += s.Problems()
	}
	return n
}

func count(t *Table) int64 {
	if t == nil {
		return 0
	}
	return t.Count
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
