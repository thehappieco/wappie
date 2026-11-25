package relink

import (
	"sync"

	"github.com/google/uuid"
)

// Running is the process's console relinks (item.relink), by number: the
// command each one answers and its session. A sync stop and a deletion
// cancel its relink through it; Wappie's own transfer of the number is
// refused while one runs (Has, DS56). The leader cancels them all when it
// stops leading, since a relink's pairing never outlives the process that
// answers its command (the spec's 14.6: the next leader answers the row).
// The zero value is ready.
type Running struct {
	mu sync.Mutex
	m  map[uuid.UUID]*run
}

type run struct {
	cmd  uuid.UUID
	sess *Session
}

// Add records sess as the relink of device answering cmd. False, and
// nothing recorded, when one runs already. A nil Running records nothing.
func (r *Running) Add(device, cmd uuid.UUID, sess *Session) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[uuid.UUID]*run{}
	}
	if r.m[device] != nil {
		return false
	}
	r.m[device] = &run{cmd: cmd, sess: sess}
	return true
}

// Remove forgets device's relink, if it is still sess.
func (r *Running) Remove(device uuid.UUID, sess *Session) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.m[device]; cur != nil && cur.sess == sess {
		delete(r.m, device)
	}
}

// Cancel ends device's relink, if one runs, and reports whether one did.
// Its end names the cause (Session.Cancel): a pause or a deletion that
// came first is state_changed. A nil Running cancels nothing.
func (r *Running) Cancel(device uuid.UUID) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	cur := r.m[device]
	r.mu.Unlock()
	if cur == nil {
		return false
	}
	cur.sess.Cancel()
	return true
}

// CancelAll ends every relink this process runs.
func (r *Running) CancelAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	all := make([]*Session, 0, len(r.m))
	for _, cur := range r.m {
		all = append(all, cur.sess)
	}
	r.mu.Unlock()
	for _, s := range all {
		s.Cancel()
	}
}

// Has reports whether a relink of device runs in this process.
func (r *Running) Has(device uuid.UUID) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[device] != nil
}

// Command is the command device's relink answers, if one runs.
func (r *Running) Command(device uuid.UUID) (uuid.UUID, bool) {
	if r == nil {
		return uuid.Nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.m[device]; cur != nil {
		return cur.cmd, true
	}
	return uuid.Nil, false
}
