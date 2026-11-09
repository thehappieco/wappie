package membership

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// The settings part in the leader (step 12a; the platform's spec, section
// 14; docs/contract.md, "Settings and commands"): the numbers section's
// sender, the command feed's follower, the executor of the commands it
// takes, and the poster of their results. They run while the settings mode
// is read or on: the leader's watcher starts them when it reads either (at
// its start, every mode check and each notice) and stops them when it
// reads off. In read every command is answered kind_not_accepted, and the
// sections go with accepts [], so the console offers nothing.
//
// A reset is the account side's too: a signed gone on the command feed, or
// a page of another generation than the stored one, resets the account and
// command state in one transaction (Contract.RestartFromCommands), at most
// once a minute from this side; the account follower's own reset cuts the
// command long-poll (the follower's commands hook).

// The settings part's defaults.
const (
	// commandBackoffMin and commandBackoffMax bound the wait after a
	// command feed call that got no page: well under the 120 s after which
	// the console shows Wappie down.
	commandBackoffMin = 2 * time.Second
	commandBackoffMax = 20 * time.Second
	// resetFloor is the least time between two resets the command feed
	// starts: each makes every document due and drops results, so a fault
	// must not repeat one in a loop.
	resetFloor = time.Minute
	// noGeneration is the wait while the account side holds no generation
	// yet: it adopts the platform's from its first page.
	noGeneration = 2 * time.Second
	// sectionDebounce is how long after a change it shows a section is sent
	// (the spec's 14.2: "debounced to 2 s"), from the first change of a run.
	sectionDebounce = 2 * time.Second
	// connectionDebounce is the debounce of a connection that only flipped
	// between online and offline: a flapping number sends one section per
	// workspace at most this often.
	connectionDebounce = 30 * time.Second
	// sectionEvery is how long after an accepted section the next is due,
	// as the snapshots' hourly.
	sectionEvery = 55 * time.Minute
	// sectionBackoffMin and sectionBackoffMax bound the wait after a
	// section that was not accepted.
	sectionBackoffMin = 5 * time.Second
	sectionBackoffMax = time.Hour
	// pairingLook is how often the sender compares the pairings the
	// process runs with the pending rows it sent: a pairing starts and ends
	// with no row change.
	pairingLook = 10 * time.Second
	// resultsBackoffMin and resultsBackoffMax bound the wait after a
	// results post that got no answer.
	resultsBackoffMin = 2 * time.Second
	resultsBackoffMax = time.Minute
	// settingsIdle is the longest the executor and the results poster wait
	// without looking, should a kick be lost.
	settingsIdle = 30 * time.Second
	// trimEvery is how often the leader trims the ledger of rows past
	// their 30 days, beside the hourly maintenance's trim.
	trimEvery = 5 * time.Minute
)

// SettingsConfig is the settings part's configuration in the leader: its
// timings (the defaults above when zero; tests shorten them) and what it
// asks of the process beside the database.
type SettingsConfig struct {
	// CommandWait is the command long-poll's wait in seconds (kc.MaxWait
	// when zero).
	CommandWait                          int
	CommandBackoffMin, CommandBackoffMax time.Duration
	ResetFloor                           time.Duration
	SectionDebounce, ConnectionDebounce  time.Duration
	SectionEvery                         time.Duration
	SectionBackoffMin, SectionBackoffMax time.Duration
	PairingLook                          time.Duration
	ResultsBackoffMin, ResultsBackoffMax time.Duration
	Idle, TrimEvery                      time.Duration
	// Numbers is the leader's process's registry: the pending rows'
	// pairing and retry. Nil: none pairs, none may be retried.
	Numbers NumberLooks
}

func (s SettingsConfig) commandWait() int {
	if s.CommandWait > 0 {
		return min(s.CommandWait, kc.MaxWait)
	}
	return kc.MaxWait
}

func (s SettingsConfig) sectionTimes() store.ContractSnapshotTimes {
	return store.ContractSnapshotTimes{
		Every:      or(s.SectionEvery, sectionEvery),
		BackoffMin: or(s.SectionBackoffMin, sectionBackoffMin),
		BackoffMax: or(s.SectionBackoffMax, sectionBackoffMax),
	}
}

// settingsWork is one leader's settings part: its four loops, while the
// settings mode is read or on, and the kicks between them.
type settingsWork struct {
	l   *Leader
	cfg SettingsConfig
	// accounts is the account follower: a reset here cuts its long-poll and
	// kicks its round.
	accounts *follower
	// sections are the notices the section sender takes; executor and
	// results wake their loops.
	sections          *sectionNotices
	executor, results chan struct{}
	// current is the effective mode the loops run in ("" while off).
	current atomic.Pointer[string]

	mu sync.Mutex
	// cut ends the command long-poll in flight, or the pause after it.
	cut context.CancelFunc
	// stop ends the running loops; nil while they do not run.
	stop context.CancelFunc
	wg   sync.WaitGroup
}

func newSettingsWork(l *Leader, accounts *follower) *settingsWork {
	return &settingsWork{l: l, cfg: l.Settings, accounts: accounts, sections: newSectionNotices(),
		executor: make(chan struct{}, 1), results: make(chan struct{}, 1)}
}

// mode is the effective settings mode the loops run in, off while they do
// not.
func (sw *settingsWork) mode() string {
	if m := sw.current.Load(); m != nil {
		return *m
	}
	return store.SettingsOff
}

// set starts the loops under ctx for mode read or on when they do not run,
// or stops them and waits for them for off. A switch between read and on
// keeps them running: every document was made due by the switch, and the
// sender reads the mode at each send. Only the leader's watcher calls it,
// and the leader's end (halt).
func (sw *settingsWork) set(ctx context.Context, mode string) {
	sw.mu.Lock()
	running := sw.stop != nil
	if mode != store.SettingsOff {
		sw.current.Store(&mode)
	}
	switch {
	case mode == store.SettingsOff && !running, mode != store.SettingsOff && running:
		sw.mu.Unlock()
		return
	case mode == store.SettingsOff:
		stop := sw.stop
		sw.stop = nil
		sw.current.Store(nil)
		sw.mu.Unlock()
		stop()
		sw.wg.Wait()
		sw.l.log().Info("contract: settings stopped")
		return
	}
	// The store's own lines (a result rejected with a code the contract
	// does not name) go to the leader's log, as its own do.
	run, stop := context.WithCancel(obs.WithLogger(ctx, sw.l.log()))
	sw.stop = stop
	sw.mu.Unlock()
	sw.l.log().Info("contract: settings started", "mode", mode)
	sw.wg.Go(func() { sw.follow(run) })
	sw.wg.Go(func() { sw.execute(run) })
	sw.wg.Go(func() { sw.post(run) })
	sw.wg.Go(func() { (&sectionSender{sw: sw, pending: map[uuid.UUID]pendingSent{}}).run(run) })
}

// halt stops the loops, if they run, and waits for them.
func (sw *settingsWork) halt() { sw.set(context.Background(), store.SettingsOff) }

// interrupt ends the command long-poll in flight, or its pause: another
// generation was seen, or the account side reset.
func (sw *settingsWork) interrupt() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.cut != nil {
		sw.cut()
	}
}

// notice takes a settings channel notice: a workspace whose numbers
// section changed, "c:" and one whose connection only flipped between
// online and offline, "u:" and a person's notices (the commands release's
// person documents), or "due".
func (sw *settingsWork) notice(payload string) { sw.sections.notice(payload) }

// dirty takes a dirty channel notice (0051's: what a snapshot shows, the
// members included): the workspace's numbers section is due within the
// debounce too, and with "all" every workspace's (the spec's 14.2: after a
// document that changes the workspace's members).
func (sw *settingsWork) dirty(payload string) { sw.sections.dirty(payload) }

// sectionNotices is what the leader's watcher hands the section sender,
// never waiting on it: the workspaces a change touched, those whose
// connections only flipped, or all of them, and a wake when a section was
// made due sooner.
type sectionNotices struct {
	mu         sync.Mutex
	ids, flips map[uuid.UUID]bool
	all        bool
	wake       chan struct{}
}

func newSectionNotices() *sectionNotices {
	return &sectionNotices{ids: map[uuid.UUID]bool{}, flips: map[uuid.UUID]bool{}, wake: make(chan struct{}, 1)}
}

// notice takes a settings channel payload.
func (n *sectionNotices) notice(payload string) {
	switch {
	case payload == "due":
		kick(n.wake)
	case len(payload) > 2 && payload[:2] == "c:":
		if id, err := uuid.Parse(payload[2:]); err == nil {
			n.mu.Lock()
			n.flips[id] = true
			n.mu.Unlock()
			kick(n.wake)
		}
	case len(payload) > 2 && payload[:2] == "u:":
		// A person's notices: their document is the commands release's.
	default:
		n.dirty(payload)
	}
}

// dirty takes a workspace's id, or "all"; any other payload is dropped.
func (n *sectionNotices) dirty(payload string) {
	n.mu.Lock()
	if payload == "all" {
		n.all = true
	} else if id, err := uuid.Parse(payload); err == nil {
		n.ids[id] = true
	} else {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	kick(n.wake)
}

// take returns and forgets what the notices said.
func (n *sectionNotices) take() (ids, flips []uuid.UUID, all bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id := range n.ids {
		ids = append(ids, id)
	}
	for id := range n.flips {
		if !n.ids[id] {
			flips = append(flips, id)
		}
	}
	all = n.all
	n.ids, n.flips, n.all = map[uuid.UUID]bool{}, map[uuid.UUID]bool{}, false
	return ids, flips, all
}

// give puts back what take returned, when it could not be written.
func (n *sectionNotices) give(ids, flips []uuid.UUID, all bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range ids {
		n.ids[id] = true
	}
	for _, id := range flips {
		n.flips[id] = true
	}
	n.all = n.all || all
}

// pause waits d, or less when ctx ends or wake is kicked; false when ctx
// ended.
func pause(ctx context.Context, d time.Duration, wake <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
	case <-t.C:
	}
	return true
}
