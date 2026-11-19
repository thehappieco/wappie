package mcpauth

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Watching an attested reader's clock from here.
//
// Every signed request carries its sender's clock, and the receiver refuses a
// timestamp more than sixty seconds from its own, in both directions. An
// enclave has no time service and its clock drifts (about 17 ppm on the pilot,
// a minute in some six weeks). Past sixty seconds every signed request either
// way is a 401, and nothing else said why: the reader's own clock_skew_ms
// stayed in the parent's journal. So the gap between each reader's timestamps
// and this server's clock is read off the requests the reader sends, and the
// log says so well before the window closes.
//
// Nothing here changes what is accepted: the window stays sixty seconds and
// the signature is the same. It only logs.

const (
	// skewWarn and skewError are the gaps that are logged as a warning and
	// as an error: a restart in a quiet hour, and a restart today.
	skewWarn  = 10 * time.Second
	skewError = 30 * time.Second
	// skewLogEvery is how often one reader's clock may be logged at one
	// level, so a reader off by a minute is a line every ten minutes and
	// not one per request.
	skewLogEvery = 10 * time.Minute
)

// Log kinds a reader's clock is rate-limited under, each per reader and level.
const (
	clockAuthenticated   = "authenticated"
	clockUnauthenticated = "unauthenticated"
	clockHealthz401      = "healthz_401"
)

// skewReading is one measured gap: the reader's timestamp minus this
// server's clock, in whole seconds, as the timestamps are.
type skewReading struct {
	seconds       int64
	authenticated bool
	at            time.Time
}

// readerClocks keeps each reader's last readings and when each kind of line
// was last logged. Only configured readers reach it, so it is bounded by
// configuration.
type readerClocks struct {
	mu sync.Mutex
	// authenticated is the last gap read off a request whose signature
	// checked; unauthenticated the last one claimed by a request refused
	// as stale, before any signature was checked.
	authenticated   map[string]skewReading
	unauthenticated map[string]skewReading
	logged          map[clockLogKey]time.Time
}

type clockLogKey struct {
	reader string
	kind   string
	level  slog.Level
}

func newReaderClocks() *readerClocks {
	return &readerClocks{
		authenticated:   map[string]skewReading{},
		unauthenticated: map[string]skewReading{},
		logged:          map[clockLogKey]time.Time{},
	}
}

// skewLevel is the level a gap is logged at, or false inside skewWarn.
func skewLevel(seconds int64) (slog.Level, bool) {
	abs := seconds
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs >= int64(skewError/time.Second):
		return slog.LevelError, true
	case abs >= int64(skewWarn/time.Second):
		return slog.LevelWarn, true
	}
	return 0, false
}

// note records a reading and reports the level to log it at. It reports
// false inside skewWarn, and when the same reader's clock was logged at the
// same level, with the same authentication, within skewLogEvery.
//
// Requests reach here out of order: a reading's time is taken when its
// headers arrive, before the body is read and the signature checked, so a
// slow request can come after a faster later one. An older reading never
// replaces a newer one.
func (c *readerClocks) note(reader string, r skewReading) (slog.Level, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kind, readings := clockUnauthenticated, c.unauthenticated
	if r.authenticated {
		kind, readings = clockAuthenticated, c.authenticated
	}
	if prev, ok := readings[reader]; !ok || !r.at.Before(prev.at) {
		readings[reader] = r
	}
	level, ok := skewLevel(r.seconds)
	if !ok {
		return 0, false
	}
	return level, c.dueLocked(clockLogKey{reader: reader, kind: kind, level: level}, r.at)
}

// due reports whether a line of this kind may be logged now, and if so
// counts it as logged.
func (c *readerClocks) due(key clockLogKey, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dueLocked(key, now)
}

// dueLocked counts a line as logged unless one was within skewLogEvery of
// now, before or after it: a request that finishes after a later one is
// inside the window too. The time kept only moves forward.
func (c *readerClocks) dueLocked(key clockLogKey, now time.Time) bool {
	if last, ok := c.logged[key]; ok && now.Sub(last) < skewLogEvery {
		return false
	}
	c.logged[key] = now
	return true
}

// readings returns a reader's last authenticated and unauthenticated
// readings, each with whether there is one.
func (c *readerClocks) readings(reader string) (auth skewReading, okAuth bool, unauth skewReading, okUnauth bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	auth, okAuth = c.authenticated[reader]
	unauth, okUnauth = c.unauthenticated[reader]
	return
}

// latest is a reader's most recent reading of either kind.
func (c *readerClocks) latest(reader string) (skewReading, bool) {
	auth, okAuth, unauth, okUnauth := c.readings(reader)
	switch {
	case okAuth && okUnauth:
		if unauth.at.After(auth.at) {
			return unauth, true
		}
		return auth, true
	case okAuth:
		return auth, true
	case okUnauth:
		return unauth, true
	}
	return skewReading{}, false
}

// skewLimitSeconds is the window the signature allows, for the log lines.
func skewLimitSeconds() int64 { return int64(mcpHMAC.Skew / time.Second) }

// noteReaderClock reads the gap off a request whose signature checked and
// whose nonce was new, and logs it when it is wide. The gap includes the
// request's time in transit, so a request held on the way (by the parent,
// say) reads as a reader running slow.
func (h *Handler) noteReaderClock(ctx context.Context, caller *AttestedReader, unix int64, now time.Time) {
	r := skewReading{seconds: unix - now.Unix(), authenticated: true, at: now}
	if level, ok := h.clocks.note(caller.ID, r); ok {
		h.log().Log(ctx, level, "an attested reader's clock is off", "reader", caller.ID,
			"skew_s", r.seconds, "authenticated", true, "limit_s", skewLimitSeconds())
	}
}

// noteStaleClock reads the gap a request refused as stale claims. Its
// signature was never checked, so the line says so: anyone at the reader's
// address could have sent the timestamp. It is still what an operator needs
// to see in place of a run of bare 401s.
func (h *Handler) noteStaleClock(ctx context.Context, caller *AttestedReader, header http.Header, now time.Time) {
	values := header.Values(HeaderTimestamp)
	if len(values) != 1 {
		return
	}
	unix, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return
	}
	r := skewReading{seconds: unix - now.Unix(), authenticated: false, at: now}
	if level, ok := h.clocks.note(caller.ID, r); ok {
		h.log().Log(ctx, level, "an attested reader's clock is off (unauthenticated)", "reader", caller.ID,
			"skew_s", r.seconds, "authenticated", false, "limit_s", skewLimitSeconds())
	}
}

// noteHealthzRefused logs, at most every skewLogEvery per reader, that the
// reader refused this server's signature on its health check, with what is
// known of its clock. The reader's 401 says nothing about why; a clock past
// the window is the likely cause, a secret out of step the other.
func (h *Handler) noteHealthzRefused(ctx context.Context, a *AttestedReader, now time.Time) {
	if !h.clocks.due(clockLogKey{reader: a.ID, kind: clockHealthz401, level: slog.LevelWarn}, now) {
		return
	}
	attrs := []any{"reader", a.ID, "limit_s", skewLimitSeconds()}
	auth, okAuth, unauth, okUnauth := h.clocks.readings(a.ID)
	if okAuth {
		attrs = append(attrs, "last_authenticated_skew_s", auth.seconds, "last_authenticated_skew_age_s", ageSeconds(auth.at, now))
	}
	if okUnauth {
		attrs = append(attrs, "last_unauthenticated_skew_s", unauth.seconds,
			"last_unauthenticated_skew_age_s", ageSeconds(unauth.at, now))
	}
	h.log().Log(ctx, slog.LevelWarn,
		"an attested reader refused this server's signed health check; a clock skew beyond the limit is the likely cause", attrs...)
}

// clockAttrs are the health line's fields for a reader's last reading, or
// none when there has been none.
func (h *Handler) clockAttrs(reader string, now time.Time) []any {
	r, ok := h.clocks.latest(reader)
	if !ok {
		return nil
	}
	return []any{"clock_skew_s", r.seconds, "clock_skew_authenticated", r.authenticated,
		"clock_skew_age_s", ageSeconds(r.at, now)}
}

func ageSeconds(at, now time.Time) int64 {
	return int64(now.Sub(at) / time.Second)
}
