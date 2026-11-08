package access

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// UseStore is where TokenUse adds its counts (store.Tokens.AddTokenUse).
type UseStore interface {
	AddTokenUse(ctx context.Context, u store.TokenUse) error
}

// TokenUse counts tokens' uses in this process, for the usage report (the
// plan's 3.6, its tokens.Counter): one "used" per token and UTC day, and
// refusals per (token, day, number, perm, code). A refusal counts only once
// the token's secret matched, and with a number only for a number of its
// workspace that the client named (Checker.Allows, never Probe). Run adds
// the counts every ten seconds, each a delta the database adds to its row,
// so processes never lose one another's; Flush adds what is left at
// shutdown. A nil *TokenUse counts nothing.
type TokenUse struct {
	Store UseStore
	Log   *slog.Logger

	mu       sync.Mutex
	used     map[store.TokenDay]bool
	sent     map[store.TokenDay]bool
	refusals map[useRefusal]int64
	dropped  int64
	warned   time.Time
}

// MaxUseKeys bounds what TokenUse holds between flushes: past it, new keys
// are dropped, with one WARN a minute.
const MaxUseKeys = 10_000

// UseFlushEvery is how often Run adds the counts.
const UseFlushEvery = 10 * time.Second

type useRefusal struct {
	token  uuid.UUID
	day    time.Time
	device uuid.UUID
	perm   string
	code   string
}

func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// size is the keys held, under mu.
func (u *TokenUse) size() int { return len(u.used) + len(u.refusals) }

// full reports, under mu, whether a new key must be dropped, and warns.
func (u *TokenUse) full(now time.Time) bool {
	if u.size() < MaxUseKeys {
		return false
	}
	u.dropped++
	if now.Sub(u.warned) >= time.Minute {
		u.warned = now
		log := u.Log
		if log == nil {
			log = slog.Default()
		}
		log.Warn("token usage counts are full until the next flush; new ones are dropped", "dropped", u.dropped)
	}
	return true
}

// Used counts token used on now's UTC day: once per process per day.
func (u *TokenUse) Used(token uuid.UUID, now time.Time) {
	if u == nil {
		return
	}
	k := store.TokenDay{Token: token, Day: utcDay(now)}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sent[k] || u.used[k] || u.full(now) {
		return
	}
	if u.used == nil {
		u.used = map[store.TokenDay]bool{}
	}
	u.used[k] = true
}

// Refused counts one refused use of token on now's UTC day with code: on
// device with perm, or of the token itself (revoked, expired,
// suspended_here) with uuid.Nil and "".
func (u *TokenUse) Refused(token uuid.UUID, now time.Time, device uuid.UUID, perm, code string) {
	if u == nil {
		return
	}
	k := useRefusal{token: token, day: utcDay(now), device: device, perm: perm, code: code}
	if device == uuid.Nil {
		k.perm = ""
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.refusals[k]; !ok && u.full(now) {
		return
	}
	if u.refusals == nil {
		u.refusals = map[useRefusal]int64{}
	}
	u.refusals[k]++
}

// Flush adds what was counted since the last flush. A failure keeps it for
// the next.
func (u *TokenUse) Flush(ctx context.Context) error {
	if u == nil || u.Store == nil {
		return nil
	}
	u.mu.Lock()
	used, refusals := u.used, u.refusals
	u.used, u.refusals = nil, nil
	u.mu.Unlock()
	if len(used) == 0 && len(refusals) == 0 {
		return nil
	}
	batch := store.TokenUse{}
	for k := range used {
		batch.Used = append(batch.Used, k)
	}
	for k, n := range refusals {
		r := store.TokenUseRefusal{Token: k.token, Day: k.day, Code: k.code, Count: n}
		if k.device != uuid.Nil {
			device, perm := k.device, k.perm
			r.Device, r.Perm = &device, &perm
		}
		batch.Refusals = append(batch.Refusals, r)
	}
	err := u.Store.AddTokenUse(ctx, batch)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		// Back for the next flush, merged with what came meanwhile.
		for k := range used {
			if u.used == nil {
				u.used = map[store.TokenDay]bool{}
			}
			u.used[k] = true
		}
		for k, n := range refusals {
			if u.refusals == nil {
				u.refusals = map[useRefusal]int64{}
			}
			u.refusals[k] += n
		}
		return err
	}
	if u.sent == nil {
		u.sent = map[store.TokenDay]bool{}
	}
	for k := range used {
		u.sent[k] = true
	}
	// The days before yesterday are done: a token used on them is never
	// counted on them again.
	cut := utcDay(time.Now()).AddDate(0, 0, -1)
	for k := range u.sent {
		if k.Day.Before(cut) {
			delete(u.sent, k)
		}
	}
	return nil
}

// Run flushes every UseFlushEvery until ctx ends.
func (u *TokenUse) Run(ctx context.Context) {
	if u == nil {
		return
	}
	t := time.NewTicker(UseFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := u.Flush(ctx); err != nil && ctx.Err() == nil {
			log := u.Log
			if log == nil {
				log = slog.Default()
			}
			log.Warn("could not add the token usage counts; they wait for the next flush", "error", err)
		}
	}
}
