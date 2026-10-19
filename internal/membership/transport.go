// Package membership is Wappie's side of the product contract's membership
// part (decision 0040; the platform's docs/contract/v1, "README" below): the
// transport to the platform's socket, the secret's life, and the client
// every call goes through. The kit's contract package signs each request,
// checks each answer, validates the wire and bounds every call; this
// package adds what the kit leaves to the app: the socket dialer and its
// peer checks, loading and reloading the sealed secret, and sorting each
// call's outcome into what may count and what may not.
//
// Nothing here writes to the database, and nothing here applies a
// document: that is the follower's and the store's (docs/contract.md).
// Nothing here logs a secret, a label or an address: subs, ids, counts and
// codes only.
package membership

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Base is the contract's address over the socket: the host is never
// dialled, the transport dials the socket whatever it says (the kit's
// Client.Base).
const Base = "http://contract"

// App is Wappie's id on the contract, its X-Happie-App.
const App = "wappie"

var (
	// ErrUnavailable means no answer could be had: the socket is missing,
	// refuses the connection or denies this process (it vanishes whenever
	// the platform's socket unit restarts), or the loopback address in
	// development does not answer. Retried with backoff, never alarmed on
	// the first.
	ErrUnavailable = errors.New("membership: the platform's contract transport is not available")
	// ErrPeer means the socket, or its directory, is not one only root
	// could have made: no request goes to it, and the transport refuses it
	// again for a minute before it looks once more (README 2, the peer's
	// own check). Logged at ERROR.
	ErrPeer = errors.New("membership: the contract socket is not the platform's")
)

// peerRetry is how long a socket that failed its peer checks is refused
// before the transport looks at it again.
const peerRetry = time.Minute

// HTTP is the client every contract call goes through, on one transport:
// the socket in production, loopback TCP in development. It follows no
// redirect (an answer is its request's, and a redirect's answer would be
// unsigned for it), uses no proxy, and has no timeout of its own: the kit
// bounds every call (CallTimeout, and the feed's wait plus FeedGrace).
func HTTP(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dial,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
			ForceAttemptHTTP2:   false,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// SocketDialer dials the platform's contract socket, whatever host a
// request's URL names, after the peer's own checks of README 2: only root
// can make an entry under /run/platform, so the socket's directory must be
// a real directory that root owns and nobody else may write, and the
// socket a socket that root owns. The signed answers are the real proof
// (README 5); these checks keep a request, and the secret's signature on
// it, from going to a socket someone else put there.
type SocketDialer struct {
	// Path is the socket, /run/platform/contract.sock.
	Path string
	// Owner is the uid that must own the socket and its directory: 0 in
	// production, the test's own uid in tests.
	Owner int
	// Log takes the ERROR of a peer check that fails; nil logs nothing.
	Log *slog.Logger
	// Now is the clock of the peer's minute (time.Now when nil).
	Now func() time.Time

	mu       sync.Mutex
	peerErr  error
	peerSeen time.Time
}

// DialContext checks the peer, then connects to the socket.
func (d *SocketDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	d.mu.Lock()
	if d.peerErr != nil && now().Sub(d.peerSeen) < peerRetry {
		err := d.peerErr
		d.mu.Unlock()
		return nil, err
	}
	d.mu.Unlock()

	if err := checkPeer(d.Path, d.Owner); err != nil {
		if errors.Is(err, ErrPeer) {
			d.mu.Lock()
			d.peerErr, d.peerSeen = err, now()
			d.mu.Unlock()
			if d.Log != nil {
				d.Log.Error("contract: the socket failed its peer checks; no request goes to it for a minute",
					"error", err)
			}
		}
		return nil, err
	}
	d.mu.Lock()
	d.peerErr = nil
	d.mu.Unlock()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", d.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return conn, nil
}

// checkPeer is README 2's peer check of the socket at path: ErrPeer when it
// or its directory is not root's alone, ErrUnavailable when it is not
// there. The reasons name what failed, never more than the path.
func checkPeer(path string, owner int) error {
	dir := filepath.Dir(path)
	di, err := os.Lstat(dir)
	if err != nil {
		return absent(err)
	}
	switch {
	case di.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: its directory is a symbolic link", ErrPeer)
	case !di.IsDir():
		return fmt.Errorf("%w: its directory is not a directory", ErrPeer)
	case di.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%w: its directory may be written by group or others", ErrPeer)
	case !ownedBy(di, owner):
		return fmt.Errorf("%w: its directory is not owned by uid %d", ErrPeer, owner)
	}
	si, err := os.Lstat(path)
	if err != nil {
		return absent(err)
	}
	switch {
	case si.Mode()&fs.ModeSocket == 0:
		return fmt.Errorf("%w: it is not a socket", ErrPeer)
	case !ownedBy(si, owner):
		return fmt.Errorf("%w: it is not owned by uid %d", ErrPeer, owner)
	}
	return nil
}

// absent sorts a failed lstat: a missing entry, or one this process may not
// look at, is the platform not being there (yet); anything else too, since
// no request can go to it either.
func absent(err error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// ownedBy reports whether fi's owner is uid.
func ownedBy(fi fs.FileInfo, uid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(uid)
}

// TCPDialer dials the platform's development transport, a loopback
// address (config.Contract.Addr, which Load refuses in prod and for any
// address that is not a loopback IP), whatever host a request's URL names.
type TCPDialer struct {
	Addr string
}

// DialContext connects to the loopback address.
func (d TCPDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return conn, nil
}
