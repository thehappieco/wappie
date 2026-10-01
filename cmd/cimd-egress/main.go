// Command cimd-egress is the parent's document egress proxy
// (docs/mcp-enclave.md §19.9): the attested reader's one way to a client
// metadata document on a host nobody configured.
//
// It listens on vsock port 8007 and on nothing else, takes connections from
// the enclave (CID 16) only, and answers each with one CONNECT tunnel to
// <host>:443 or one refusal; internal/cimdegress decides which. The reader
// speaks TLS through the tunnel and verifies the certificate itself, so this
// process can refuse or delay a document, never read or forge one.
//
// It reads WS_CIMD_EGRESS_OWN_ADDRESSES (the deployment's own addresses,
// never dialed: at least the parent's Elastic IP and the API host's) and
// nothing else of the server's configuration. Proxy variables in the
// environment are ignored. One journal line per tunnel goes to standard
// error.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"whatserver2/internal/cimdegress"
)

const (
	// vsockPort is the port the reader's bridge dials (vsock 3:8007).
	vsockPort = 8007
	// enclaveCID is the reader enclave's context id, as the supervisor
	// starts it; no other peer is served.
	enclaveCID = 16
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("cimd egress stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	own, err := cimdegress.ParseOwn(os.Getenv("WS_CIMD_EGRESS_OWN_ADDRESSES"))
	if err != nil {
		return err
	}
	listener, err := listenVsock(vsockPort, enclaveCID)
	if err != nil {
		return fmt.Errorf("listen on vsock %d: %w", vsockPort, err)
	}
	proxy := cimdegress.New(own, log)
	log.Info("cimd egress listening", "vsock_port", vsockPort, "peer_cid", enclaveCID, "own_addresses", len(own))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	errs := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if errors.Is(err, errForeignPeer) {
				log.Warn("cimd egress refused a peer that is not the enclave")
				continue
			}
			if err != nil {
				errs <- err
				return
			}
			go proxy.Serve(conn)
		}
	}()
	select {
	case sig := <-stop:
		// A tunnel lives six seconds at most; the reader retries a
		// document it could not fetch.
		log.Info("cimd egress stopping", "signal", sig.String())
		return nil
	case err := <-errs:
		return err
	}
}
