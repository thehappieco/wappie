package main

import (
	"errors"
	"net"
)

// errForeignPeer is a connection from another context than the enclave's,
// which the listener closed.
var errForeignPeer = errors.New("cimd-egress: a peer that is not the enclave")

// listener accepts the enclave's connections.
type listener interface {
	Accept() (net.Conn, error)
}
