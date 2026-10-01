//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// vsockListener is a listening AF_VSOCK socket that hands on only the
// connections from one context id.
type vsockListener struct {
	fd         int
	port, peer uint32
}

// listenVsock listens on a vsock port, for any local context id, and serves
// connections from peer only.
func listenVsock(port, peer uint32) (listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		//nolint:errcheck // the bind error is the one to report
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 64); err != nil {
		//nolint:errcheck // the listen error is the one to report
		_ = unix.Close(fd)
		return nil, err
	}
	return &vsockListener{fd: fd, port: port, peer: peer}, nil
}

// Accept waits for a connection. One from another context id is closed at
// once and reported as errForeignPeer.
func (l *vsockListener) Accept() (net.Conn, error) {
	nfd, sa, err := unix.Accept4(l.fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	if err != nil {
		return nil, err
	}
	vm, ok := sa.(*unix.SockaddrVM)
	if !ok || vm.CID != l.peer {
		//nolint:errcheck // refused either way
		_ = unix.Close(nfd)
		return nil, errForeignPeer
	}
	// A non-blocking descriptor joins the runtime's poller, so the
	// tunnel's deadlines work on it.
	file := os.NewFile(uintptr(nfd), "vsock:"+strconv.FormatUint(uint64(vm.CID), 10))
	return &vsockConn{File: file, local: vsockAddr{cid: unix.VMADDR_CID_ANY, port: l.port}, remote: vsockAddr{cid: vm.CID, port: vm.Port}}, nil
}

// vsockConn is an accepted vsock connection as a net.Conn.
type vsockConn struct {
	*os.File
	local, remote vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr  { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr { return c.remote }

// vsockAddr is a vsock context id and port.
type vsockAddr struct{ cid, port uint32 }

func (vsockAddr) Network() string  { return "vsock" }
func (a vsockAddr) String() string { return fmt.Sprintf("%d:%d", a.cid, a.port) }
