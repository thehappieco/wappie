//go:build !linux

package main

import "errors"

// listenVsock needs Linux: the proxy runs on the enclave's parent instance.
func listenVsock(_, _ uint32) (listener, error) {
	return nil, errors.New("vsock needs Linux; the egress proxy runs on the enclave's parent instance")
}
