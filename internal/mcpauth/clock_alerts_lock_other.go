//go:build !unix

package mcpauth

import "errors"

// lockAlerts needs flock, which only Unix systems have; the server runs on
// Linux. Without it no alert is claimed, so none is mailed.
func lockAlerts(string) (func(), error) {
	return nil, errors.New("the reader clock alerts need a Unix file lock")
}
