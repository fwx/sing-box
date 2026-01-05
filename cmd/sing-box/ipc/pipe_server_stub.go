//go:build !windows

package ipc

import (
	"errors"
	"net"
)

const (
	// PipeName is not used on non-Windows platforms
	PipeName = ""
)

// createPipeListener returns an error on non-Windows platforms
func createPipeListener() (net.Listener, error) {
	return nil, errors.New("Named Pipe IPC is only supported on Windows")
}

// isPipeSupported returns false on non-Windows platforms
func isPipeSupported() bool {
	return false
}
