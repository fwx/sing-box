//go:build windows

package ipc

import (
	"net"

	"github.com/tailscale/go-winio"
)

const (
	// PipeName is the hardcoded Named Pipe name
	PipeName = `\\.\pipe\LoopVPN_SingBox`

	// PipeInputBufferSize is the input buffer size
	PipeInputBufferSize = 65536

	// PipeOutputBufferSize is the output buffer size
	PipeOutputBufferSize = 65536
)

// createPipeListener creates a Windows Named Pipe listener
func createPipeListener() (net.Listener, error) {
	config := &winio.PipeConfig{
		// Security descriptor allowing Everyone to connect
		// D: = DACL
		// (A;;GA;;;WD) = Allow (A) Generic All (GA) to Everyone (WD = World)
		SecurityDescriptor: "D:(A;;GA;;;WD)",
		MessageMode:        false, // Use byte mode - simpler and more reliable with length-prefixed protocol
		InputBufferSize:    PipeInputBufferSize,
		OutputBufferSize:   PipeOutputBufferSize,
	}

	return winio.ListenPipe(PipeName, config)
}

// isPipeSupported returns true on Windows
func isPipeSupported() bool {
	return true
}
