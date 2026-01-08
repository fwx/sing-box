//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-box/cmd/sing-box/ipc"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
)

// run starts the IPC pipe server on Windows
func run() error {
	// Create context with registries (required for DNS transport parsing)
	ctx := include.Context(globalCtx)

	// Create logger
	logFactory, err := log.New(log.Options{
		Context: ctx,
	})
	if err != nil {
		return err
	}
	defer logFactory.Close()

	logger := logFactory.Logger()
	logger.Info("loopie started")

	// Create and start pipe server
	pipeServer, err := ipc.NewPipeServer(ctx, logger)
	if err != nil {
		return err
	}

	// Setup signal handling for graceful shutdown
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignals)

	// Handle OS signals in a separate goroutine
	ctx, cancel := context.WithCancel(globalCtx)
	go func() {
		select {
		case <-osSignals:
			logger.Info("received shutdown signal")
			cancel()
			pipeServer.Stop()
		case <-ctx.Done():
		}
	}()

	// Start the pipe server (blocking)
	err = pipeServer.Start()
	cancel()
	return err
}
