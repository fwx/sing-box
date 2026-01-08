//go:build windows && !generate

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

func main() {
	globalCtx = context.Background()

	ctx := include.Context(globalCtx)

	logFactory, err := log.New(log.Options{
		Context: ctx,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer logFactory.Close()

	logger := logFactory.Logger()
	logger.Info("loopie started")

	pipeServer, err := ipc.NewPipeServer(ctx, logger)
	if err != nil {
		log.Fatal(err)
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignals)

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

	err = pipeServer.Start()
	cancel()
	if err != nil {
		log.Fatal(err)
	}
}
