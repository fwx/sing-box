package ipc

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*StatsTracker)(nil)

// StatsTracker implements adapter.ConnectionTracker for simple traffic statistics
type StatsTracker struct {
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
}

// NewStatsTracker creates a new stats tracker
func NewStatsTracker() *StatsTracker {
	return &StatsTracker{}
}

// Total returns total upload and download bytes
func (t *StatsTracker) Total() (upload int64, download int64) {
	return t.uploadTotal.Load(), t.downloadTotal.Load()
}

// Reset resets the counters
func (t *StatsTracker) Reset() {
	t.uploadTotal.Store(0)
	t.downloadTotal.Store(0)
}

// RoutedConnection implements adapter.ConnectionTracker
func (t *StatsTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	return bufio.NewCounterConn(conn, []N.CountFunc{func(n int64) {
		t.uploadTotal.Add(n)
	}}, []N.CountFunc{func(n int64) {
		t.downloadTotal.Add(n)
	}})
}

// RoutedPacketConnection implements adapter.ConnectionTracker
func (t *StatsTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	return bufio.NewCounterPacketConn(conn, []N.CountFunc{func(n int64) {
		t.uploadTotal.Add(n)
	}}, []N.CountFunc{func(n int64) {
		t.downloadTotal.Add(n)
	}})
}
