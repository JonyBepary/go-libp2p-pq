package mplex

import (
	"errors"
	"net"
	"testing"

	"github.com/JonyBepary/go-libp2p-pq/core/network"
	test "github.com/JonyBepary/go-libp2p-pq/p2p/muxer/testsuite"
)

func TestDefaultTransport(t *testing.T) {
	test.SubtestAll(t, DefaultTransport)
}

type memoryScope struct {
	network.PeerScope
	limit    int
	reserved int
}

func (m *memoryScope) ReserveMemory(size int, prio uint8) error {
	if m.reserved+size > m.limit {
		return errors.New("too much")
	}
	m.reserved += size
	return nil
}

func (m *memoryScope) ReleaseMemory(size int) {
	m.reserved -= size
	if m.reserved < 0 {
		panic("too much memory released")
	}
}

type memoryLimitedTransport struct {
	Transport
}

func (t *memoryLimitedTransport) NewConn(nc net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	return t.Transport.NewConn(nc, isServer, &memoryScope{
		limit:     3 * 1 << 20,
		PeerScope: scope,
	})
}

func TestDefaultTransportWithMemoryLimit(t *testing.T) {
	test.SubtestAll(t, &memoryLimitedTransport{
		Transport: *DefaultTransport,
	})
}
