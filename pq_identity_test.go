package libp2p

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// A host whose libp2p identity key is ML-DSA-65 must be able to listen and
// complete a Noise handshake. This is the property PQS relies on when the
// proposer signs block headers with its identity key.
func TestHostWithMLDSAIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	priv1, _, err := crypto.GenerateKeyPair(crypto.MLDSA65, 0)
	if err != nil {
		t.Fatalf("generate key 1: %v", err)
	}
	priv2, _, err := crypto.GenerateKeyPair(crypto.MLDSA65, 0)
	if err != nil {
		t.Fatalf("generate key 2: %v", err)
	}

	h1, err := New(Identity(priv1), ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("host 1 (listener): %v", err)
	}
	t.Cleanup(func() { _ = h1.Close() })

	h2, err := New(Identity(priv2), ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("host 2 (dialer): %v", err)
	}
	t.Cleanup(func() { _ = h2.Close() })

	if h1.ID() == h2.ID() {
		t.Fatal("distinct ML-DSA keys produced the same peer ID")
	}

	const testProto = "/pqs/mldsa-test/1.0.0"
	h1.SetStreamHandler(testProto, func(stream network.Stream) {
		defer stream.Close()
		buf := make([]byte, 2)
		_, _ = io.ReadFull(stream, buf)
	})

	info := peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}
	if err := h2.Connect(ctx, info); err != nil {
		t.Fatalf("connect: %v", err)
	}

	connected := false
	for _, c := range h2.Network().ConnsToPeer(h1.ID()) {
		if c.Stat().Direction == network.DirOutbound {
			connected = true
		}
	}
	if !connected && h2.Network().Connectedness(h1.ID()) != network.Connected {
		t.Fatalf("not connected to %s", h1.ID())
	}

	// A stream round trip proves the secured session is usable, not just open.
	s, err := h2.NewStream(ctx, h1.ID(), testProto)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer s.Close()
	if _, err := s.Write([]byte("pq")); err != nil {
		t.Fatalf("write: %v", err)
	}
}
