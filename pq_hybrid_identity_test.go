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

// A host with a hybrid Ed25519 + ML-DSA-44 identity must complete a Noise
// handshake with another hybrid host and with a classical host: the identity
// key only signs the handshake payload, so the algorithm is local.
func TestHostWithHybridIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	priv1, _, err := crypto.GenerateKeyPair(crypto.HYBRID_ED25519_MLDSA44, 0)
	if err != nil {
		t.Fatalf("hybrid key 1: %v", err)
	}
	priv2, _, err := crypto.GenerateKeyPair(crypto.HYBRID_ED25519_MLDSA44, 0)
	if err != nil {
		t.Fatalf("hybrid key 2: %v", err)
	}

	const testProto = "/pqs/hybrid-test/1.0.0"

	h1, err := New(Identity(priv1), ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("hybrid host 1: %v", err)
	}
	t.Cleanup(func() { _ = h1.Close() })
	h1.SetStreamHandler(testProto, func(s network.Stream) {
		defer s.Close()
		buf := make([]byte, 2)
		_, _ = io.ReadFull(s, buf)
	})

	h2, err := New(Identity(priv2), ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("hybrid host 2: %v", err)
	}
	t.Cleanup(func() { _ = h2.Close() })

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect hybrid -> hybrid: %v", err)
	}
	stream, err := h2.NewStream(ctx, h1.ID(), testProto)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("hy")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Hybrid host dialing a classical host must work too.
	classicalPriv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	h3, err := New(Identity(classicalPriv), ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("classical host: %v", err)
	}
	t.Cleanup(func() { _ = h3.Close() })

	if err := h2.Connect(ctx, peer.AddrInfo{ID: h3.ID(), Addrs: h3.Addrs()}); err != nil {
		t.Fatalf("connect hybrid -> ed25519: %v", err)
	}
	if got := h2.Network().Connectedness(h3.ID()); got != network.Connected {
		t.Fatalf("connectedness = %v, want Connected", got)
	}
}
