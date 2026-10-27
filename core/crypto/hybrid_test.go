package crypto_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
)

func hybridKey(t *testing.T) (crypto.PrivKey, crypto.PubKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateKeyPair(crypto.HYBRID_ED25519_MLDSA44, 0)
	if err != nil {
		t.Fatalf("generate hybrid key: %v", err)
	}
	return priv, pub
}

func TestHybridKeyRoundTrip(t *testing.T) {
	priv, pub := hybridKey(t)

	if pub.Type() != pb.KeyType_HYBRID_ED25519_MLDSA44 {
		t.Fatalf("type = %s, want HYBRID_ED25519_MLDSA44", pub.Type())
	}

	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	pubBack, err := crypto.UnmarshalPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("unmarshal public: %v", err)
	}
	rawA, _ := pub.Raw()
	rawB, _ := pubBack.Raw()
	if !bytes.Equal(rawA, rawB) {
		t.Fatal("public key changed across marshal/unmarshal")
	}
	t.Logf("hybrid public key: %d bytes, signature scheme: Ed25519 + ML-DSA-44 (compact)", len(rawA))

	privBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	privBack, err := crypto.UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("unmarshal private: %v", err)
	}

	message := []byte("block header hash")
	sig, err := privBack.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := pubBack.Verify(message, sig)
	if err != nil || !ok {
		t.Fatalf("verify failed (ok=%v err=%v)", ok, err)
	}
	t.Logf("hybrid signature: %d bytes", len(sig))

	// Wrong message, wrong key, and a tampered signature must all fail.
	if ok, _ := pubBack.Verify([]byte("other message"), sig); ok {
		t.Fatal("signature verified for a different message")
	}
	_, otherPub := hybridKey(t)
	if ok, _ := otherPub.Verify(message, sig); ok {
		t.Fatal("signature verified under an unrelated key")
	}
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xFF
	if ok, _ := pubBack.Verify(message, bad); ok {
		t.Fatal("tampered signature accepted")
	}
}

func TestHybridAlgorithmFieldIsFixed32(t *testing.T) {
	_, pub := hybridKey(t)
	encoded, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	found := false
	rest := encoded
	for len(rest) > 0 {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			t.Fatalf("malformed protobuf: %v", protowire.ParseError(n))
		}
		rest = rest[n:]
		switch typ {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(rest)
		case protowire.Fixed32Type:
			val, m := protowire.ConsumeFixed32(rest)
			if num == 3 {
				found = true
				if val != crypto.AlgorithmHybridEd25519MLDSA44 {
					t.Fatalf("algorithm = 0x%08X, want 0x%08X", val, crypto.AlgorithmHybridEd25519MLDSA44)
				}
				if m != 4 {
					t.Fatalf("algorithm field is %d bytes, want 4", m)
				}
			}
			n = m
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(rest)
		default:
			t.Fatalf("unexpected wire type %d", typ)
		}
		if n < 0 {
			t.Fatalf("malformed protobuf: %v", protowire.ParseError(n))
		}
		rest = rest[n:]
	}
	if !found {
		t.Fatal("Algorithm field missing from the hybrid public key")
	}
}

func TestHybridKeyPeerID(t *testing.T) {
	_, pub := hybridKey(t)
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("peer.IDFromPublicKey: %v", err)
	}
	if len(id) == 0 {
		t.Fatal("empty peer ID")
	}
	_, other := hybridKey(t)
	id2, err := peer.IDFromPublicKey(other)
	if err != nil {
		t.Fatalf("peer.IDFromPublicKey: %v", err)
	}
	if id == id2 {
		t.Fatal("two hybrid keys produced the same peer ID")
	}
}
