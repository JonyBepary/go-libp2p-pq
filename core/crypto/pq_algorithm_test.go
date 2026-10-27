package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
)

// mlDSA65 generates an ML-DSA-65 key pair for tests.
func mlDSA65(t *testing.T) (crypto.PrivKey, crypto.PubKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateKeyPair(crypto.MLDSA65, 0)
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	return priv, pub
}

// The Algorithm field must be a 4-byte fixed32 on the wire, not a varint.
func TestAlgorithmFieldIsFixed32(t *testing.T) {
	_, pub := mlDSA65(t)

	encoded, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	var found bool
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
				if val != crypto.AlgorithmMLDSA65 {
					t.Fatalf("algorithm = 0x%08X, want 0x%08X", val, crypto.AlgorithmMLDSA65)
				}
				if m != 4 {
					t.Fatalf("algorithm field consumed %d bytes, want 4", m)
				}
			}
			n = m
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(rest)
		default:
			t.Fatalf("unexpected wire type %d for field %d", typ, num)
		}
		if n < 0 {
			t.Fatalf("malformed protobuf: %v", protowire.ParseError(n))
		}
		rest = rest[n:]
	}

	if !found {
		t.Fatal("Algorithm field (3) missing from the marshalled public key")
	}
}

func TestLegacyKeyHasNoAlgorithmField(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	encoded, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rest := encoded
	for len(rest) > 0 {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			t.Fatalf("malformed protobuf: %v", protowire.ParseError(n))
		}
		if num == 3 {
			t.Fatal("legacy Ed25519 key must not carry an Algorithm field")
		}
		rest = rest[n:]
		switch typ {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(rest)
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(rest)
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(rest)
		default:
			t.Fatalf("unexpected wire type %d", typ)
		}
		if n < 0 {
			t.Fatalf("malformed protobuf: %v", protowire.ParseError(n))
		}
		rest = rest[n:]
	}
}

func TestPQKeyRoundTrip(t *testing.T) {
	priv, pub := mlDSA65(t)

	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	pubBack, err := crypto.UnmarshalPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("unmarshal public: %v", err)
	}
	if pubBack.Type() != pb.KeyType_MLDSA65 {
		t.Fatalf("type = %s, want MLDSA65", pubBack.Type())
	}
	rawOriginal, err := pub.Raw()
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	rawBack, err := pubBack.Raw()
	if err != nil {
		t.Fatalf("raw back: %v", err)
	}
	if !bytes.Equal(rawOriginal, rawBack) {
		t.Fatal("public key bytes changed across marshal/unmarshal")
	}

	privBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	privBack, err := crypto.UnmarshalPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("unmarshal private: %v", err)
	}

	message := []byte("pqs block header hash")
	sig, err := privBack.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := pubBack.Verify(message, sig)
	if err != nil || !ok {
		t.Fatalf("verify failed (ok=%v err=%v)", ok, err)
	}

	// A signature must not verify under a different key or message.
	_, otherPub := mlDSA65(t)
	if ok, _ := otherPub.Verify(message, sig); ok {
		t.Fatal("signature verified under an unrelated key")
	}
	if ok, _ := pubBack.Verify([]byte("different"), sig); ok {
		t.Fatal("signature verified for a different message")
	}
}

func TestPQKeyPeerID(t *testing.T) {
	_, pub := mlDSA65(t)
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("peer.IDFromPublicKey: %v", err)
	}
	if len(id) == 0 {
		t.Fatal("empty peer ID")
	}

	_, pub2 := mlDSA65(t)
	id2, err := peer.IDFromPublicKey(pub2)
	if err != nil {
		t.Fatalf("peer.IDFromPublicKey: %v", err)
	}
	if id == id2 {
		t.Fatal("two distinct ML-DSA keys produced the same peer ID")
	}
}

func TestUnknownAlgorithmRejected(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatalf("raw: %v", err)
	}

	unknown := uint32(0x0B000001) // outside the reserved PQ block, unregistered
	_, err = crypto.PublicKeyFromProto(&pb.PublicKey{
		Type:      pb.KeyType_Ed25519.Enum(),
		Data:      raw,
		Algorithm: &unknown,
	})
	if !errors.Is(err, crypto.ErrBadKeyType) {
		t.Fatalf("unknown algorithm: err = %v, want ErrBadKeyType", err)
	}
}

func TestConflictingTypeAndAlgorithmRejected(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatalf("raw: %v", err)
	}

	// The legacy field claims Ed25519 while the 4-byte field claims ML-DSA-65;
	// one of them is a lie, so the message must be rejected.
	conflict := crypto.AlgorithmMLDSA65
	_, err = crypto.PublicKeyFromProto(&pb.PublicKey{
		Type:      pb.KeyType_Ed25519.Enum(),
		Data:      raw,
		Algorithm: &conflict,
	})
	if !errors.Is(err, crypto.ErrBadKeyType) {
		t.Fatalf("conflicting type/algorithm: err = %v, want ErrBadKeyType", err)
	}
}

func TestAlgorithmRegistryIsConsistent(t *testing.T) {
	for _, kt := range []pb.KeyType{
		pb.KeyType_MLDSA44, pb.KeyType_MLDSA65, pb.KeyType_MLDSA87,
		pb.KeyType_SLHDSA_SHA2_128s, pb.KeyType_SLHDSA_SHAKE_256f,
	} {
		alg, ok := crypto.AlgorithmForKeyType(kt)
		if !ok {
			t.Fatalf("%s has no algorithm identifier", kt)
		}
		if alg&0xFFFF0000 != 0x0A000000 {
			t.Errorf("%s algorithm 0x%08X is outside the reserved PQ block", kt, alg)
		}
		back, ok := crypto.KeyTypeForAlgorithm(alg)
		if !ok || back != kt {
			t.Errorf("round-trip failed for %s (0x%08X -> %s)", kt, alg, back)
		}
	}

	if _, ok := crypto.AlgorithmForKeyType(pb.KeyType_Ed25519); ok {
		t.Error("Ed25519 must not carry a 4-byte algorithm identifier")
	}
}

func TestAlgorithmExtMarkerAccepted(t *testing.T) {
	_, pub := mlDSA65(t)
	raw, err := pub.Raw()
	if err != nil {
		t.Fatalf("raw: %v", err)
	}

	alg := crypto.AlgorithmMLDSA65
	got, err := crypto.PublicKeyFromProto(&pb.PublicKey{
		Type:      pb.KeyType_ALGORITHM_EXT.Enum(),
		Data:      raw,
		Algorithm: &alg,
	})
	if err != nil {
		t.Fatalf("ALGORITHM_EXT public key rejected: %v", err)
	}
	if got.Type() != pb.KeyType_MLDSA65 {
		t.Fatalf("type = %s, want MLDSA65", got.Type())
	}
}
