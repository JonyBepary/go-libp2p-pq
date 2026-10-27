// Package crypto hybrid classical + post-quantum signing key.
//
// This key type wraps the hybrid schemes from
// github.com/quantumcoinproject/circl (a CIRCL fork). The compact variant signs
// with Ed25519 and ML-DSA-44 (the SLH-DSA key is bound into the public key but
// not used for signing), so a signature verifies only if both components are
// valid: breaking either family alone does not break authenticity.
//
// The hybrid scheme signs a fixed 32-byte digest. Arbitrary messages are
// therefore reduced with a domain-separated SHA3-256 first; without the domain
// separator a gossip signature could be replayed as a block or vote signature.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	hybrid "github.com/quantumcoinproject/circl/sign/hybridedmldsaslhdsa"
	"golang.org/x/crypto/sha3"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

// HybridDomainSeparator is prepended to every message before hashing.
const HybridDomainSeparator = "pqs-libp2p-hybrid-v1"

func init() {
	PubKeyUnmarshallers[pb.KeyType_HYBRID_ED25519_MLDSA44] = UnmarshalHybridEd25519MLDSA44PublicKey
	PrivKeyUnmarshallers[pb.KeyType_HYBRID_ED25519_MLDSA44] = UnmarshalHybridEd25519MLDSA44PrivateKey
}

// hybridDigest reduces an arbitrary message to the 32-byte digest the hybrid
// scheme signs, with domain separation.
func hybridDigest(msg []byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write([]byte(HybridDomainSeparator))
	_, _ = h.Write(msg)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type hybridPrivKey struct {
	sk *hybrid.PrivateKey
}

func (k *hybridPrivKey) Type() pb.KeyType { return pb.KeyType_HYBRID_ED25519_MLDSA44 }

func (k *hybridPrivKey) Raw() ([]byte, error) { return k.sk.MarshalBinary() }

func (k *hybridPrivKey) Equals(o Key) bool { return basicEquals(k, o) }

func (k *hybridPrivKey) Sign(msg []byte) (sig []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "hybrid signing") }()
	digest := hybridDigest(msg)
	return hybrid.SignCompact(k.sk, rand.Reader, digest[:])
}

func (k *hybridPrivKey) GetPublic() PubKey {
	pub, err := k.sk.GetPublicKey()
	if err != nil {
		// GetPublicKey only fails on an internally inconsistent key, which
		// cannot arise from a key constructed through this package.
		panic(fmt.Sprintf("hybrid private key is inconsistent: %v", err))
	}
	return &hybridPubKey{pk: pub}
}

type hybridPubKey struct {
	pk *hybrid.PublicKey
}

func (k *hybridPubKey) Type() pb.KeyType { return pb.KeyType_HYBRID_ED25519_MLDSA44 }

func (k *hybridPubKey) Raw() ([]byte, error) { return k.pk.MarshalBinary() }

func (k *hybridPubKey) Equals(o Key) bool { return basicEquals(k, o) }

func (k *hybridPubKey) Verify(data, sig []byte) (ok bool, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "hybrid verification") }()
	digest := hybridDigest(data)
	return hybrid.VerifyCompact(k.pk, digest[:], sig), nil
}

// GenerateHybridEd25519MLDSA44Key generates a hybrid Ed25519 + ML-DSA-44 key pair.
func GenerateHybridEd25519MLDSA44Key(src io.Reader) (PrivKey, PubKey, error) {
	if src == nil {
		src = rand.Reader
	}
	pub, priv, err := hybrid.GenerateKey(src)
	if err != nil {
		return nil, nil, fmt.Errorf("generate hybrid key: %w", err)
	}
	return &hybridPrivKey{sk: priv}, &hybridPubKey{pk: pub}, nil
}

// UnmarshalHybridEd25519MLDSA44PublicKey parses a hybrid public key.
func UnmarshalHybridEd25519MLDSA44PublicKey(data []byte) (PubKey, error) {
	pk, err := hybrid.UnmarshalPublicKey(data)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, errors.New("nil hybrid public key")
	}
	return &hybridPubKey{pk: pk}, nil
}

// UnmarshalHybridEd25519MLDSA44PrivateKey parses a hybrid private key.
func UnmarshalHybridEd25519MLDSA44PrivateKey(data []byte) (PrivKey, error) {
	sk, err := hybrid.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, errors.New("nil hybrid private key")
	}
	return &hybridPrivKey{sk: sk}, nil
}
