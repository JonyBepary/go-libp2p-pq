// Package crypto ML-DSA signing key implementations.
//
// This file provides three ML-DSA parameter sets as libp2p signing keys,
// all backed by the Cloudflare CIRCL library (github.com/cloudflare/circl).
//
// ML-DSA-44 (KeyType_MLDSA44):
//   - NIST Security Level 2 (≈AES-128)
//   - Public key:  1312 bytes
//   - Private key: 2560 bytes
//   - Signature:   2420 bytes
//
// ML-DSA-65 (KeyType_MLDSA65):
//   - NIST Security Level 3 (≈AES-192)
//   - Public key:  1952 bytes
//   - Private key: 4032 bytes
//   - Signature:   3309 bytes
//
// ML-DSA-87 (KeyType_MLDSA87):
//   - NIST Security Level 5 (≈AES-256)
//   - Public key:  2592 bytes
//   - Private key: 4896 bytes
//   - Signature:   4627 bytes
package crypto

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

func init() {
	PubKeyUnmarshallers[pb.KeyType_MLDSA44] = UnmarshalMLDSA44PublicKey
	PubKeyUnmarshallers[pb.KeyType_MLDSA65] = UnmarshalMLDSA65PublicKey
	PubKeyUnmarshallers[pb.KeyType_MLDSA87] = UnmarshalMLDSA87PublicKey

	PrivKeyUnmarshallers[pb.KeyType_MLDSA44] = UnmarshalMLDSA44PrivateKey
	PrivKeyUnmarshallers[pb.KeyType_MLDSA65] = UnmarshalMLDSA65PrivateKey
	PrivKeyUnmarshallers[pb.KeyType_MLDSA87] = UnmarshalMLDSA87PrivateKey
}

// pqSignPrivKey wraps a CIRCL sign.PrivateKey as a libp2p crypto.PrivKey.
type pqSignPrivKey struct {
	scheme  sign.Scheme
	sk      sign.PrivateKey
	keyType pb.KeyType
}

func (k *pqSignPrivKey) Type() pb.KeyType { return k.keyType }

func (k *pqSignPrivKey) Raw() ([]byte, error) { return k.sk.MarshalBinary() }

func (k *pqSignPrivKey) Equals(o Key) bool { return basicEquals(k, o) }

func (k *pqSignPrivKey) Sign(msg []byte) (sig []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "pq signing") }()
	return k.scheme.Sign(k.sk, msg, nil), nil
}

func (k *pqSignPrivKey) GetPublic() PubKey {
	// crypto.Signer.Public() returns the public key; cast to sign.PublicKey.
	pub := k.sk.Public().(sign.PublicKey)
	return &pqSignPubKey{scheme: k.scheme, pk: pub, keyType: k.keyType}
}

// pqSignPubKey wraps a CIRCL sign.PublicKey as a libp2p crypto.PubKey.
type pqSignPubKey struct {
	scheme  sign.Scheme
	pk      sign.PublicKey
	keyType pb.KeyType
}

func (k *pqSignPubKey) Type() pb.KeyType { return k.keyType }

func (k *pqSignPubKey) Raw() ([]byte, error) { return k.pk.MarshalBinary() }

func (k *pqSignPubKey) Equals(o Key) bool { return basicEquals(k, o) }

func (k *pqSignPubKey) Verify(data, sig []byte) (ok bool, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "pq verification") }()
	return k.scheme.Verify(k.pk, data, sig, nil), nil
}

// generatePQKey generates a key pair using the given scheme and io.Reader.
// If src provides enough bytes for a seed, DeriveKey is used; otherwise
// GenerateKey (which uses crypto/rand internally) is called.
func generatePQKey(scheme sign.Scheme, src io.Reader, keyType pb.KeyType) (PrivKey, PubKey, error) {
	seed := make([]byte, scheme.SeedSize())
	if _, err := io.ReadFull(src, seed); err != nil {
		return nil, nil, fmt.Errorf("reading seed for %s: %w", scheme.Name(), err)
	}
	pub, priv := scheme.DeriveKey(seed)
	privKey := &pqSignPrivKey{scheme: scheme, sk: priv, keyType: keyType}
	pubKey := &pqSignPubKey{scheme: scheme, pk: pub, keyType: keyType}
	return privKey, pubKey, nil
}

// GenerateMLDSA44Key generates an ML-DSA-44 key pair using entropy from src.
func GenerateMLDSA44Key(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(mldsa44.Scheme(), src, pb.KeyType_MLDSA44)
}

// GenerateMLDSA65Key generates an ML-DSA-65 key pair using entropy from src.
func GenerateMLDSA65Key(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(mldsa65.Scheme(), src, pb.KeyType_MLDSA65)
}

// GenerateMLDSA87Key generates an ML-DSA-87 key pair using entropy from src.
func GenerateMLDSA87Key(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(mldsa87.Scheme(), src, pb.KeyType_MLDSA87)
}

// unmarshalPQPublicKey is a helper for unmarshalling PQ public keys with size validation.
func unmarshalPQPublicKey(scheme sign.Scheme, keyType pb.KeyType, data []byte) (PubKey, error) {
	if len(data) != scheme.PublicKeySize() {
		return nil, fmt.Errorf("expected %s public key of %d bytes, got %d",
			scheme.Name(), scheme.PublicKeySize(), len(data))
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}
	return &pqSignPubKey{scheme: scheme, pk: pk, keyType: keyType}, nil
}

// unmarshalPQPrivateKey is a helper for unmarshalling PQ private keys with size validation.
func unmarshalPQPrivateKey(scheme sign.Scheme, keyType pb.KeyType, data []byte) (PrivKey, error) {
	if len(data) != scheme.PrivateKeySize() {
		return nil, fmt.Errorf("expected %s private key of %d bytes, got %d",
			scheme.Name(), scheme.PrivateKeySize(), len(data))
	}
	sk, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &pqSignPrivKey{scheme: scheme, sk: sk, keyType: keyType}, nil
}

// UnmarshalMLDSA44PublicKey parses an ML-DSA-44 public key from raw bytes.
func UnmarshalMLDSA44PublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(mldsa44.Scheme(), pb.KeyType_MLDSA44, data)
}

// UnmarshalMLDSA65PublicKey parses an ML-DSA-65 public key from raw bytes.
func UnmarshalMLDSA65PublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(mldsa65.Scheme(), pb.KeyType_MLDSA65, data)
}

// UnmarshalMLDSA87PublicKey parses an ML-DSA-87 public key from raw bytes.
func UnmarshalMLDSA87PublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(mldsa87.Scheme(), pb.KeyType_MLDSA87, data)
}

// UnmarshalMLDSA44PrivateKey parses an ML-DSA-44 private key from raw bytes.
func UnmarshalMLDSA44PrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(mldsa44.Scheme(), pb.KeyType_MLDSA44, data)
}

// UnmarshalMLDSA65PrivateKey parses an ML-DSA-65 private key from raw bytes.
func UnmarshalMLDSA65PrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(mldsa65.Scheme(), pb.KeyType_MLDSA65, data)
}

// UnmarshalMLDSA87PrivateKey parses an ML-DSA-87 private key from raw bytes.
func UnmarshalMLDSA87PrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(mldsa87.Scheme(), pb.KeyType_MLDSA87, data)
}
