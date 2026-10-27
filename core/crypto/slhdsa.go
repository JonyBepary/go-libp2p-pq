// Package crypto SLH-DSA signing key implementations.
//
// This file provides twelve SLH-DSA parameter sets as libp2p signing keys,
// all backed by the Cloudflare CIRCL library (github.com/cloudflare/circl).
//
// SLH-DSA-SHA2-128s (KeyType_SLHDSA_SHA2_128s):
//   - NIST Security Level 1
//   - Public key:  32 bytes
//   - Private key: 64 bytes
//   - Signature:   7856 bytes
//
// SLH-DSA-SHA2-128f (KeyType_SLHDSA_SHA2_128f):
//   - NIST Security Level 1
//   - Public key:  32 bytes
//   - Private key: 64 bytes
//   - Signature:   17088 bytes
//
// SLH-DSA-SHA2-192s (KeyType_SLHDSA_SHA2_192s):
//   - NIST Security Level 3
//   - Public key:  48 bytes
//   - Private key: 96 bytes
//   - Signature:   16224 bytes
//
// SLH-DSA-SHA2-192f (KeyType_SLHDSA_SHA2_192f):
//   - NIST Security Level 3
//   - Public key:  48 bytes
//   - Private key: 96 bytes
//   - Signature:   35664 bytes
//
// SLH-DSA-SHA2-256s (KeyType_SLHDSA_SHA2_256s):
//   - NIST Security Level 5
//   - Public key:  64 bytes
//   - Private key: 128 bytes
//   - Signature:   29792 bytes
//
// SLH-DSA-SHA2-256f (KeyType_SLHDSA_SHA2_256f):
//   - NIST Security Level 5
//   - Public key:  64 bytes
//   - Private key: 128 bytes
//   - Signature:   49856 bytes
//
// SLH-DSA-SHAKE-128s (KeyType_SLHDSA_SHAKE_128s):
//   - NIST Security Level 1
//   - Public key:  32 bytes
//   - Private key: 64 bytes
//   - Signature:   7856 bytes
//
// SLH-DSA-SHAKE-128f (KeyType_SLHDSA_SHAKE_128f):
//   - NIST Security Level 1
//   - Public key:  32 bytes
//   - Private key: 64 bytes
//   - Signature:   17088 bytes
//
// SLH-DSA-SHAKE-192s (KeyType_SLHDSA_SHAKE_192s):
//   - NIST Security Level 3
//   - Public key:  48 bytes
//   - Private key: 96 bytes
//   - Signature:   16224 bytes
//
// SLH-DSA-SHAKE-192f (KeyType_SLHDSA_SHAKE_192f):
//   - NIST Security Level 3
//   - Public key:  48 bytes
//   - Private key: 96 bytes
//   - Signature:   35664 bytes
//
// SLH-DSA-SHAKE-256s (KeyType_SLHDSA_SHAKE_256s):
//   - NIST Security Level 5
//   - Public key:  64 bytes
//   - Private key: 128 bytes
//   - Signature:   29792 bytes
//
// SLH-DSA-SHAKE-256f (KeyType_SLHDSA_SHAKE_256f):
//   - NIST Security Level 5
//   - Public key:  64 bytes
//   - Private key: 128 bytes
//   - Signature:   49856 bytes
package crypto

import (
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

func init() {
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_128s] = UnmarshalSLHDSASHA2128sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_128f] = UnmarshalSLHDSASHA2128fPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_192s] = UnmarshalSLHDSASHA2192sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_192f] = UnmarshalSLHDSASHA2192fPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_256s] = UnmarshalSLHDSASHA2256sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_256f] = UnmarshalSLHDSASHA2256fPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_128s] = UnmarshalSLHDSASHAKE128sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_128f] = UnmarshalSLHDSASHAKE128fPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_192s] = UnmarshalSLHDSASHAKE192sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_192f] = UnmarshalSLHDSASHAKE192fPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_256s] = UnmarshalSLHDSASHAKE256sPublicKey
	PubKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_256f] = UnmarshalSLHDSASHAKE256fPublicKey

	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_128s] = UnmarshalSLHDSASHA2128sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_128f] = UnmarshalSLHDSASHA2128fPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_192s] = UnmarshalSLHDSASHA2192sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_192f] = UnmarshalSLHDSASHA2192fPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_256s] = UnmarshalSLHDSASHA2256sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHA2_256f] = UnmarshalSLHDSASHA2256fPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_128s] = UnmarshalSLHDSASHAKE128sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_128f] = UnmarshalSLHDSASHAKE128fPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_192s] = UnmarshalSLHDSASHAKE192sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_192f] = UnmarshalSLHDSASHAKE192fPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_256s] = UnmarshalSLHDSASHAKE256sPrivateKey
	PrivKeyUnmarshallers[pb.KeyType_SLHDSA_SHAKE_256f] = UnmarshalSLHDSASHAKE256fPrivateKey
}

// GenerateSLHDSASHA2128sKey generates an SLH-DSA-SHA2-128s key pair using entropy from src.
func GenerateSLHDSASHA2128sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_128s.Scheme(), src, pb.KeyType_SLHDSA_SHA2_128s)
}

// GenerateSLHDSASHA2128fKey generates an SLH-DSA-SHA2-128f key pair using entropy from src.
func GenerateSLHDSASHA2128fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_128f.Scheme(), src, pb.KeyType_SLHDSA_SHA2_128f)
}

// GenerateSLHDSASHA2192sKey generates an SLH-DSA-SHA2-192s key pair using entropy from src.
func GenerateSLHDSASHA2192sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_192s.Scheme(), src, pb.KeyType_SLHDSA_SHA2_192s)
}

// GenerateSLHDSASHA2192fKey generates an SLH-DSA-SHA2-192f key pair using entropy from src.
func GenerateSLHDSASHA2192fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_192f.Scheme(), src, pb.KeyType_SLHDSA_SHA2_192f)
}

// GenerateSLHDSASHA2256sKey generates an SLH-DSA-SHA2-256s key pair using entropy from src.
func GenerateSLHDSASHA2256sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_256s.Scheme(), src, pb.KeyType_SLHDSA_SHA2_256s)
}

// GenerateSLHDSASHA2256fKey generates an SLH-DSA-SHA2-256f key pair using entropy from src.
func GenerateSLHDSASHA2256fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHA2_256f.Scheme(), src, pb.KeyType_SLHDSA_SHA2_256f)
}

// GenerateSLHDSASHAKE128sKey generates an SLH-DSA-SHAKE-128s key pair using entropy from src.
func GenerateSLHDSASHAKE128sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_128s.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_128s)
}

// GenerateSLHDSASHAKE128fKey generates an SLH-DSA-SHAKE-128f key pair using entropy from src.
func GenerateSLHDSASHAKE128fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_128f.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_128f)
}

// GenerateSLHDSASHAKE192sKey generates an SLH-DSA-SHAKE-192s key pair using entropy from src.
func GenerateSLHDSASHAKE192sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_192s.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_192s)
}

// GenerateSLHDSASHAKE192fKey generates an SLH-DSA-SHAKE-192f key pair using entropy from src.
func GenerateSLHDSASHAKE192fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_192f.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_192f)
}

// GenerateSLHDSASHAKE256sKey generates an SLH-DSA-SHAKE-256s key pair using entropy from src.
func GenerateSLHDSASHAKE256sKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_256s.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_256s)
}

// GenerateSLHDSASHAKE256fKey generates an SLH-DSA-SHAKE-256f key pair using entropy from src.
func GenerateSLHDSASHAKE256fKey(src io.Reader) (PrivKey, PubKey, error) {
	return generatePQKey(slhdsa.SHAKE_256f.Scheme(), src, pb.KeyType_SLHDSA_SHAKE_256f)
}

// UnmarshalSLHDSASHA2128sPublicKey parses an SLH-DSA-SHA2-128s public key from raw bytes.
func UnmarshalSLHDSASHA2128sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_128s.Scheme(), pb.KeyType_SLHDSA_SHA2_128s, data)
}

// UnmarshalSLHDSASHA2128fPublicKey parses an SLH-DSA-SHA2-128f public key from raw bytes.
func UnmarshalSLHDSASHA2128fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_128f.Scheme(), pb.KeyType_SLHDSA_SHA2_128f, data)
}

// UnmarshalSLHDSASHA2192sPublicKey parses an SLH-DSA-SHA2-192s public key from raw bytes.
func UnmarshalSLHDSASHA2192sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_192s.Scheme(), pb.KeyType_SLHDSA_SHA2_192s, data)
}

// UnmarshalSLHDSASHA2192fPublicKey parses an SLH-DSA-SHA2-192f public key from raw bytes.
func UnmarshalSLHDSASHA2192fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_192f.Scheme(), pb.KeyType_SLHDSA_SHA2_192f, data)
}

// UnmarshalSLHDSASHA2256sPublicKey parses an SLH-DSA-SHA2-256s public key from raw bytes.
func UnmarshalSLHDSASHA2256sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_256s.Scheme(), pb.KeyType_SLHDSA_SHA2_256s, data)
}

// UnmarshalSLHDSASHA2256fPublicKey parses an SLH-DSA-SHA2-256f public key from raw bytes.
func UnmarshalSLHDSASHA2256fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHA2_256f.Scheme(), pb.KeyType_SLHDSA_SHA2_256f, data)
}

// UnmarshalSLHDSASHAKE128sPublicKey parses an SLH-DSA-SHAKE-128s public key from raw bytes.
func UnmarshalSLHDSASHAKE128sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_128s.Scheme(), pb.KeyType_SLHDSA_SHAKE_128s, data)
}

// UnmarshalSLHDSASHAKE128fPublicKey parses an SLH-DSA-SHAKE-128f public key from raw bytes.
func UnmarshalSLHDSASHAKE128fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_128f.Scheme(), pb.KeyType_SLHDSA_SHAKE_128f, data)
}

// UnmarshalSLHDSASHAKE192sPublicKey parses an SLH-DSA-SHAKE-192s public key from raw bytes.
func UnmarshalSLHDSASHAKE192sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_192s.Scheme(), pb.KeyType_SLHDSA_SHAKE_192s, data)
}

// UnmarshalSLHDSASHAKE192fPublicKey parses an SLH-DSA-SHAKE-192f public key from raw bytes.
func UnmarshalSLHDSASHAKE192fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_192f.Scheme(), pb.KeyType_SLHDSA_SHAKE_192f, data)
}

// UnmarshalSLHDSASHAKE256sPublicKey parses an SLH-DSA-SHAKE-256s public key from raw bytes.
func UnmarshalSLHDSASHAKE256sPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_256s.Scheme(), pb.KeyType_SLHDSA_SHAKE_256s, data)
}

// UnmarshalSLHDSASHAKE256fPublicKey parses an SLH-DSA-SHAKE-256f public key from raw bytes.
func UnmarshalSLHDSASHAKE256fPublicKey(data []byte) (PubKey, error) {
	return unmarshalPQPublicKey(slhdsa.SHAKE_256f.Scheme(), pb.KeyType_SLHDSA_SHAKE_256f, data)
}

// UnmarshalSLHDSASHA2128sPrivateKey parses an SLH-DSA-SHA2-128s private key from raw bytes.
func UnmarshalSLHDSASHA2128sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_128s.Scheme(), pb.KeyType_SLHDSA_SHA2_128s, data)
}

// UnmarshalSLHDSASHA2128fPrivateKey parses an SLH-DSA-SHA2-128f private key from raw bytes.
func UnmarshalSLHDSASHA2128fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_128f.Scheme(), pb.KeyType_SLHDSA_SHA2_128f, data)
}

// UnmarshalSLHDSASHA2192sPrivateKey parses an SLH-DSA-SHA2-192s private key from raw bytes.
func UnmarshalSLHDSASHA2192sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_192s.Scheme(), pb.KeyType_SLHDSA_SHA2_192s, data)
}

// UnmarshalSLHDSASHA2192fPrivateKey parses an SLH-DSA-SHA2-192f private key from raw bytes.
func UnmarshalSLHDSASHA2192fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_192f.Scheme(), pb.KeyType_SLHDSA_SHA2_192f, data)
}

// UnmarshalSLHDSASHA2256sPrivateKey parses an SLH-DSA-SHA2-256s private key from raw bytes.
func UnmarshalSLHDSASHA2256sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_256s.Scheme(), pb.KeyType_SLHDSA_SHA2_256s, data)
}

// UnmarshalSLHDSASHA2256fPrivateKey parses an SLH-DSA-SHA2-256f private key from raw bytes.
func UnmarshalSLHDSASHA2256fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHA2_256f.Scheme(), pb.KeyType_SLHDSA_SHA2_256f, data)
}

// UnmarshalSLHDSASHAKE128sPrivateKey parses an SLH-DSA-SHAKE-128s private key from raw bytes.
func UnmarshalSLHDSASHAKE128sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_128s.Scheme(), pb.KeyType_SLHDSA_SHAKE_128s, data)
}

// UnmarshalSLHDSASHAKE128fPrivateKey parses an SLH-DSA-SHAKE-128f private key from raw bytes.
func UnmarshalSLHDSASHAKE128fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_128f.Scheme(), pb.KeyType_SLHDSA_SHAKE_128f, data)
}

// UnmarshalSLHDSASHAKE192sPrivateKey parses an SLH-DSA-SHAKE-192s private key from raw bytes.
func UnmarshalSLHDSASHAKE192sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_192s.Scheme(), pb.KeyType_SLHDSA_SHAKE_192s, data)
}

// UnmarshalSLHDSASHAKE192fPrivateKey parses an SLH-DSA-SHAKE-192f private key from raw bytes.
func UnmarshalSLHDSASHAKE192fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_192f.Scheme(), pb.KeyType_SLHDSA_SHAKE_192f, data)
}

// UnmarshalSLHDSASHAKE256sPrivateKey parses an SLH-DSA-SHAKE-256s private key from raw bytes.
func UnmarshalSLHDSASHAKE256sPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_256s.Scheme(), pb.KeyType_SLHDSA_SHAKE_256s, data)
}

// UnmarshalSLHDSASHAKE256fPrivateKey parses an SLH-DSA-SHAKE-256f private key from raw bytes.
func UnmarshalSLHDSASHAKE256fPrivateKey(data []byte) (PrivKey, error) {
	return unmarshalPQPrivateKey(slhdsa.SHAKE_256f.Scheme(), pb.KeyType_SLHDSA_SHAKE_256f, data)
}
