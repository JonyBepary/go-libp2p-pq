package crypto

import (
	"fmt"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

// Four-byte algorithm identifiers.
//
// These are written into the optional `Algorithm` (fixed32) field of the
// PublicKey and PrivateKey protobufs. fixed32 is exactly 4 bytes on the wire,
// so identifiers come from a flat 32-bit space and cannot collide with enum
// values that future versions of this repo might add to the legacy `Type`
// field. The 0x0A000000 block is reserved for post-quantum signing algorithms.
const (
	AlgorithmMLDSA44 uint32 = 0x0A000000
	AlgorithmMLDSA65 uint32 = 0x0A000001
	AlgorithmMLDSA87 uint32 = 0x0A000002

	AlgorithmSLHDSASHA2128s uint32 = 0x0A000010
	AlgorithmSLHDSASHA2128f uint32 = 0x0A000011
	AlgorithmSLHDSASHA2192s uint32 = 0x0A000012
	AlgorithmSLHDSASHA2192f uint32 = 0x0A000013
	AlgorithmSLHDSASHA2256s uint32 = 0x0A000014
	AlgorithmSLHDSASHA2256f uint32 = 0x0A000015

	AlgorithmSLHDSASHAKE128s uint32 = 0x0A000020
	AlgorithmSLHDSASHAKE128f uint32 = 0x0A000021
	AlgorithmSLHDSASHAKE192s uint32 = 0x0A000022
	AlgorithmSLHDSASHAKE192f uint32 = 0x0A000023
	AlgorithmSLHDSASHAKE256s uint32 = 0x0A000024
	AlgorithmSLHDSASHAKE256f uint32 = 0x0A000025
)

var algorithmByKeyType = map[pb.KeyType]uint32{
	pb.KeyType_MLDSA44: AlgorithmMLDSA44,
	pb.KeyType_MLDSA65: AlgorithmMLDSA65,
	pb.KeyType_MLDSA87: AlgorithmMLDSA87,

	pb.KeyType_SLHDSA_SHA2_128s: AlgorithmSLHDSASHA2128s,
	pb.KeyType_SLHDSA_SHA2_128f: AlgorithmSLHDSASHA2128f,
	pb.KeyType_SLHDSA_SHA2_192s: AlgorithmSLHDSASHA2192s,
	pb.KeyType_SLHDSA_SHA2_192f: AlgorithmSLHDSASHA2192f,
	pb.KeyType_SLHDSA_SHA2_256s: AlgorithmSLHDSASHA2256s,
	pb.KeyType_SLHDSA_SHA2_256f: AlgorithmSLHDSASHA2256f,

	pb.KeyType_SLHDSA_SHAKE_128s: AlgorithmSLHDSASHAKE128s,
	pb.KeyType_SLHDSA_SHAKE_128f: AlgorithmSLHDSASHAKE128f,
	pb.KeyType_SLHDSA_SHAKE_192s: AlgorithmSLHDSASHAKE192s,
	pb.KeyType_SLHDSA_SHAKE_192f: AlgorithmSLHDSASHAKE192f,
	pb.KeyType_SLHDSA_SHAKE_256s: AlgorithmSLHDSASHAKE256s,
	pb.KeyType_SLHDSA_SHAKE_256f: AlgorithmSLHDSASHAKE256f,
}

var keyTypeByAlgorithm = func() map[uint32]pb.KeyType {
	m := make(map[uint32]pb.KeyType, len(algorithmByKeyType))
	for kt, alg := range algorithmByKeyType {
		m[alg] = kt
	}
	return m
}()

// AlgorithmForKeyType returns the 4-byte algorithm identifier for a key type.
// The second result is false for legacy (non-PQ) key types, which keep using
// the enum field only.
func AlgorithmForKeyType(kt pb.KeyType) (uint32, bool) {
	alg, ok := algorithmByKeyType[kt]
	return alg, ok
}

// KeyTypeForAlgorithm maps a 4-byte algorithm identifier back to a key type.
func KeyTypeForAlgorithm(alg uint32) (pb.KeyType, bool) {
	kt, ok := keyTypeByAlgorithm[alg]
	return kt, ok
}

// resolveKeyType applies the wire precedence rule for key messages:
//
//  1. If Algorithm is present, it is authoritative. An unknown identifier is an
//     error: falling back to Type would silently reinterpret a key under an
//     algorithm the peer did not intend.
//  2. If Algorithm is absent, Type is used (legacy behaviour).
//  3. Type may be ALGORITHM_EXT as an explicit "see Algorithm" marker.
//  4. Otherwise Type and Algorithm must agree; a disagreement is rejected rather
//     than resolved by picking a winner.
func resolveKeyType(legacy pb.KeyType, algorithm *uint32) (pb.KeyType, error) {
	if algorithm == nil {
		return legacy, nil
	}
	kt, ok := KeyTypeForAlgorithm(*algorithm)
	if !ok {
		return 0, fmt.Errorf("%w: unknown algorithm 0x%08X", ErrBadKeyType, *algorithm)
	}
	switch {
	case legacy == pb.KeyType_ALGORITHM_EXT:
		// Explicit escape hatch: the 4-byte field is authoritative.
		return kt, nil
	case legacy == kt:
		return kt, nil
	default:
		return 0, fmt.Errorf("%w: Type %s contradicts Algorithm 0x%08X (%s)",
			ErrBadKeyType, legacy, *algorithm, kt)
	}
}
