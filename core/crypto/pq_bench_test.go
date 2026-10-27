package crypto

import (
	"crypto/rand"
	"testing"
)

// ML-DSA-44 benchmarks
func BenchmarkMLDSA44KeyGen(b *testing.B) { benchmarkPQKeyGen(b, MLDSA44) }
func BenchmarkMLDSA44Sign(b *testing.B)   { benchmarkPQSign(b, MLDSA44) }
func BenchmarkMLDSA44Verify(b *testing.B) { benchmarkPQVerify(b, MLDSA44) }

// ML-DSA-65 benchmarks
func BenchmarkMLDSA65KeyGen(b *testing.B) { benchmarkPQKeyGen(b, MLDSA65) }
func BenchmarkMLDSA65Sign(b *testing.B)   { benchmarkPQSign(b, MLDSA65) }
func BenchmarkMLDSA65Verify(b *testing.B) { benchmarkPQVerify(b, MLDSA65) }

// ML-DSA-87 benchmarks
func BenchmarkMLDSA87KeyGen(b *testing.B) { benchmarkPQKeyGen(b, MLDSA87) }
func BenchmarkMLDSA87Sign(b *testing.B)   { benchmarkPQSign(b, MLDSA87) }
func BenchmarkMLDSA87Verify(b *testing.B) { benchmarkPQVerify(b, MLDSA87) }

// SLH-DSA-SHA2-128s benchmarks
func BenchmarkSLHDSA_SHA2_128s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_128s) }
func BenchmarkSLHDSA_SHA2_128s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_128s) }
func BenchmarkSLHDSA_SHA2_128s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_128s) }

// SLH-DSA-SHA2-128f benchmarks
func BenchmarkSLHDSA_SHA2_128f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_128f) }
func BenchmarkSLHDSA_SHA2_128f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_128f) }
func BenchmarkSLHDSA_SHA2_128f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_128f) }

// SLH-DSA-SHA2-192s benchmarks
func BenchmarkSLHDSA_SHA2_192s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_192s) }
func BenchmarkSLHDSA_SHA2_192s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_192s) }
func BenchmarkSLHDSA_SHA2_192s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_192s) }

// SLH-DSA-SHA2-192f benchmarks
func BenchmarkSLHDSA_SHA2_192f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_192f) }
func BenchmarkSLHDSA_SHA2_192f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_192f) }
func BenchmarkSLHDSA_SHA2_192f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_192f) }

// SLH-DSA-SHA2-256s benchmarks
func BenchmarkSLHDSA_SHA2_256s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_256s) }
func BenchmarkSLHDSA_SHA2_256s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_256s) }
func BenchmarkSLHDSA_SHA2_256s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_256s) }

// SLH-DSA-SHA2-256f benchmarks
func BenchmarkSLHDSA_SHA2_256f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHA2_256f) }
func BenchmarkSLHDSA_SHA2_256f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHA2_256f) }
func BenchmarkSLHDSA_SHA2_256f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHA2_256f) }

// SLH-DSA-SHAKE-128s benchmarks
func BenchmarkSLHDSA_SHAKE_128s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_128s) }
func BenchmarkSLHDSA_SHAKE_128s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_128s) }
func BenchmarkSLHDSA_SHAKE_128s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_128s) }

// SLH-DSA-SHAKE-128f benchmarks
func BenchmarkSLHDSA_SHAKE_128f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_128f) }
func BenchmarkSLHDSA_SHAKE_128f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_128f) }
func BenchmarkSLHDSA_SHAKE_128f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_128f) }

// SLH-DSA-SHAKE-192s benchmarks
func BenchmarkSLHDSA_SHAKE_192s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_192s) }
func BenchmarkSLHDSA_SHAKE_192s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_192s) }
func BenchmarkSLHDSA_SHAKE_192s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_192s) }

// SLH-DSA-SHAKE-192f benchmarks
func BenchmarkSLHDSA_SHAKE_192f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_192f) }
func BenchmarkSLHDSA_SHAKE_192f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_192f) }
func BenchmarkSLHDSA_SHAKE_192f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_192f) }

// SLH-DSA-SHAKE-256s benchmarks
func BenchmarkSLHDSA_SHAKE_256s_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_256s) }
func BenchmarkSLHDSA_SHAKE_256s_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_256s) }
func BenchmarkSLHDSA_SHAKE_256s_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_256s) }

// SLH-DSA-SHAKE-256f benchmarks
func BenchmarkSLHDSA_SHAKE_256f_KeyGen(b *testing.B) { benchmarkPQKeyGen(b, SLHDSA_SHAKE_256f) }
func BenchmarkSLHDSA_SHAKE_256f_Sign(b *testing.B)   { benchmarkPQSign(b, SLHDSA_SHAKE_256f) }
func BenchmarkSLHDSA_SHAKE_256f_Verify(b *testing.B) { benchmarkPQVerify(b, SLHDSA_SHAKE_256f) }

// benchmarkPQKeyGen measures key pair generation time for a PQ signing algorithm.
func benchmarkPQKeyGen(b *testing.B, typ int) {
	b.Helper()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKeyPairWithReader(typ, 0, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarkPQSign measures signing time for a PQ signing algorithm over a 100-byte message.
func benchmarkPQSign(b *testing.B, typ int) {
	b.Helper()
	sk, _, err := GenerateKeyPairWithReader(typ, 0, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.Sign(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarkPQVerify measures signature verification time for a PQ signing algorithm.
func benchmarkPQVerify(b *testing.B, typ int) {
	b.Helper()
	sk, pk, err := GenerateKeyPairWithReader(typ, 0, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 100)
	sig, err := sk.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := pk.Verify(msg, sig)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("signature should be valid")
		}
	}
}
