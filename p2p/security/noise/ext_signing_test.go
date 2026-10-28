package noise

import (
	"crypto/rand"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/p2p/security/noise/pb"
)

// extensionsDigest must be deterministic and sensitive to every field that
// carries PQ material.
func TestExtensionsDigest(t *testing.T) {
	alg := "X-Wing"
	a := &pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("pk"), PqKemCiphertext: []byte("ct")}
	b := &pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("pk"), PqKemCiphertext: []byte("ct")}
	require.Equal(t, extensionsDigest(a), extensionsDigest(b))

	c := &pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("pk2"), PqKemCiphertext: []byte("ct")}
	require.NotEqual(t, extensionsDigest(a), extensionsDigest(c))

	d := &pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("pk"), PqKemCiphertext: []byte("ct2")}
	require.NotEqual(t, extensionsDigest(a), extensionsDigest(d))

	// nil and empty are the same digest, so a stripped extension is detected by
	// the difference from a non-empty one.
	require.Equal(t, extensionsDigest(nil), extensionsDigest(&pb.NoiseExtensions{}))
	require.NotEqual(t, extensionsDigest(nil), extensionsDigest(a))
}

// The handshake payload signature must cover both the stage-0 extensions and
// the extensions carried in the payload. A verifier with a different stage-0
// digest (what a stripping attacker would produce) must reject.
func TestHandshakeSignatureBindsExtensions(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	static := noise.DHKey{Public: make([]byte, 32), Private: make([]byte, 32)}
	_, _ = rand.Read(static.Public)

	alg := "X-Wing"
	ext := &pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("kem-pk")}
	digest := extensionsDigest(ext)

	signer := &secureSession{localKey: priv}
	payload, err := signer.generateHandshakePayload(static, ext, digest)
	require.NoError(t, err)

	verifier := &secureSession{checkPeerID: false}
	got, err := verifier.handleRemoteHandshakePayload(payload, static.Public, digest)
	require.NoError(t, err)
	require.Equal(t, ext.GetPqKemPubkey(), got.GetPqKemPubkey())

	// A different stage-0 digest means the peer signed a different transcript.
	wrong := extensionsDigest(&pb.NoiseExtensions{PqKemAlgorithm: &alg, PqKemPubkey: []byte("other")})
	_, err = verifier.handleRemoteHandshakePayload(payload, static.Public, wrong)
	require.Error(t, err, "handshake accepted a mismatched stage-0 digest")
	require.Contains(t, err.Error(), "signature")
}
