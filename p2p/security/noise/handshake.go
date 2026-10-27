package noise

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/security/noise/pb"

	"github.com/flynn/noise"
	pool "github.com/libp2p/go-buffer-pool"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

// payloadSigPrefix is prepended to our Noise static key before signing with
// our libp2p identity key.
const payloadSigPrefix = "noise-libp2p-static-key:"

// All noise session share a fixed cipher suite
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// runHandshake exchanges handshake messages with the remote peer to establish
// a noise-libp2p session. It blocks until the handshake completes or fails.
func (s *secureSession) runHandshake(ctx context.Context) (err error) {
	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Fprintf(os.Stderr, "caught panic: %s\n%s\n", rerr, debug.Stack())
			err = fmt.Errorf("panic in Noise handshake: %s", rerr)
		}
	}()

	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating static keypair: %w", err)
	}

	cfg := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     s.initiator,
		StaticKeypair: kp,
		Prologue:      s.prologue,
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("error initializing handshake state: %w", err)
	}

	// set a deadline to complete the handshake, if one has been supplied.
	// clear it after we're done.
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.SetDeadline(deadline); err == nil {
			// schedule the deadline removal once we're done handshaking.
			defer s.SetDeadline(time.Time{})
		}
	}

	// We can re-use this buffer for all handshake messages.
	hbuf := pool.Get(2 << 10)
	defer pool.Put(hbuf)

	if s.initiator {
		// stage 0 //
		// If PQ KEM is enabled, generate an ephemeral KEM keypair and include
		// the public key in the stage 0 payload (unencrypted in XX pattern).
		var kemPrivKey kem.PrivateKey
		var stage0Payload []byte
		if s.pqKEMEnabled {
			kemScheme, algName, err := kemSchemeForAlgorithm(s.kemAlgorithm)
			if err != nil {
				return err
			}
			kemPub, kemPriv, err := kemScheme.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("pq kem key generation failed: %w", err)
			}
			kemPrivKey = kemPriv
			kemPubBytes, err := kemPub.MarshalBinary()
			if err != nil {
				return fmt.Errorf("pq kem public key marshal failed: %w", err)
			}
			algNameStr := algName
			ext := &pb.NoiseExtensions{
				PqKemPubkey:    kemPubBytes,
				PqKemAlgorithm: &algNameStr,
			}
			stage0Payload, err = proto.Marshal(&pb.NoiseHandshakePayload{
				Extensions: ext,
			})
			if err != nil {
				return fmt.Errorf("error marshaling stage 0 KEM payload: %w", err)
			}
		}

		if err := s.sendHandshakeMessage(hs, stage0Payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// stage 1 //
		plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}
		rcvdEd, err := s.handleRemoteHandshakePayload(plaintext, hs.PeerStatic())
		if err != nil {
			return err
		}

		// If PQ KEM is enabled, decapsulate the ciphertext from stage 1 extensions.
		var kemSharedSecret []byte
		if kemPrivKey != nil && rcvdEd != nil && len(rcvdEd.GetPqKemCiphertext()) > 0 {
			kemScheme, _, err := kemSchemeForAlgorithm(s.kemAlgorithm)
			if err != nil {
				return err
			}
			kemSharedSecret, err = kemScheme.Decapsulate(kemPrivKey, rcvdEd.GetPqKemCiphertext())
			if err != nil {
				return fmt.Errorf("pq kem decapsulation failed: %w", err)
			}
		}

		if s.initiatorEarlyDataHandler != nil {
			if err := s.initiatorEarlyDataHandler.Received(ctx, s.insecureConn, rcvdEd); err != nil {
				return err
			}
		}

		// stage 2 //
		// Handshake Msg Len = len(DHT static key) +  MAC(static key is encrypted) + len(Payload) + MAC(payload is encrypted)
		var ed *pb.NoiseExtensions
		if s.initiatorEarlyDataHandler != nil {
			ed = s.initiatorEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
		}
		payload, err := s.generateHandshakePayload(kp, ed)
		if err != nil {
			return err
		}
		if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// Mix the PQ KEM shared secret into the session cipher states.
		if len(kemSharedSecret) > 0 {
			if err := s.mixKEMSecret(kemSharedSecret); err != nil {
				return fmt.Errorf("pq kem mix key failed: %w", err)
			}
		}
		return nil
	} else {
		// stage 0 //
		stage0Plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}

		// Parse stage 0 payload for PQ KEM public key (if present).
		var kemSharedSecret []byte
		var kemCiphertext []byte
		if len(stage0Plaintext) > 0 {
			stage0Payload := new(pb.NoiseHandshakePayload)
			if err := proto.Unmarshal(stage0Plaintext, stage0Payload); err == nil {
				ext := stage0Payload.GetExtensions()
				if ext != nil && len(ext.GetPqKemPubkey()) > 0 {
					algName := ext.GetPqKemAlgorithm()
					kemScheme, err := kemSchemeByName(algName)
					if err == nil {
						kemPub, err := kemScheme.UnmarshalBinaryPublicKey(ext.GetPqKemPubkey())
						if err == nil {
							ct, ss, err := kemScheme.Encapsulate(kemPub)
							if err != nil {
								return fmt.Errorf("pq kem encapsulation failed: %w", err)
							}
							kemSharedSecret = ss
							kemCiphertext = ct
						}
					}
				}
			}
		}

		// stage 1 //
		// Handshake Msg Len = len(DH ephemeral key) + len(DHT static key) +  MAC(static key is encrypted) + len(Payload) +
		// MAC(payload is encrypted)
		var ed *pb.NoiseExtensions
		if s.responderEarlyDataHandler != nil {
			ed = s.responderEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
		}
		// Include KEM ciphertext in stage 1 extensions if we encapsulated.
		if len(kemCiphertext) > 0 {
			if ed == nil {
				ed = &pb.NoiseExtensions{}
			}
			ed.PqKemCiphertext = kemCiphertext
		}
		payload, err := s.generateHandshakePayload(kp, ed)
		if err != nil {
			return err
		}
		if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// stage 2 //
		plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}
		rcvdEd, err := s.handleRemoteHandshakePayload(plaintext, hs.PeerStatic())
		if err != nil {
			return err
		}
		if s.responderEarlyDataHandler != nil {
			if err := s.responderEarlyDataHandler.Received(ctx, s.insecureConn, rcvdEd); err != nil {
				return err
			}
		}

		// Mix the PQ KEM shared secret into the session cipher states.
		if len(kemSharedSecret) > 0 {
			if err := s.mixKEMSecret(kemSharedSecret); err != nil {
				return fmt.Errorf("pq kem mix key failed: %w", err)
			}
		}
		return nil
	}
}

// mixKEMSecret mixes the PQ KEM shared secret into the session cipher states
// using HKDF-SHA256. This folds the PQ secret into the session keys after
// the standard Noise XX handshake completes.
// PQKEMNegotiated reports whether this session actually used the PQ KEM
// extension. It is false when the peer did not advertise or return KEM data,
// which is exactly the silent classical fallback.
func (s *secureSession) PQKEMNegotiated() bool { return s.pqKEMNegotiated }

// PQKEMAlgorithmName returns the configured KEM algorithm name.
func (s *secureSession) PQKEMAlgorithmName() string {
	if !s.pqKEMEnabled {
		return ""
	}
	_, name, err := kemSchemeForAlgorithm(s.kemAlgorithm)
	if err != nil {
		return ""
	}
	return name
}

func (s *secureSession) mixKEMSecret(kemSharedSecret []byte) error {
	s.pqKEMNegotiated = true
	// Derive new keys by mixing the KEM shared secret with the current cipher keys.
	// We use HKDF-SHA256 with the KEM shared secret as the IKM and the current
	// enc/dec keys as the salt to produce new enc/dec keys.
	encKey := s.enc.UnsafeKey()
	decKey := s.dec.UnsafeKey()

	newEncKey, err := hkdfDeriveKey(encKey[:], kemSharedSecret)
	if err != nil {
		return err
	}
	newDecKey, err := hkdfDeriveKey(decKey[:], kemSharedSecret)
	if err != nil {
		return err
	}

	s.enc = noise.UnsafeNewCipherState(cipherSuite, newEncKey, 0)
	s.dec = noise.UnsafeNewCipherState(cipherSuite, newDecKey, 0)
	return nil
}

// hkdfDeriveKey derives a 32-byte key using HKDF-SHA256 with the given
// input key material (ikm) and salt.
func hkdfDeriveKey(salt, ikm []byte) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, ikm, salt, []byte("noise-libp2p-pq-kem"))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// kemSchemeByName returns the CIRCL kem.Scheme for the given algorithm name string.
// This is used by the responder to look up the scheme from the initiator's extension.
func kemSchemeByName(name string) (kem.Scheme, error) {
	for _, alg := range []KEMAlgorithm{KEMAlgorithmXWing, KEMAlgorithmMLKEM768X25519, KEMAlgorithmMLKEM512X25519, KEMAlgorithmMLKEM1024X448} {
		scheme, algName, err := kemSchemeForAlgorithm(alg)
		if err == nil && algName == name {
			return scheme, nil
		}
	}
	return nil, fmt.Errorf("unknown KEM algorithm name: %q", name)
}

// setCipherStates sets the initial cipher states that will be used to protect
// traffic after the handshake.
//
// It is called when the final handshake message is processed by
// either sendHandshakeMessage or readHandshakeMessage.
func (s *secureSession) setCipherStates(cs1, cs2 *noise.CipherState) {
	if s.initiator {
		s.enc = cs1
		s.dec = cs2
	} else {
		s.enc = cs2
		s.dec = cs1
	}
}

// sendHandshakeMessage sends the next handshake message in the sequence.
//
// If payload is non-empty, it will be included in the handshake message.
// If this is the final message in the sequence, calls setCipherStates
// to initialize cipher states.
func (s *secureSession) sendHandshakeMessage(hs *noise.HandshakeState, payload []byte, hbuf []byte) error {
	// the first two bytes will be the length of the noise handshake message.
	bz, cs1, cs2, err := hs.WriteMessage(hbuf[:LengthPrefixLength], payload)
	if err != nil {
		return err
	}

	// bz will also include the length prefix as we passed a slice of LengthPrefixLength length
	// to hs.Write().
	binary.BigEndian.PutUint16(bz, uint16(len(bz)-LengthPrefixLength))

	_, err = s.writeMsgInsecure(bz)
	if err != nil {
		return err
	}

	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return nil
}

// readHandshakeMessage reads a message from the insecure conn and tries to
// process it as the expected next message in the handshake sequence.
//
// If the message contains a payload, it will be decrypted and returned.
//
// If this is the final message in the sequence, it calls setCipherStates
// to initialize cipher states.
func (s *secureSession) readHandshakeMessage(hs *noise.HandshakeState) ([]byte, error) {
	l, err := s.readNextInsecureMsgLen()
	if err != nil {
		return nil, err
	}

	buf := pool.Get(l)
	defer pool.Put(buf)

	if err := s.readNextMsgInsecure(buf); err != nil {
		return nil, err
	}

	msg, cs1, cs2, err := hs.ReadMessage(nil, buf)
	if err != nil {
		return nil, err
	}
	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return msg, nil
}

// generateHandshakePayload creates a libp2p handshake payload with a
// signature of our static noise key.
func (s *secureSession) generateHandshakePayload(localStatic noise.DHKey, ext *pb.NoiseExtensions) ([]byte, error) {
	// obtain the public key from the handshake session, so we can sign it with
	// our libp2p secret key.
	localKeyRaw, err := crypto.MarshalPublicKey(s.LocalPublicKey())
	if err != nil {
		return nil, fmt.Errorf("error serializing libp2p identity key: %w", err)
	}

	// prepare payload to sign; perform signature.
	toSign := append([]byte(payloadSigPrefix), localStatic.Public...)
	signedPayload, err := s.localKey.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("error signing handshake payload: %w", err)
	}

	// create payload
	payloadEnc, err := proto.Marshal(&pb.NoiseHandshakePayload{
		IdentityKey: localKeyRaw,
		IdentitySig: signedPayload,
		Extensions:  ext,
	})
	if err != nil {
		return nil, fmt.Errorf("error marshaling handshake payload: %w", err)
	}
	return payloadEnc, nil
}

// handleRemoteHandshakePayload unmarshals the handshake payload object sent
// by the remote peer and validates the signature against the peer's static Noise key.
// It returns the data attached to the payload.
func (s *secureSession) handleRemoteHandshakePayload(payload []byte, remoteStatic []byte) (*pb.NoiseExtensions, error) {
	// unmarshal payload
	nhp := new(pb.NoiseHandshakePayload)
	err := proto.Unmarshal(payload, nhp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling remote handshake payload: %w", err)
	}

	// unpack remote peer's public libp2p key
	remotePubKey, err := crypto.UnmarshalPublicKey(nhp.GetIdentityKey())
	if err != nil {
		return nil, err
	}
	id, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}

	// check the peer ID if enabled
	if s.checkPeerID && s.remoteID != id {
		return nil, sec.ErrPeerIDMismatch{Expected: s.remoteID, Actual: id}
	}

	// verify payload is signed by asserted remote libp2p key.
	sig := nhp.GetIdentitySig()
	msg := append([]byte(payloadSigPrefix), remoteStatic...)
	ok, err := remotePubKey.Verify(msg, sig)
	if err != nil {
		return nil, fmt.Errorf("error verifying signature: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("handshake signature invalid")
	}

	// set remote peer key and id
	s.remoteID = id
	s.remoteKey = remotePubKey
	return nhp.Extensions, nil
}
