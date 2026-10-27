package noise

import (
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/canonicallog"
	tptu "github.com/libp2p/go-libp2p/p2p/net/upgrader"
	"github.com/libp2p/go-libp2p/p2p/security/noise/pb"

	manet "github.com/multiformats/go-multiaddr/net"
)

// KEMAlgorithm identifies a KEM algorithm for the Noise PQ extension.
type KEMAlgorithm int

const (
	// KEMAlgorithmXWing is the X-Wing hybrid KEM (X25519 + ML-KEM-768).
	KEMAlgorithmXWing KEMAlgorithm = iota
	// KEMAlgorithmMLKEM768X25519 is the ML-KEM-768 + X25519 hybrid KEM.
	KEMAlgorithmMLKEM768X25519
	// KEMAlgorithmMLKEM512X25519 is the ML-KEM-512 + X25519 hybrid KEM.
	KEMAlgorithmMLKEM512X25519
	// KEMAlgorithmMLKEM1024X448 is the ML-KEM-1024 + X448 hybrid KEM.
	KEMAlgorithmMLKEM1024X448
)

// kemSchemeForAlgorithm returns the CIRCL kem.Scheme and algorithm name string
// for the given KEMAlgorithm.
func kemSchemeForAlgorithm(alg KEMAlgorithm) (kem.Scheme, string, error) {
	switch alg {
	case KEMAlgorithmXWing:
		return xwing.Scheme(), "X-Wing", nil
	case KEMAlgorithmMLKEM768X25519:
		return hybrid.X25519MLKEM768(), "ML-KEM-768+X25519", nil
	case KEMAlgorithmMLKEM512X25519:
		return hybrid.Kyber512X25519(), "ML-KEM-512+X25519", nil
	case KEMAlgorithmMLKEM1024X448:
		return hybrid.Kyber1024X448(), "ML-KEM-1024+X448", nil
	default:
		return nil, "", fmt.Errorf("unknown KEM algorithm: %d", alg)
	}
}

// ID is the protocol ID for noise
const ID = "/noise"
const maxProtoNum = 100

type Transport struct {
	protocolID protocol.ID
	localID    peer.ID
	privateKey crypto.PrivKey
	muxers     []protocol.ID
}

var _ sec.SecureTransport = &Transport{}

// New creates a new Noise transport using the given private key as its
// libp2p identity key.
func New(id protocol.ID, privkey crypto.PrivKey, muxers []tptu.StreamMuxer) (*Transport, error) {
	localID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	muxerIDs := make([]protocol.ID, 0, len(muxers))
	for _, m := range muxers {
		muxerIDs = append(muxerIDs, m.ID)
	}

	return &Transport{
		protocolID: id,
		localID:    localID,
		privateKey: privkey,
		muxers:     muxerIDs,
	}, nil
}

// SecureInbound runs the Noise handshake as the responder.
// If p is empty, connections from any peer are accepted.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	responderEDH := newTransportEDH(t)
	c, err := newSecureSession(t, ctx, insecure, p, nil, nil, responderEDH, false, p != "", false, 0)
	if err != nil {
		addr, maErr := manet.FromNetAddr(insecure.RemoteAddr())
		if maErr == nil {
			canonicallog.LogPeerStatus(100, p, addr, "handshake_failure", "noise", "err", err.Error())
		}
	}
	return SessionWithConnState(c, responderEDH.MatchMuxers(false)), err
}

// SecureOutbound runs the Noise handshake as the initiator.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	initiatorEDH := newTransportEDH(t)
	c, err := newSecureSession(t, ctx, insecure, p, nil, initiatorEDH, nil, true, true, false, 0)
	if err != nil {
		return c, err
	}
	return SessionWithConnState(c, initiatorEDH.MatchMuxers(true)), err
}

func (t *Transport) WithSessionOptions(opts ...SessionOption) (*SessionTransport, error) {
	st := &SessionTransport{t: t, protocolID: t.protocolID}
	for _, opt := range opts {
		if err := opt(st); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func (t *Transport) ID() protocol.ID {
	return t.protocolID
}

func matchMuxers(initiatorMuxers, responderMuxers []protocol.ID) protocol.ID {
	for _, initMuxer := range initiatorMuxers {
		if slices.Contains(responderMuxers, initMuxer) {
			return initMuxer
		}
	}
	return ""
}

type transportEarlyDataHandler struct {
	transport      *Transport
	receivedMuxers []protocol.ID
}

var _ EarlyDataHandler = &transportEarlyDataHandler{}

func newTransportEDH(t *Transport) *transportEarlyDataHandler {
	return &transportEarlyDataHandler{transport: t}
}

func (i *transportEarlyDataHandler) Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions {
	return &pb.NoiseExtensions{
		StreamMuxers: protocol.ConvertToStrings(i.transport.muxers),
	}
}

func (i *transportEarlyDataHandler) Received(_ context.Context, _ net.Conn, extension *pb.NoiseExtensions) error {
	// Discard messages with size or the number of protocols exceeding extension limit for security.
	if extension != nil && len(extension.StreamMuxers) <= maxProtoNum {
		i.receivedMuxers = protocol.ConvertFromStrings(extension.GetStreamMuxers())
	}
	return nil
}

func (i *transportEarlyDataHandler) MatchMuxers(isInitiator bool) protocol.ID {
	if isInitiator {
		return matchMuxers(i.transport.muxers, i.receivedMuxers)
	}
	return matchMuxers(i.receivedMuxers, i.transport.muxers)
}
