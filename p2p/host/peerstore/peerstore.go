package peerstore

import (
	"github.com/JonyBepary/go-libp2p-pq/core/peer"
	pstore "github.com/JonyBepary/go-libp2p-pq/core/peerstore"
)

func PeerInfos(ps pstore.Peerstore, peers peer.IDSlice) []peer.AddrInfo {
	pi := make([]peer.AddrInfo, len(peers))
	for i, p := range peers {
		pi[i] = ps.PeerInfo(p)
	}
	return pi
}

func PeerInfoIDs(pis []peer.AddrInfo) peer.IDSlice {
	ps := make(peer.IDSlice, len(pis))
	for i, pi := range pis {
		ps[i] = pi.ID
	}
	return ps
}
