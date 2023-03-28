package host

import "github.com/JonyBepary/go-libp2p-pq/core/peer"

// InfoFromHost returns a peer.AddrInfo struct with the Host's ID and all of its Addrs.
func InfoFromHost(h Host) *peer.AddrInfo {
	return &peer.AddrInfo{
		ID:    h.ID(),
		Addrs: h.Addrs(),
	}
}
