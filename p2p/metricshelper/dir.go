package metricshelper

import "github.com/JonyBepary/go-libp2p-pq/core/network"

func GetDirection(dir network.Direction) string {
	switch dir {
	case network.DirOutbound:
		return "outbound"
	case network.DirInbound:
		return "inbound"
	default:
		return "unknown"
	}
}
