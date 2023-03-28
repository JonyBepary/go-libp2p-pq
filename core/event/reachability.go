package event

import (
	"github.com/JonyBepary/go-libp2p-pq/core/network"
)

// EvtLocalReachabilityChanged is an event struct to be emitted when the local's
// node reachability changes state.
//
// This event is usually emitted by the AutoNAT subsystem.
type EvtLocalReachabilityChanged struct {
	Reachability network.Reachability
}
