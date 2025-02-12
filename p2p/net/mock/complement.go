package mocknet

import (
	"github.com/JonyBepary/go-libp2p-pq/core/network"
)

// StreamComplement returns the other end of the given stream. This function
// panics when passed a non-mocknet stream.
func StreamComplement(s network.Stream) network.Stream {
	return s.(*stream).rstream
}

// ConnComplement returns the other end of the given connection. This function
// panics when passed a non-mocknet connection.
func ConnComplement(c network.Conn) network.Conn {
	return c.(*conn).rconn
}
