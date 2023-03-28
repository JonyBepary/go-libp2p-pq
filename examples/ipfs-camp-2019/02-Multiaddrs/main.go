package main

import (
	"github.com/JonyBepary/go-libp2p-pq"
	"github.com/JonyBepary/go-libp2p-pq/p2p/transport/tcp"
	"github.com/JonyBepary/go-libp2p-pq/p2p/transport/websocket"
)

func main() {
	transports := libp2p.ChainOptions(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
	)

	// TODO: add some listen addresses with the libp2p.ListenAddrs or
	// libp2p.ListenAddrStrings configuration options.

	host, err := libp2p.New(transports)
	if err != nil {
		panic(err)
	}

	// TODO: with our host made, let's connect to our bootstrap peer

	host.Close()
}
