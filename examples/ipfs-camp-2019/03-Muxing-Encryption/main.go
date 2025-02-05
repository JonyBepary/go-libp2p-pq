package main

import (
	"context"
	"fmt"
	"time"

	"github.com/JonyBepary/go-libp2p-pq"
	"github.com/JonyBepary/go-libp2p-pq/p2p/transport/tcp"
	"github.com/JonyBepary/go-libp2p-pq/p2p/transport/websocket"

	"github.com/JonyBepary/go-libp2p-pq/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	transports := libp2p.ChainOptions(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
	)

	// TODO: add a libp2p.Security instance and some libp2p.Muxer's

	listenAddrs := libp2p.ListenAddrStrings(
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/0.0.0.0/tcp/0/ws",
	)

	host, err := libp2p.New(transports, listenAddrs)
	if err != nil {
		panic(err)
	}
	defer host.Close()

	for _, addr := range host.Addrs() {
		fmt.Println("Listening on", addr)
	}

	targetAddr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/63785/p2p/QmWjz6xb8v9K4KnYEwP5Yk75k5mMBCehzWFLCvvQpYxF3d")
	if err != nil {
		panic(err)
	}

	targetInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = host.Connect(ctx, *targetInfo)
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to", targetInfo.ID)
}
