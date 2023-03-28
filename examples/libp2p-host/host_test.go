package main

import (
	"testing"

	"github.com/JonyBepary/go-libp2p-pq/examples/testutils"
)

func TestMain(t *testing.T) {
	var h testutils.LogHarness
	h.ExpectPrefix("Hello World, my hosts ID is ")
	h.ExpectPrefix("Hello World, my second hosts ID is ")
	h.Run(t, run)
}
