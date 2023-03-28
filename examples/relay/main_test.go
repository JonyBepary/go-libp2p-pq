package main

import (
	"os"
	"testing"

	"github.com/JonyBepary/go-libp2p-pq/examples/testutils"
)

func TestMain(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("This test is flaky on CI, see https://github.com/JonyBepary/go-libp2p-pq/issues/1158.")
	}
	var h testutils.LogHarness
	h.ExpectPrefix("As suspected we cannot directly dial between the unreachable hosts")
	h.ExpectPrefix("Awesome! We're now communicating via the relay!")
	h.Run(t, run)
}
