package pstoremanager

import (
	"context"
	"sync"
	"time"

	"github.com/JonyBepary/go-libp2p-pq/core/event"
	"github.com/JonyBepary/go-libp2p-pq/core/network"
	"github.com/JonyBepary/go-libp2p-pq/core/peer"
	"github.com/JonyBepary/go-libp2p-pq/core/peerstore"
	"github.com/JonyBepary/go-libp2p-pq/p2p/host/eventbus"

	logging "github.com/ipfs/go-log/v2"
)

var log = logging.Logger("pstoremanager")

type Option func(*PeerstoreManager) error

// WithGracePeriod sets the grace period.
// If a peer doesn't reconnect during the grace period, its data is removed.
// Default: 1 minute.
func WithGracePeriod(p time.Duration) Option {
	return func(m *PeerstoreManager) error {
		m.gracePeriod = p
		return nil
	}
}

// WithCleanupInterval set the clean up interval.
// During a clean up run peers that disconnected before the grace period are removed.
// If unset, the interval is set to half the grace period.
func WithCleanupInterval(t time.Duration) Option {
	return func(m *PeerstoreManager) error {
		m.cleanupInterval = t
		return nil
	}
}

type PeerstoreManager struct {
	pstore   peerstore.Peerstore
	eventBus event.Bus

	cancel   context.CancelFunc
	refCount sync.WaitGroup

	gracePeriod     time.Duration
	cleanupInterval time.Duration
}

func NewPeerstoreManager(pstore peerstore.Peerstore, eventBus event.Bus, opts ...Option) (*PeerstoreManager, error) {
	m := &PeerstoreManager{
		pstore:      pstore,
		gracePeriod: time.Minute,
		eventBus:    eventBus,
	}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	if m.cleanupInterval == 0 {
		m.cleanupInterval = m.gracePeriod / 2
	}
	return m, nil
}

func (m *PeerstoreManager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	sub, err := m.eventBus.Subscribe(&event.EvtPeerConnectednessChanged{}, eventbus.Name("pstoremanager"))
	if err != nil {
		log.Warnf("subscription failed. Peerstore manager not activated. Error: %s", err)
		return
	}
	m.refCount.Add(1)
	go m.background(ctx, sub)
}

func (m *PeerstoreManager) background(ctx context.Context, sub event.Subscription) {
	defer m.refCount.Done()
	defer sub.Close()
	disconnected := make(map[peer.ID]time.Time)

	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	defer func() {
		for p := range disconnected {
			m.pstore.RemovePeer(p)
		}
	}()

	for {
		select {
		case e, ok := <-sub.Out():
			if !ok {
				return
			}
			ev := e.(event.EvtPeerConnectednessChanged)
			p := ev.Peer
			switch ev.Connectedness {
			case network.NotConnected:
				if _, ok := disconnected[p]; !ok {
					disconnected[p] = time.Now()
				}
			case network.Connected:
				// If we reconnect to the peer before we've cleared the information, keep it.
				delete(disconnected, p)
			}
		case <-ticker.C:
			now := time.Now()
			for p, disconnectTime := range disconnected {
				if disconnectTime.Add(m.gracePeriod).Before(now) {
					m.pstore.RemovePeer(p)
					delete(disconnected, p)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *PeerstoreManager) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.refCount.Wait()
	return nil
}
