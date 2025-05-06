package peer

import (
	"log"
	"net"
	"sync"
	"time"
)

// Peer represents a remote VPN endpoint with associated security parameters and connection state
type Peer struct {
	Endpoint   *net.UDPAddr
	PublicKey  [32]byte
	AllowedIPs []string // CIDR notation routes
	LastSeen   time.Time
	Mu         sync.RWMutex // Protects against concurrent state modifications
}

// PeerMap manages a thread-safe collection of peer
type PeerMap struct {
	peers map[string]*Peer
	mu    sync.RWMutex
}

// NewPeerMap creates a new peer map
func NewPeerMap() *PeerMap {
	return &PeerMap{
		peers: make(map[string]*Peer),
	}
}

// AddOrUpdatePeer adds a new peer or updates an existing one
func (pm *PeerMap) AddOrUpdatePeer(peerID string, peer *Peer) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.peers[peerID] = peer
}

// GetPeer retrieves a peer by ID
func (pm *PeerMap) GetPeer(peerID string) (*Peer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peer, exists := pm.peers[peerID]
	return peer, exists
}

// RemovePeer removes a peer from the map
func (pm *PeerMap) RemovePeer(peerID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.peers, peerID)
}

// FindPeerByEndpoint finds a peer by its endpoint address
func (pm *PeerMap) FindPeerByEndpoint(addr *net.UDPAddr) (*Peer, string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for peerID, peer := range pm.peers {
		peer.Mu.RLock()
		sameEndpoint := peer.Endpoint != nil && peer.Endpoint.String() == addr.String()
		peer.Mu.RUnlock()

		if sameEndpoint {
			return peer, peerID
		}
	}

	return nil, ""
}

// FindBestPeerForDestination finds the best peer for routing to a destination IP
func (pm *PeerMap) FindBestPeerForDestination(dstIP net.IP) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var bestPeer *Peer
	var bestPrefixLen int = -1

	for _, peer := range pm.peers {
		peer.Mu.RLock()
		for _, cidrStr := range peer.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Printf("Invalid CIDR %s: %v", cidrStr, err)
				continue
			}

			// Check if destination matches this CIDR
			if ipNet.Contains(dstIP) {
				// Calculate prefix length
				_, bits := ipNet.Mask.Size()
				if bits > bestPrefixLen {
					bestPeer = peer
					bestPrefixLen = bits
				}
			}
		}
		peer.Mu.RUnlock()
	}

	return bestPeer
}

// UpdateLastSeen updates the LastSeen timestamp for a peer
func (p *Peer) UpdateLastSeen() {
	p.Mu.Lock()
	defer p.Mu.Unlock()
	p.LastSeen = time.Now()
}

// GetLastSeen safely retrieves the LastSeen timestamp
func (p *Peer) GetLastSeen() time.Time {
	p.Mu.RLock()
	defer p.Mu.RUnlock()
	return p.LastSeen
}

// RemoveStalePeers removes peer that haven't been seen for over 2 minutes
func (pm *PeerMap) RemoveStalePeers() []string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var removed []string
	now := time.Now()

	for peerID, peer := range pm.peers {
		peer.Mu.RLock()
		lastSeen := peer.LastSeen
		endpoint := peer.Endpoint
		peer.Mu.RUnlock()

		if now.Sub(lastSeen) > 2*time.Minute {
			log.Printf("Peer %s is stale (last seen %s ago)",
				endpoint, now.Sub(lastSeen).String())
			delete(pm.peers, peerID)
			removed = append(removed, peerID)
		}
	}

	return removed
}

// ForEach executes a function for each peer in the map
func (pm *PeerMap) ForEach(f func(peerID string, peer *Peer)) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for peerID, peer := range pm.peers {
		f(peerID, peer)
	}
}
