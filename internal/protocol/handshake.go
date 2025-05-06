package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mjtas/customVPN/internal/peer"
)

const (
	// Packet types
	PacketHandshake      = 1
	PacketHandshakeReply = 2
	PacketData           = 3
	PacketKeepalive      = 4

	// Magic value to identify valid packets
	PacketMagic = 0x4D565050

	// Handshake retry parameters
	HandshakeRetryCount    = 5
	HandshakeRetryInterval = 2 * time.Second
)

// HandshakePacket represents the handshake message format
type HandshakePacket struct {
	Magic     uint32   // Magic bytes to identify valid VPN packets
	Type      uint8    // Packet type (1 = handshake initiation)
	Timestamp uint64   // Timestamp to prevent replay attacks
	PublicKey [32]byte // Sender's public key
	Reserved  [3]byte  // Reserved for future use
}

// NewHandshakePacket creates a new handshake packet
func NewHandshakePacket(publicKey [32]byte, isReply bool) *HandshakePacket {
	packetType := PacketHandshake
	if isReply {
		packetType = PacketHandshakeReply
	}

	return &HandshakePacket{
		Magic:     PacketMagic,
		Type:      uint8(packetType),
		Timestamp: uint64(time.Now().UnixNano()),
		PublicKey: publicKey,
	}
}

// Marshal converts a HandshakePacket to bytes
func (p *HandshakePacket) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.Magic)
	binary.Write(buf, binary.BigEndian, p.Type)
	binary.Write(buf, binary.BigEndian, p.Timestamp)
	buf.Write(p.PublicKey[:])
	buf.Write(p.Reserved[:])
	return buf.Bytes()
}

// SendHandshake sends a handshake packet to the specified endpoint
func (v *VPNHandler) SendHandshake(endpoint *net.UDPAddr, isReply bool) error {
	// Create handshake packet
	handshake := NewHandshakePacket(v.cfg.Keys.PublicKey, isReply)

	// Marshal the packet
	packetData := handshake.Marshal()

	// Send the handshake packet
	_, err := v.conn.WriteToUDP(packetData, endpoint)
	if err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	log.Printf("Handshake %s sent to %s", map[bool]string{false: "initiation", true: "reply"}[isReply], endpoint)
	return nil
}

// ProcessHandshake handles received handshake packets
func (v *VPNHandler) ProcessHandshake(data []byte, addr *net.UDPAddr) error {
	if len(data) < 44 { // Minimum handshake packet size
		return fmt.Errorf("handshake packet too small: %d bytes", len(data))
	}

	// Parse the handshake packet
	var handshake HandshakePacket
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.BigEndian, &handshake.Magic); err != nil {
		return fmt.Errorf("failed to read magic: %w", err)
	}

	if handshake.Magic != PacketMagic {
		return fmt.Errorf("invalid magic value: 0x%x", handshake.Magic)
	}

	if err := binary.Read(buf, binary.BigEndian, &handshake.Type); err != nil {
		return fmt.Errorf("failed to read packet type: %w", err)
	}

	if handshake.Type != PacketHandshake && handshake.Type != PacketHandshakeReply {
		return fmt.Errorf("not a handshake packet: type %d", handshake.Type)
	}

	if err := binary.Read(buf, binary.BigEndian, &handshake.Timestamp); err != nil {
		return fmt.Errorf("failed to read timestamp: %w", err)
	}

	// Check timestamp to prevent replay attacks (within 30 second window)
	now := uint64(time.Now().UnixNano())
	if now > handshake.Timestamp && now-handshake.Timestamp > uint64(30*time.Second) {
		return fmt.Errorf("handshake packet too old (possible replay attack)")
	}

	// Read public key
	if _, err := buf.Read(handshake.PublicKey[:]); err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	// Read reserved bytes
	if _, err := buf.Read(handshake.Reserved[:]); err != nil {
		return fmt.Errorf("failed to read reserved bytes: %w", err)
	}

	// Extract peer ID from public key
	peerID := string(handshake.PublicKey[:])

	// Check if we know this peer
	existingPeer, peerExists := v.peerMap.GetPeer(peerID)

	if !peerExists {
		// New peer - create and add it
		newPeer := &peer.Peer{
			Endpoint:   addr,
			PublicKey:  handshake.PublicKey,
			AllowedIPs: []string{"10.100.0.0/24"}, // Default allowed subnet
			LastSeen:   time.Now(),
		}
		v.peerMap.AddOrUpdatePeer(peerID, newPeer)
		log.Printf("New peer registered from %s with public key: %x", addr.String(), handshake.PublicKey[:8])
	} else {
		// Update existing peer
		existingPeer.Mu.Lock()
		existingPeer.Endpoint = addr
		existingPeer.LastSeen = time.Now()
		existingPeer.Mu.Unlock()
		log.Printf("Updated peer from %s with public key: %x", addr.String(), handshake.PublicKey[:8])
	}

	// If this is a handshake initiation, send a reply
	if handshake.Type == PacketHandshake {
		if err := v.SendHandshake(addr, true); err != nil {
			return fmt.Errorf("failed to send handshake reply: %w", err)
		}
	}

	return nil
}

// PerformHandshake attempts to establish a connection with a peer
func (v *VPNHandler) PerformHandshake(peer *peer.Peer) error {
	// Send initial handshake
	if err := v.SendHandshake(peer.Endpoint, false); err != nil {
		return fmt.Errorf("handshake initiation failed: %w", err)
	}

	return nil
}

// performInitialHandshake implements the initial handshake procedure for client mode
func performInitialHandshake(ctx context.Context, handler *VPNHandler, serverPubKey [32]byte) error {
	const (
		handshakeTimeout   = 30 * time.Second
		stateCheckInterval = 100 * time.Millisecond
	)

	log.Printf("Attempting initial handshake with server")

	deadline := time.Now().Add(handshakeTimeout)
	serverKeyStr := string(serverPubKey[:])

	// Validate server key format before starting
	if bytes.Equal(serverPubKey[:], make([]byte, 32)) {
		return fmt.Errorf("invalid server public key - all zeros")
	}

	for attempt := 1; attempt <= HandshakeRetryCount; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("handshake cancelled by context")
		default:
			if time.Now().After(deadline) {
				return fmt.Errorf("handshake timed out after %s", handshakeTimeout)
			}

			// Get fresh peer reference each attempt
			serverPeer, exists := handler.peerMap.GetPeer(serverKeyStr)
			if !exists {
				return fmt.Errorf("server peer disappeared from peer map")
			}

			log.Printf("Sending handshake attempt %d/%d", attempt, HandshakeRetryCount)
			if err := handler.SendHandshake(serverPeer.Endpoint, false); err != nil {
				log.Printf("Handshake send error: %v", err)
				continue
			}

			// Monitor peer state changes instead of raw packets
			success := false
			stateCheckDeadline := time.After(HandshakeRetryInterval)

			for !success {
				select {
				case <-stateCheckDeadline:
					log.Printf("No response to attempt %d", attempt)
					break
				case <-time.After(stateCheckInterval):
					currentPeer, _ := handler.peerMap.GetPeer(serverKeyStr)

					if currentPeer != nil &&
						time.Since(currentPeer.LastSeen) < 2*time.Second &&
						currentPeer.Endpoint.String() != "" {
						success = true
						log.Printf("Handshake verified through peer state update")
						break
					}
				}
			}

			if success {
				// Final verification of cryptographic identity
				if !bytes.Equal(serverPeer.PublicKey[:], serverPubKey[:]) {
					log.Printf("Key mismatch after handshake! Expected: %x Got: %x",
						serverPubKey[:4], serverPeer.PublicKey[:4])
					return fmt.Errorf("server identity verification failed")
				}

				log.Printf("Handshake completed successfully")
				return nil
			}
		}
	}

	// Post-failure analysis
	currentPeer, _ := handler.peerMap.GetPeer(serverKeyStr)
	if currentPeer == nil {
		return fmt.Errorf("server peer not found in peer map")
	}

	timeSinceContact := time.Since(currentPeer.LastSeen)
	return fmt.Errorf("handshake failed after %d attempts. Last contact: %v ago",
		HandshakeRetryCount, timeSinceContact.Round(time.Second))
}

// ValidateHandshakeReply checks if a received packet is a valid handshake reply
func (v *VPNHandler) ValidateHandshakeReply(data []byte) (bool, [32]byte, error) {
	if len(data) < 44 {
		return false, [32]byte{}, fmt.Errorf("packet too small for handshake reply")
	}

	var magic uint32
	var packetType uint8
	var peerKey [32]byte

	buf := bytes.NewReader(data)
	binary.Read(buf, binary.BigEndian, &magic)

	if magic != PacketMagic {
		return false, peerKey, fmt.Errorf("invalid magic value")
	}

	binary.Read(buf, binary.BigEndian, &packetType)

	if packetType != PacketHandshakeReply {
		return false, peerKey, nil // Not a handshake reply, but not an error
	}

	// Skip timestamp
	binary.Read(buf, binary.BigEndian, new(uint64))

	// Read peer public key - ensure we read the full 32 bytes
	n, err := buf.Read(peerKey[:])
	if err != nil || n != 32 {
		return false, peerKey, fmt.Errorf("failed to read complete public key, got %d bytes: %v", n, err)
	}

	return true, peerKey, nil
}
