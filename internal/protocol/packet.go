package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mjtas/customVPN/internal/config"
	"github.com/mjtas/customVPN/internal/crypto"
	"github.com/mjtas/customVPN/internal/peer"
	"github.com/songgao/water"
)

// VPNHandler is the main controller responsible for handling packet I/O
type VPNHandler struct {
	cfg     *config.Config
	conn    *net.UDPConn
	iface   *water.Interface
	peerMap *peer.PeerMap
}

// DataPacket represents the structure of an encrypted VPN data packet
type DataPacket struct {
	Magic    uint32  // Magic bytes to identify valid VPN packets
	Type     uint8   // Packet type (3 = data)
	Reserved [3]byte // Reserved for future use
	Data     []byte  // Encrypted payload
}

// ReadFromTUN reads IP packets from the TUN interface and forwards them to appropriate peers
func (v *VPNHandler) ReadFromTUN(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("ReadFromTUN: started")

	buffer := make([]byte, config.DefaultMTU)

	// Create a read channel to handle non-blocking reads
	readCh := make(chan struct {
		n   int
		err error
	})

	for {
		// Start a goroutine to read from TUN (which might block)
		go func() {
			n, err := v.iface.Read(buffer)
			// Only send if not cancelled
			select {
			case <-ctx.Done():
				return
			case readCh <- struct {
				n   int
				err error
			}{n, err}:
			}
		}()

		select {
		case <-ctx.Done():
			log.Println("ReadFromTUN: context cancelled, exiting")
			return

		case result := <-readCh:
			if result.err != nil {
				if result.err == io.EOF || ctx.Err() != nil {
					log.Println("ReadFromTUN: TUN interface closed or context cancelled")
					return
				}
				log.Printf("TUN read error: %v", result.err)
				continue
			}

			n := result.n
			if n < 20 { // Too small for IP packet
				continue
			}

			// Process IP packet version
			ipVersion := (buffer[0] >> 4) & 0xF // Get IP version from first 4 bits

			// Different handling for IPv4 and IPv6
			var dstIP net.IP
			if ipVersion == 4 && n >= 20 { // IPv4 packet
				dstIP = net.IP(buffer[16:20])
			} else if ipVersion == 6 && n >= 40 { // IPv6 packet (minimum header size is 40 bytes)
				dstIP = net.IP(buffer[24:40])
			} else {
				log.Printf("Unsupported IP version or malformed packet: %d", ipVersion)
				continue
			}

			// Forward to the appropriate peer
			v.forwardPacketToPeer(buffer[:n], dstIP)
		}
	}
}

// forwardPacketToPeer finds the best peer for a destination and forwards the packet
func (v *VPNHandler) forwardPacketToPeer(packet []byte, dstIP net.IP) {
	// Find the best peer for this destination
	destinationPeer := v.peerMap.FindBestPeerForDestination(dstIP)
	if destinationPeer == nil {
		if v.cfg.Mode == "client" {
			// In client mode, forward all traffic to the server by default
			v.peerMap.ForEach(func(peerID string, p *peer.Peer) {
				destinationPeer = p
			})
		} else {
			log.Printf("No peer found for destination %s", dstIP.String())
			return
		}
	}

	if destinationPeer == nil {
		return
	}

	destinationPeer.Mu.RLock()
	endpoint := destinationPeer.Endpoint
	peerKey := destinationPeer.PublicKey
	destinationPeer.Mu.RUnlock()

	if endpoint == nil {
		log.Printf("Peer has no endpoint")
		return
	}

	// Encrypt the packet for the peer
	encryptedPacket, err := v.encryptPacketForPeer(packet, peerKey)
	if err != nil {
		log.Printf("Encryption failed: %v", err)
		return
	}

	// Send to the peer
	if _, err := v.conn.WriteToUDP(encryptedPacket, endpoint); err != nil {
		log.Printf("UDP write error: %v", err)
	}
}

// encryptPacketForPeer encrypts a data packet for a specific peer
func (v *VPNHandler) encryptPacketForPeer(packet []byte, peerKey [32]byte) ([]byte, error) {
	// Debug info
	if v.cfg.Debug {
		printPacketInfo(packet, "Sending packet")
	}

	// Encrypt packet data using NaCl box
	encrypted, err := crypto.EncryptPacket(v.cfg.Keys.PrivateKey, peerKey, packet)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Create data packet header
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(PacketMagic))
	binary.Write(buf, binary.BigEndian, uint8(PacketData))
	buf.Write([]byte{0, 0, 0}) // Reserved bytes

	// Combine header and encrypted data
	buf.Write(encrypted)

	finalPacket := buf.Bytes()

	// Debug info
	if v.cfg.Debug {
		log.Printf("Created VPN packet: Magic=0x%x, Type=%d, DataLen=%d",
			PacketMagic, PacketData, len(encrypted))
	}

	return finalPacket, nil
}

// ReadFromUDP reads encrypted packets from the UDP socket and processes them
func (v *VPNHandler) ReadFromUDP(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("ReadFromUDP: started")

	buffer := make([]byte, config.ReadBufferSize)

	// Create a channel to signal shutdown
	done := make(chan struct{})

	// Goroutine to close the connection when context is cancelled
	go func() {
		<-ctx.Done()
		log.Println("ReadFromUDP: context cancelled, closing socket")
		v.conn.Close() // Unblock any pending Read operations
		close(done)
	}()

	for {
		select {
		case <-done:
			log.Println("ReadFromUDP: shutdown signal received, exiting")
			return
		default:
			// Set a short read deadline to allow for context cancellation checks
			v.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			n, addr, err := v.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}

				// Check for context cancellation or connection closed
				if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
					log.Println("ReadFromUDP: connection closed or context cancelled")
					return
				}

				log.Printf("UDP read error: %v", err)
				continue
			}

			if n < 8 { // Too small for a valid packet
				log.Printf("Received packet too small: %d bytes", n)
				continue
			}

			log.Printf("Received %d bytes: %x", n, buffer[:n])

			// Check packet type
			magic := binary.BigEndian.Uint32(buffer[:4])
			if magic != PacketMagic {
				log.Printf("Invalid packet magic: 0x%x", magic)
				continue
			}

			packetType := buffer[4]

			switch packetType {
			case PacketHandshake, PacketHandshakeReply:
				if err := v.ProcessHandshake(buffer[:n], addr); err != nil {
					log.Printf("Handshake processing error: %v", err)
				}

			case PacketData:
				// Process data packet
				if err := v.processDataPacket(buffer[:n], addr); err != nil {
					log.Printf("Data packet processing error: %v", err)
				}

			case PacketKeepalive:
				// Process keepalive packet (update peer lastSeen)
				p, _ := v.peerMap.FindPeerByEndpoint(addr)
				if p != nil {
					p.UpdateLastSeen()
				}

			default:
				log.Printf("Unknown packet type: %d", packetType)
			}
		}
	}
}

// processDataPacket handles incoming encrypted data packets
func (v *VPNHandler) processDataPacket(packetData []byte, addr *net.UDPAddr) error {
	if len(packetData) < 8 { // Minimum header size
		return fmt.Errorf("data packet too small")
	}

	// Find the peer by endpoint
	p, _ := v.peerMap.FindPeerByEndpoint(addr)
	if p == nil {
		return fmt.Errorf("received data packet from unknown peer: %s", addr.String())
	}

	// Decrypt the packet
	p.Mu.RLock()
	peerKey := p.PublicKey
	p.Mu.RUnlock()

	// Skip header (4 bytes magic + 1 byte type + 3 bytes reserved)
	encryptedData := packetData[8:]

	// Decrypt the packet
	decrypted, err := crypto.DecryptPacket(v.cfg.Keys.PrivateKey, peerKey, encryptedData)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Update peer's last seen timestamp
	p.UpdateLastSeen()

	// Write decrypted packet to TUN interface
	if _, err := v.iface.Write(decrypted); err != nil {
		return fmt.Errorf("failed to write to TUN: %w", err)
	}

	return nil
}

// MaintainPeers periodically checks and maintains peer connections
func (v *VPNHandler) MaintainPeers(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("MaintainPeers: started")

	// Clean up stale peers every minute
	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	// Send keepalives every 30 seconds if enabled
	var keepaliveTicker *time.Ticker
	if v.cfg.PersistentKeepalive {
		keepaliveTicker = time.NewTicker(config.HeartbeatInterval * time.Second)
		defer keepaliveTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("MaintainPeers: context cancelled, exiting")
			return

		case <-cleanupTicker.C:
			// Check if context is cancelled before proceeding
			if ctx.Err() != nil {
				return
			}

			// Remove stale peers
			removed := v.peerMap.RemoveStalePeers()
			if len(removed) > 0 {
				log.Printf("Removed %d stale peers", len(removed))
			}

		case <-keepaliveTicker.C:
			// Check if context is cancelled before proceeding
			if ctx.Err() != nil {
				return
			}

			if !v.cfg.PersistentKeepalive {
				continue
			}

			// Send keepalives to all peers
			v.peerMap.ForEach(func(peerID string, p *peer.Peer) {
				p.Mu.RLock()
				lastSeen := p.LastSeen
				endpoint := p.Endpoint
				p.Mu.RUnlock()

				// Check if we need to send a keepalive
				if time.Since(lastSeen) > 20*time.Second && endpoint != nil {
					v.sendKeepalivePacket(endpoint)
				}
			})
		}
	}
}

// sendKeepalivePacket sends a keepalive packet to a peer
func (v *VPNHandler) sendKeepalivePacket(endpoint *net.UDPAddr) {
	// Create keepalive packet
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(PacketMagic))
	binary.Write(buf, binary.BigEndian, uint8(PacketKeepalive))
	buf.Write([]byte{0, 0, 0}) // Reserved bytes
	binary.Write(buf, binary.BigEndian, uint64(time.Now().UnixNano()))
	log.Printf("Keepalive packet bytes: %x", buf.Bytes())

	// Send the keepalive packet
	if _, err := v.conn.WriteToUDP(buf.Bytes(), endpoint); err != nil {
		log.Printf("Failed to send keepalive to %s: %v", endpoint.String(), err)
	}
}

// printPacketInfo prints detailed information about a packet for debugging
func printPacketInfo(packet []byte, label string) {
	if len(packet) < 20 {
		log.Printf("%s: Packet too small to analyse (%d bytes)", label, len(packet))
		return
	}

	version := (packet[0] >> 4) & 0x0F
	log.Printf("%s: IP version: %d", label, version)

	if version == 4 {
		// IPv4 packet
		ihl := packet[0] & 0x0F
		totalLength := binary.BigEndian.Uint16(packet[2:4])
		protocol := packet[9]
		srcIP := net.IP(packet[12:16]).String()
		dstIP := net.IP(packet[16:20]).String()

		log.Printf("%s: IPv4 packet - IHL: %d, Length: %d, Protocol: %d, Src: %s, Dst: %s",
			label, ihl, totalLength, protocol, srcIP, dstIP)

		// If ICMP (protocol 1), print more details
		if protocol == 1 && len(packet) >= int(ihl)*4+8 {
			icmpType := packet[ihl*4]
			icmpCode := packet[ihl*4+1]
			log.Printf("%s: ICMP - Type: %d, Code: %d", label, icmpType, icmpCode)
		}
	} else if version == 6 {
		// IPv6 packet
		payloadLength := binary.BigEndian.Uint16(packet[4:6])
		nextHeader := packet[6]
		srcIP := net.IP(packet[8:24]).String()
		dstIP := net.IP(packet[24:40]).String()

		log.Printf("%s: IPv6 packet - Length: %d, Next Header: %d, Src: %s, Dst: %s",
			label, payloadLength, nextHeader, srcIP, dstIP)
	}
}
