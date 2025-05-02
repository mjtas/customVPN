package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Mock for TUN interface
type mockTUN struct {
	readChan  chan []byte
	writeChan chan []byte
	closed    bool
	name      string
	mu        sync.Mutex
}

func (m *mockTUN) Read(p []byte) (n int, err error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("device closed")
	}
	m.mu.Unlock()

	data := <-m.readChan
	copy(p, data)
	return len(data), nil
}

func (m *mockTUN) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("device closed")
	}
	m.mu.Unlock()

	copied := make([]byte, len(p))
	copy(copied, p)
	m.writeChan <- copied
	return len(p), nil
}

func (m *mockTUN) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.readChan)
	close(m.writeChan)
	return nil
}

func (m *mockTUN) Name() string {
	return m.name
}

// Mock UDP connection
type mockUDPConn struct {
	readChan  chan udpPacket
	writeChan chan udpPacket
	closed    bool
	mu        sync.Mutex
}

type udpPacket struct {
	data []byte
	addr *net.UDPAddr
}

func (m *mockUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, nil, errors.New("connection closed")
	}
	m.mu.Unlock()

	packet := <-m.readChan
	copy(b, packet.data)
	return len(packet.data), packet.addr, nil
}

func (m *mockUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("connection closed")
	}
	m.mu.Unlock()

	copied := make([]byte, len(b))
	copy(copied, b)
	m.writeChan <- udpPacket{copied, addr}
	return len(b), nil
}

func (m *mockUDPConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.readChan)
	close(m.writeChan)
	return nil
}

func (m *mockUDPConn) SetReadDeadline(t time.Time) error {
	return nil // Mock implementation ignores deadlines
}

// Helper function to create test IP packets
func createIPPacket(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))

	// IP version and header length
	packet[0] = 0x45 // IPv4, 5 32-bit words (20 bytes)

	// Total length
	binary.BigEndian.PutUint16(packet[2:4], uint16(20+len(payload)))

	// Protocol
	packet[9] = protocol

	// Source IP
	copy(packet[12:16], srcIP.To4())

	// Destination IP
	copy(packet[16:20], dstIP.To4())

	// Payload
	copy(packet[20:], payload)

	return packet
}

// Test key generation
func TestGenerateKeyPair(t *testing.T) {
	err := generateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Check that keys are properly initialized
	var zeroKey [32]byte
	if bytes.Equal(globalConfig.PrivateKey[:], zeroKey[:]) {
		t.Error("Private key not generated")
	}
	if bytes.Equal(globalConfig.PublicKey[:], zeroKey[:]) {
		t.Error("Public key not generated")
	}
}

// Test key saving and loading
func TestKeySaveLoad(t *testing.T) {
	// Generate a keypair
	err := generateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Save keys to a temporary file
	tmpFile, err := os.CreateTemp("", "vpntest-*.key")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	origPrivKey := globalConfig.PrivateKey
	origPubKey := globalConfig.PublicKey

	err = saveKeys(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to save keys: %v", err)
	}

	// Reset keys
	globalConfig.PrivateKey = [32]byte{}
	globalConfig.PublicKey = [32]byte{}

	// Load keys
	err = loadKeys(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load keys: %v", err)
	}

	// Verify keys match
	if !bytes.Equal(globalConfig.PrivateKey[:], origPrivKey[:]) {
		t.Error("Loaded private key doesn't match original")
	}
	if !bytes.Equal(globalConfig.PublicKey[:], origPubKey[:]) {
		t.Error("Loaded public key doesn't match original")
	}
}

// Test peer management
func TestPeerManagement(t *testing.T) {
	// Clear peers map
	globalConfig.Peers = make(map[string]*Peer)

	// Create fake peer data
	peerKey := [32]byte{1, 2, 3, 4, 5}
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// Add peer
	globalConfig.mu.Lock()
	globalConfig.Peers[string(peerKey[:])] = &Peer{
		Endpoint:  peerAddr,
		PublicKey: peerKey,
		LastSeen:  time.Now().Add(-1 * time.Minute),
	}
	globalConfig.mu.Unlock()

	// Check if peer exists
	globalConfig.mu.RLock()
	peer, exists := globalConfig.Peers[string(peerKey[:])]
	globalConfig.mu.RUnlock()

	if !exists {
		t.Fatal("Peer should exist after adding")
	}

	if !peer.Endpoint.IP.Equal(peerAddr.IP) || peer.Endpoint.Port != peerAddr.Port {
		t.Error("Peer endpoint doesn't match")
	}

	if !bytes.Equal(peer.PublicKey[:], peerKey[:]) {
		t.Error("Peer public key doesn't match")
	}

	// Test peer update
	newTime := time.Now()
	peer.mu.Lock()
	peer.LastSeen = newTime
	peer.mu.Unlock()

	peer.mu.RLock()
	if !peer.LastSeen.Equal(newTime) {
		t.Error("Peer LastSeen time wasn't updated correctly")
	}
	peer.mu.RUnlock()
}

// Test command-line flag parsing
func TestFlagParsing(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test cases
	testCases := []struct {
		args     []string
		expected struct {
			mode       string
			serverAddr string
			listenPort int
			ifaceIP    string
		}
	}{
		{
			args: []string{"cmd", "-mode", "server", "-port", "12345", "-ip", "10.0.1.1"},
			expected: struct {
				mode       string
				serverAddr string
				listenPort int
				ifaceIP    string
			}{
				mode:       "server",
				serverAddr: "",
				listenPort: 12345,
				ifaceIP:    "10.0.1.1",
			},
		},
		{
			args: []string{"cmd", "-mode", "client", "-server", "example.com:51820", "-ip", "10.0.1.2"},
			expected: struct {
				mode       string
				serverAddr string
				listenPort int
				ifaceIP    string
			}{
				mode:       "client",
				serverAddr: "example.com:51820",
				listenPort: DefaultPort, // Default value
				ifaceIP:    "10.0.1.2",
			},
		},
	}

	for i, tc := range testCases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			// Set up command-line arguments
			os.Args = tc.args

			// Reset flag parsing
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

			// Parse flags
			var mode = flag.String("mode", "server", "Operation mode (server/client)")
			var serverAddr = flag.String("server", "", "Server address (client mode)")
			var listenPort = flag.Int("port", DefaultPort, "UDP port to listen on")
			var ifaceIP = flag.String("ip", "10.0.0.1", "TUN interface IP address")
			flag.Parse()

			// Check results
			if *mode != tc.expected.mode {
				t.Errorf("Case %d: mode expected %s, got %s", i, tc.expected.mode, *mode)
			}
			if *serverAddr != tc.expected.serverAddr {
				t.Errorf("Case %d: serverAddr expected %s, got %s", i, tc.expected.serverAddr, *serverAddr)
			}
			if *listenPort != tc.expected.listenPort {
				t.Errorf("Case %d: listenPort expected %d, got %d", i, tc.expected.listenPort, *listenPort)
			}
			if *ifaceIP != tc.expected.ifaceIP {
				t.Errorf("Case %d: ifaceIP expected %s, got %s", i, tc.expected.ifaceIP, *ifaceIP)
			}
		})
	}
}

// TestEncryptAndDecryptPacket tests the encryption and decryption functions
func TestEncryptAndDecryptPacket(t *testing.T) {
	// Generate key pairs for both sides
	pub1, priv1, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, priv2, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Set up global config for first peer
	globalConfig = &Config{
		Peers: make(map[string]*Peer),
	}
	copy(globalConfig.PrivateKey[:], priv1[:])
	copy(globalConfig.PublicKey[:], pub1[:])

	// Create test packet
	originalPacket := []byte("This is a test packet for encryption and decryption")

	// Encrypt packet
	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pub2[:])

	encrypted, err := encryptPacket(recipientPubKey, originalPacket)
	require.NoError(t, err)
	assert.NotEqual(t, originalPacket, encrypted, "Encrypted data should differ from original")

	// Switch to second peer for decryption
	var oldPrivKey [32]byte
	copy(oldPrivKey[:], globalConfig.PrivateKey[:])
	var oldPubKey [32]byte
	copy(oldPubKey[:], globalConfig.PublicKey[:])

	copy(globalConfig.PrivateKey[:], priv2[:])
	copy(globalConfig.PublicKey[:], pub2[:])

	// Decrypt packet
	var senderPubKey [32]byte
	copy(senderPubKey[:], pub1[:])

	decrypted, err := decryptPacket(senderPubKey, encrypted)
	require.NoError(t, err)

	// Compare original and decrypted
	assert.Equal(t, originalPacket, decrypted, "Decrypted packet should match original")

	// Restore original keys
	copy(globalConfig.PrivateKey[:], oldPrivKey[:])
	copy(globalConfig.PublicKey[:], oldPubKey[:])
}

// TestDecryptInvalidPacket tests decryption of invalid packets
func TestDecryptInvalidPacket(t *testing.T) {
	// Generate key pairs
	pub1, priv1, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, priv2, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Set up global config
	globalConfig = &Config{
		Peers: make(map[string]*Peer),
	}
	copy(globalConfig.PrivateKey[:], priv1[:])
	copy(globalConfig.PublicKey[:], pub1[:])

	// Test case 1: Packet too short
	var senderPubKey [32]byte
	copy(senderPubKey[:], pub2[:])

	_, err = decryptPacket(senderPubKey, []byte("short"))
	assert.Error(t, err, "Should reject packets shorter than nonce size")

	// Test case 2: Invalid nonce/ciphertext
	invalidPacket := make([]byte, 100)
	rand.Read(invalidPacket)

	_, err = decryptPacket(senderPubKey, invalidPacket)
	assert.Error(t, err, "Should reject packets with invalid encryption")

	// Test case 3: Tampered packet
	originalPacket := []byte("This is a test packet for encryption and decryption")

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pub2[:])

	encrypted, err := encryptPacket(recipientPubKey, originalPacket)
	require.NoError(t, err)

	// Tamper with encrypted data
	encrypted[30] ^= 0x01

	// Switch to second peer for decryption
	copy(globalConfig.PrivateKey[:], priv2[:])
	copy(globalConfig.PublicKey[:], pub2[:])

	_, err = decryptPacket(senderPubKey, encrypted)
	assert.Error(t, err, "Should reject tampered packets")
}

// TestReplayAttackPrevention tests that old packets are rejected
func TestReplayAttackPrevention(t *testing.T) {
	// Generate key pairs
	pub1, priv1, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, priv2, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Set up global config for first peer
	globalConfig = &Config{
		Peers: make(map[string]*Peer),
	}
	copy(globalConfig.PrivateKey[:], priv1[:])
	copy(globalConfig.PublicKey[:], pub1[:])

	// Create test packet
	originalPacket := []byte("This is a test packet for replay attack prevention")

	// Encrypt packet with timestamp from 60 seconds ago
	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pub2[:])

	// Generate packet
	nonce := make([]byte, 24)
	rand.Read(nonce[:16])

	// Use timestamp from 60 seconds ago
	pastTime := time.Now().Add(-60 * time.Second).UnixNano()
	binary.BigEndian.PutUint64(nonce[16:], uint64(pastTime))

	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Manual encryption to set old timestamp
	encrypted := box.Seal(nonce, originalPacket, &nonceArray, &recipientPubKey, &globalConfig.PrivateKey)

	// Switch to second peer for decryption
	copy(globalConfig.PrivateKey[:], priv2[:])
	copy(globalConfig.PublicKey[:], pub2[:])

	// Decrypt packet
	var senderPubKey [32]byte
	copy(senderPubKey[:], pub1[:])

	_, err = decryptPacket(senderPubKey, encrypted)
	assert.Error(t, err, "Should reject packets with old timestamps")
	assert.Contains(t, err.Error(), "replay attack", "Error should mention replay attack")
}
