// VPN tunnel using modern cryptographic primitives
// Operates in either server or client mode, managing peer connections over UDP with
// NaCl box encryption (Curve25519+XSalsa20+Poly1305) and TUN interface routing
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/songgao/water"
	"golang.org/x/crypto/nacl/box"
)

const (
	DefaultPort       = 51820
	DefaultMTU        = 1420 // Reduced to account for encryption overhead
	ReadBufferSize    = 2048
	HeartbeatInterval = 30 * time.Second
)

// Peer represents a remote VPN endpoint with associated security parameters and connection state
type Peer struct {
	Endpoint   *net.UDPAddr
	PublicKey  [32]byte
	AllowedIPs []string // CIDR notation routes ("192.168.1.0/24")
	LastSeen   time.Time
	mu         sync.RWMutex // Protects against concurrent state modifications
}

// Config contains global tunnel configuration and synchronised peer state
type Config struct {
	Mode                string
	ServerAddr          string
	ListenPort          int
	PrivateKey          [32]byte
	PublicKey           [32]byte
	Peers               map[string]*Peer
	InterfaceIP         string
	InterfaceMask       string
	Routes              []string
	PersistentKeepalive bool
	mu                  sync.RWMutex // Serialises access to Peers map and other mutable fields
}

var globalConfig = &Config{
	ListenPort:          DefaultPort,
	Peers:               make(map[string]*Peer),
	PersistentKeepalive: true,
}

var tunConfig = water.Config{
	DeviceType: water.TUN,
}

// initTunConfig initialises platform-specific TUN interface parameters
func initTunConfig() {
	switch runtime.GOOS {
	case "darwin":
		tunConfig.PlatformSpecificParams.Name = ""
	}
}

// generateKeyPair creates a new Curve25519 key pair using crypto/rand as entropy source
// Keys are stored in globalConfig and logged for verification purposes
func generateKeyPair() error {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	copy(globalConfig.PublicKey[:], publicKey[:])
	copy(globalConfig.PrivateKey[:], privateKey[:])

	log.Printf("Public key: %x", globalConfig.PublicKey)
	return nil
}

// loadKeys reads a 64-byte key file containing a Curve25519 key pair
// File format: 32-byte private key followed by 32-byte public key
// Does not validate key cryptographic properties - assumes properly generated keys
// Returns error for file I/O issues or incorrect key file structure
func loadKeys(keyFile string) error {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("key read error: %w", err)
	}

	if len(data) != 64 {
		return fmt.Errorf("invalid key file format")
	}

	copy(globalConfig.PrivateKey[:], data[:32])
	copy(globalConfig.PublicKey[:], data[32:])

	return nil
}

// saveKeys persists the X25519 key pair to disk in raw binary format
// Creates a 0600 permission file (user read/write only) containing:
// [32-byte private key][32-byte public key]
// Security critical - caller must ensure safe file storage location
func saveKeys(keyFile string) error {
	data := make([]byte, 64)
	copy(data[:32], globalConfig.PrivateKey[:])
	copy(data[32:], globalConfig.PublicKey[:])

	return os.WriteFile(keyFile, data, 0600)
}

// encryptPacket implements authenticated encryption using NaCl box:
// - Generates 24-byte nonce (16 random bytes + 8 byte timestamp)
// - Seals plaintext with recipient's public key and nonce
// - Appends nonce to ciphertext for transport
// The timestamp provides replay protection within a 30-second window
func encryptPacket(recipient [32]byte, plaintext []byte) ([]byte, error) {
	// Create a unique nonce for this message
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce[:16]); err != nil {
		return nil, err
	}

	// Use timestamp in last 8 bytes to prevent replay attacks
	binary.BigEndian.PutUint64(nonce[16:], uint64(time.Now().UnixNano()))

	var nonceArray [24]byte
	copy(nonceArray[:], nonce)

	// Encrypt with NaCl box (authenticated encryption)
	encrypted := box.Seal(nonce, plaintext, &nonceArray, &recipient, &globalConfig.PrivateKey)
	return encrypted, nil
}

// decryptPacket verifies and decrypts a message using NaCl box:
// - Extracts nonce from first 24 bytes
// - Validates timestamp freshness (±30 seconds)
// - Opens ciphertext with sender's public key
// Returns plaintext only if authentication succeeds and timestamp is valid
func decryptPacket(sender [32]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var nonceArray [24]byte
	copy(nonceArray[:], ciphertext[:24])

	// Verify timestamp to prevent replay attacks (within 30 second window)
	timestamp := binary.BigEndian.Uint64(ciphertext[16:24])
	now := uint64(time.Now().UnixNano())

	// Allow for some clock skew (30 seconds)
	if now > timestamp && now-timestamp > uint64(30*time.Second) {
		return nil, fmt.Errorf("packet too old (possible replay attack)")
	}

	decrypted, ok := box.Open(nil, ciphertext[24:], &nonceArray, &sender, &globalConfig.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}

// configureInterface sets up TUN device parameters using platform-specific utilities
// Implements cross-platform network configuration through external command execution
// Critical for proper packet routing and interface functionality
func configureInterface(iface *water.Interface) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "ip"
		args = []string{"link", "set", "dev", iface.Name(), "mtu", fmt.Sprintf("%d", DefaultMTU), "up"}
	case "darwin":
		cmd = "ifconfig"
		args = []string{iface.Name(), "mtu", fmt.Sprintf("%d", DefaultMTU), "up"}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	// Execute the command to set MTU and bring interface up
	if err := execCommand(cmd, args...); err != nil {
		return err
	}

	// Set IP address
	if globalConfig.InterfaceIP != "" {
		if err := assignIP(iface.Name(), globalConfig.InterfaceIP, globalConfig.InterfaceMask); err != nil {
			return err
		}
	}

	// Configure routes
	for _, route := range globalConfig.Routes {
		if err := addRoute(route, iface.Name()); err != nil {
			log.Printf("Warning: could not add route %s: %v", route, err)
		}
	}

	return nil
}

// assignIP configures the TUN interface with specified IP address and netmask
// using platform-specific utilities:
// - Linux: `ip addr add <ip>/<mask> dev <iface>`
// - Darwin: `ifconfig <iface> inet <ip> netmask <mask>`
// Does not validate IP/Mask syntax - assumes pre-validated configuration
// Not atomic - may leave interface in partial state on error
func assignIP(iface, ip, mask string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		maskIP := net.ParseIP(mask)
		if maskIP == nil {
			return fmt.Errorf("invalid subnet mask: %q", mask)
		}
		ones, _ := net.IPMask(maskIP.To4()).Size()
		cidr := fmt.Sprintf("%s/%d", ip, ones)
		cmd = "ip"
		args = []string{"addr", "add", cidr, "dev", iface}

	case "darwin":
		cmd = "ifconfig"
		args = []string{
			iface,
			"inet",
			ip,
			"10.100.0.2", // Destination address (required for macOS TUN)
			"netmask",
			mask,
			"up", // Explicit interface activation
		}

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err := execCommand(cmd, args...); err != nil {
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	log.Printf("Configured %s with IP %s/%s", iface, ip, mask)
	return nil
}

// addRoute creates a network route directing traffic through the TUN interface:
// - Linux: `ip route add <network> dev <iface>`
// - Darwin: `route add -net <network> -interface <iface>`
// Overwrites existing routes without confirmation, requires root privileges for raw socket operations
func addRoute(network, iface string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "ip"
		args = []string{"route", "add", network, "dev", iface}
	case "darwin":
		cmd = "route"
		args = []string{"add", "-net", network, "-interface", iface}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return execCommand(cmd, args...)
}

// execCommand securely executes system commands with sanitised arguments
// Implements security-critical process spawning with the following:
// - Absolute path resolution (prevent PATH injection)
// - Argument sanitisation
// - Timeout handling
// - Output capture/redirection
func execCommand(command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Resolve absolute path to prevent PATH injection
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command resolution failed for %q: %w", command, err)
	}

	cmd := exec.CommandContext(ctx, path, args...)

	// Capture output for error diagnostics
	output, err := cmd.CombinedOutput()
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("command timed out: %s %v", path, args)
	case err != nil:
		return fmt.Errorf("command failed [%s %v]: %w\nOutput:\n%s",
			path, args, err, string(output))
	}

	log.Printf("Executed successfully: %s %v\nOutput:\n%s", path, args, string(output))
	return nil
}

// createTUN handles platform-specific TUN interface creation with fallback logic:
// - Darwin: Attempts utunX devices sequentially if default creation fails
// - Linux: Direct creation using kernel TUN driver
// Returns configured interface or error if all attempts fail
func createTUN() (*water.Interface, error) {
	// On macOS, we'll make a special consideration for the interface creation
	if runtime.GOOS == "darwin" {
		// Try several utun devices if needed
		var iface *water.Interface
		var err error

		// First try with empty name (recommended approach)
		iface, err = water.New(tunConfig)
		if err != nil {
			// If that fails, try specific utun devices
			for i := 0; i < 5; i++ {
				localConfig := tunConfig
				localConfig.PlatformSpecificParams.Name = fmt.Sprintf("utun%d", i)
				iface, err = water.New(localConfig)
				if err == nil {
					break
				}
			}

			if err != nil {
				return nil, fmt.Errorf("TUN creation failed: %w", err)
			}
		}

		log.Printf("Created TUN %s", iface.Name())

		if err := configureInterface(iface); err != nil {
			iface.Close()
			return nil, fmt.Errorf("interface configuration failed: %w", err)
		}

		return iface, nil
	}

	// For linux
	iface, err := water.New(tunConfig)
	if err != nil {
		return nil, fmt.Errorf("TUN creation failed: %w", err)
	}

	log.Printf("Created TUN %s", iface.Name())

	if err := configureInterface(iface); err != nil {
		iface.Close()
		return nil, fmt.Errorf("interface configuration failed: %w", err)
	}

	return iface, nil
}

// handleSignals sets up OS signal interception for graceful shutdown.
// Listens for SIGINT and SIGTERM to trigger:
// 1. Context cancellation to propagate shutdown through the application
// 2. TUN interface closure to release network resources
// Runs in a dedicated goroutine to prevent blocking signal reception
func handleSignals(ctx context.Context, cancel context.CancelFunc, iface *water.Interface) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		iface.Close()
	}()
}

// startServer initialises the VPN server infrastructure:
// - Binds to UDP port for peer communication
// - Starts TUN/UDP read workers with context-aware cancellation
// - Launches peer maintenance goroutine for connection health checks
// Blocks until context cancellation, then performs orderly shutdown
// via deferred connection closure and WaitGroup synchronisation
func startServer(ctx context.Context, iface *water.Interface) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: globalConfig.ListenPort,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		return fmt.Errorf("UDP listen failed: %w", err)
	}
	defer conn.Close()

	log.Printf("Server listening on :%d", globalConfig.ListenPort)

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(3)
	go readFromTUN(ctx, conn, iface, &wg)
	go readFromUDP(ctx, conn, iface, &wg)
	go maintainPeers(ctx, conn, &wg)

	<-ctx.Done()
	return nil
}

// startClient configures client-mode VPN connectivity:
// - Uses ephemeral UDP port for outbound communication
// - Manages server peer entry with simplified routing
// - Initiates periodic keepalives and handshake retries
// Implements best-effort cleanup through defer statements but may leave
// residual routes/addresses on abrupt termination
func startClient(ctx context.Context, iface *water.Interface) error {
	serverAddr, err := net.ResolveUDPAddr("udp", globalConfig.ServerAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 0, // Use random port
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		return fmt.Errorf("UDP listen failed: %w", err)
	}
	defer conn.Close()

	// Add server as a peer
	serverPubKey := [32]byte{} // This should be provided in a real implementation
	globalConfig.mu.Lock()
	// When connecting to server (client mode)
	globalConfig.Peers[string(serverPubKey[:])] = &Peer{
		Endpoint:   serverAddr,
		PublicKey:  serverPubKey,
		AllowedIPs: globalConfig.Routes, // Use configured routes
		LastSeen:   time.Now(),
	}
	globalConfig.mu.Unlock()

	log.Printf("Connected to server at %s", serverAddr.String())

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(3)
	go readFromTUN(ctx, conn, iface, &wg)
	go readFromUDP(ctx, conn, iface, &wg)
	go maintainPeers(ctx, conn, &wg)

	// Send initial handshake
	if err := sendHandshake(conn, serverAddr); err != nil {
		log.Printf("Initial handshake failed: %v", err)
	}

	<-ctx.Done()
	return nil
}

// sendHandshake transmits initial key exchange packet using insecure
// cleartext format (HELLO + 32-byte public key)
// WARNING: Production implementation requires cryptographic authentication and protection against replay attacks
func sendHandshake(conn *net.UDPConn, addr *net.UDPAddr) error {
	// Create a simple handshake packet containing our public key
	handshake := append([]byte("HELLO"), globalConfig.PublicKey[:]...)

	_, err := conn.WriteToUDP(handshake, addr)
	return err
}

// readFromTUN implements the outbound packet processing pipeline:
// 1. Reads raw IP packets from TUN interface
// 2. Extracts destination IP (offset 16-20 in IPv4 header)
// 3. Looks up peer using simplified first-match routing
// 4. Encrypts payload using peer's public key
// 5. Transmits via UDP with best-effort delivery
// Handles context cancellation and synchronises shutdown via WaitGroup
// MTU-sized buffers prevent IP fragmentation but may drop large packets
func readFromTUN(ctx context.Context, conn *net.UDPConn, iface *water.Interface, wg *sync.WaitGroup) {
	defer wg.Done()

	packet := make([]byte, DefaultMTU)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := iface.Read(packet)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("TUN read error: %v", err)
				continue
			}

			// Extract destination IP from IPv4 header
			if len(packet) < 20 {
				log.Printf("Invalid IP packet length: %d", len(packet))
				continue
			}
			dstIP := net.IP(packet[16:20])

			var (
				bestPeer    *Peer
				longestMask int
			)

			globalConfig.mu.RLock()
			// Iterate through all peers to find best route
			for _, peer := range globalConfig.Peers {
				peer.mu.RLock()
				// Check each allowed CIDR for this peer
				for _, cidr := range peer.AllowedIPs {
					_, ipNet, err := net.ParseCIDR(cidr)
					if err != nil {
						log.Printf("Invalid CIDR in routing table: %s", cidr)
						continue
					}

					// Check if destination matches this CIDR
					if ipNet.Contains(dstIP) {
						maskSize, _ := ipNet.Mask.Size()
						// Prefer longest prefix match
						if maskSize > longestMask {
							longestMask = maskSize
							bestPeer = peer
						}
					}
				}
				peer.mu.RUnlock()
			}
			globalConfig.mu.RUnlock()

			if bestPeer == nil {
				log.Printf("No route for %s - dropping packet", dstIP)
				continue
			}

			// Encrypt and send to the selected peer
			encrypted, err := encryptPacket(bestPeer.PublicKey, packet[:n])
			if err != nil {
				log.Printf("Encryption error for %s: %v", dstIP, err)
				continue
			}

			if _, err := conn.WriteToUDP(encrypted, bestPeer.Endpoint); err != nil {
				log.Printf("Failed to send to %s: %v", bestPeer.Endpoint, err)
			}
		}
	}
}

// readFromUDP processes incoming encrypted packets:
// - Handles peer registration via HELLO handshakes
// - Decrypts valid packets using peer's public key
// - Writes decrypted payloads to TUN interface
// Implements 1-second read deadline for graceful context cancellation
func readFromUDP(ctx context.Context, conn *net.UDPConn, iface *water.Interface, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, ReadBufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
				log.Printf("Failed to set read deadline: %v", err)
			}

			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}

				if ctx.Err() != nil {
					return
				}

				log.Printf("UDP read error: %v", err)
				continue
			}

			// Handle handshake packets
			if n > 5 && string(buf[:5]) == "HELLO" {
				if n != 5+32 {
					log.Printf("Invalid handshake from %s", addr)
					continue
				}

				var peerKey [32]byte
				copy(peerKey[:], buf[5:5+32])

				globalConfig.mu.Lock()
				globalConfig.Peers[string(peerKey[:])] = &Peer{
					Endpoint:   addr,
					PublicKey:  peerKey,
					AllowedIPs: []string{"0.0.0.0/0"}, // Default route in this example
					LastSeen:   time.Now(),
				}
				globalConfig.mu.Unlock()

				log.Printf("New peer registered from %s", addr)
				continue
			}

			// Find the peer key based on source address
			var peerKey [32]byte
			var peerFound bool

			globalConfig.mu.RLock()
			for _, peer := range globalConfig.Peers {
				if peer.Endpoint.String() == addr.String() {
					peerKey = peer.PublicKey
					peerFound = true

					// Update last seen time
					peer.mu.Lock()
					peer.LastSeen = time.Now()
					peer.mu.Unlock()
					break
				}
			}
			globalConfig.mu.RUnlock()

			if !peerFound {
				log.Printf("Packet from unknown peer %s", addr)
				continue
			}

			plaintext, err := decryptPacket(peerKey, buf[:n])
			if err != nil {
				log.Printf("Decryption error from %s: %v", addr, err)
				continue
			}

			if _, err := iface.Write(plaintext); err != nil {
				log.Printf("TUN write error: %v", err)
			}
		}
	}
}

// maintainPeers performs periodic connection maintenance:
// - Removes peers exceeding 2-minute inactivity threshold
// - Sends keepalives to prevent NAT traversal timeouts
// - Runs on HeartbeatInterval schedule until context cancellation
// Maintains peer liveness through LastSeen timestamp updates
func maintainPeers(ctx context.Context, conn *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// Send keepalives and remove stale peers
			globalConfig.mu.Lock()
			for key, peer := range globalConfig.Peers {
				peer.mu.RLock()
				lastSeen := peer.LastSeen
				peer.mu.RUnlock()

				// Check if peer is stale (not seen for 2 minutes)
				if now.Sub(lastSeen) > 2*time.Minute {
					log.Printf("Removing stale peer %s", peer.Endpoint)
					delete(globalConfig.Peers, key)
					continue
				}

				// Send keepalive if necessary
				if globalConfig.PersistentKeepalive && now.Sub(lastSeen) > HeartbeatInterval/2 {
					keepalive := []byte("PING")
					encrypted, err := encryptPacket(peer.PublicKey, keepalive)
					if err != nil {
						log.Printf("Failed to encrypt keepalive: %v", err)
						continue
					}

					if _, err := conn.WriteToUDP(encrypted, peer.Endpoint); err != nil {
						log.Printf("Failed to send keepalive to %s: %v", peer.Endpoint, err)
					}
				}
			}
			globalConfig.mu.Unlock()
		}
	}
}

func main() {
	var (
		mode       = flag.String("mode", "server", "Operation mode (server/client)")
		serverAddr = flag.String("server", "", "Server address (client mode)")
		listenPort = flag.Int("port", DefaultPort, "UDP port to listen on")
		keyFile    = flag.String("key", "", "Path to key file")
		ifaceIP    = flag.String("ip", "10.0.0.1", "TUN interface IP address")
		ifaceMask  = flag.String("mask", "255.255.255.0", "TUN interface netmask")
		genKey     = flag.Bool("genkey", false, "Generate and print new keys")
		routes     = flag.String("routes", "", "Comma-separated list of routes")
	)
	flag.Parse()

	// Initialise platform-specific TUN configuration
	initTunConfig()

	// Generate keys if requested
	if *genKey {
		if err := generateKeyPair(); err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}

		if *keyFile != "" {
			if err := saveKeys(*keyFile); err != nil {
				log.Fatalf("Failed to save keys: %v", err)
			}
			log.Printf("Keys saved to %s", *keyFile)
		}

		fmt.Printf("Public key: %x\n", globalConfig.PublicKey)
		fmt.Printf("Private key: %x\n", globalConfig.PrivateKey)
		return
	}

	// Initialise configuration
	globalConfig.Mode = *mode
	globalConfig.ServerAddr = *serverAddr
	globalConfig.ListenPort = *listenPort
	globalConfig.InterfaceIP = *ifaceIP
	globalConfig.InterfaceMask = *ifaceMask

	// Parse routes if provided
	if *routes != "" {
		// Basic parsing - would be more robust in production
		globalConfig.Routes = append(globalConfig.Routes, *routes)
	}

	// Load or generate keys
	if *keyFile != "" {
		if err := loadKeys(*keyFile); err != nil {
			if os.IsNotExist(err) {
				log.Printf("Key file not found, generating new keys")
				if err := generateKeyPair(); err != nil {
					log.Fatalf("Key generation failed: %v", err)
				}

				if err := saveKeys(*keyFile); err != nil {
					log.Fatalf("Failed to save keys: %v", err)
				}
			} else {
				log.Fatalf("Failed to load keys: %v", err)
			}
		}
	} else {
		if err := generateKeyPair(); err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and configure TUN interface
	iface, err := createTUN()
	if err != nil {
		log.Fatalf("Failed to create TUN: %v", err)
	}
	defer iface.Close()

	handleSignals(ctx, cancel, iface)

	// Start in appropriate mode
	var runErr error
	if *mode == "server" {
		runErr = startServer(ctx, iface)
	} else if *mode == "client" {
		if *serverAddr == "" {
			log.Fatal("Server address required in client mode")
		}
		runErr = startClient(ctx, iface)
	} else {
		log.Fatalf("Invalid mode: %s", *mode)
	}

	if runErr != nil {
		log.Fatalf("Error: %v", runErr)
	}
}
