package protocol

import (
	"context"
	"fmt"
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

// StartClient configures client-mode VPN connectivity
func StartClient(ctx context.Context, cfg *config.Config, iface *water.Interface, serverPubKeyHex string) error {
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	log.Printf("Resolved server address: %s", serverAddr.String())

	serverPubKey, err := crypto.ParsePublicKeyHex(serverPubKeyHex)
	if err != nil {
		return err
	}

	log.Printf("Using server public key: %s", serverPubKeyHex)

	// Listen on UDP (with retries if port binding fails)
	var conn *net.UDPConn
	for i := 0; i < 5; i++ {
		conn, err = net.ListenUDP("udp", &net.UDPAddr{
			Port: 0, // Use random port
			IP:   net.ParseIP("0.0.0.0"),
		})
		if err == nil {
			break
		}
		log.Printf("UDP bind attempt %d failed: %v", i+1, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("UDP listen failed after multiple attempts: %w", err)
	}
	defer conn.Close()

	log.Printf("Client listening on %s", conn.LocalAddr().String())

	// Configure routes for server peer
	routes := []string{"10.100.0.1/32", "10.100.0.2/32"} // Route to server IP
	if len(cfg.Routes) > 0 {
		for _, route := range cfg.Routes {
			if !strings.Contains(route, "/") {
				route = route + "/32"
			}
			routes = append(routes, route)
		}
	}

	// Create peer manager
	peerMap := peer.NewPeerMap()

	// Add server as peer
	serverPeer := &peer.Peer{
		Endpoint:   serverAddr,
		PublicKey:  serverPubKey,
		AllowedIPs: routes,
		LastSeen:   time.Now().Add(-1 * time.Minute), // Set to past time to force handshake
	}
	peerMap.AddOrUpdatePeer(string(serverPubKey[:]), serverPeer)

	log.Printf("Registered server at %s as peer", serverAddr.String())

	vpnHandler := &VPNHandler{
		cfg:     cfg,
		conn:    conn,
		iface:   iface,
		peerMap: peerMap,
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Start worker goroutines
	go vpnHandler.ReadFromTUN(ctx, &wg)
	go vpnHandler.ReadFromUDP(ctx, &wg)
	go vpnHandler.MaintainPeers(ctx, &wg)

	// Perform initial handshake
	if err := performInitialHandshake(ctx, vpnHandler, serverPubKey); err != nil {
		log.Printf("Warning: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()
	wg.Wait()
	return nil
}
