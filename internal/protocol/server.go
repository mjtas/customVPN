package protocol

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/mjtas/customVPN/internal/config"
	"github.com/mjtas/customVPN/internal/peer"
	"github.com/songgao/water"
)

// StartServer initialises the VPN server infrastructure
func StartServer(ctx context.Context, cfg *config.Config, iface *water.Interface) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: cfg.ListenPort,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("Server listening on :%d", cfg.ListenPort)

	// Create peer manager
	peerMap := peer.NewPeerMap()

	var wg sync.WaitGroup
	defer wg.Wait()

	vpnHandler := &VPNHandler{
		cfg:     cfg,
		conn:    conn,
		iface:   iface,
		peerMap: peerMap,
	}

	wg.Add(3)
	go vpnHandler.ReadFromTUN(ctx, &wg)
	go vpnHandler.ReadFromUDP(ctx, &wg)
	go vpnHandler.MaintainPeers(ctx, &wg)

	<-ctx.Done()
	return nil
}
