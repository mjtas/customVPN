package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mjtas/customVPN/internal/config"
	"github.com/mjtas/customVPN/internal/crypto"
	"github.com/mjtas/customVPN/internal/network"
	"github.com/mjtas/customVPN/internal/protocol"
)

func main() {
	var (
		mode            = flag.String("mode", "server", "Operation mode (server/client)")
		serverAddr      = flag.String("server", "", "Server address (client mode)")
		listenPort      = flag.Int("port", config.DefaultPort, "UDP port to listen on")
		keyFile         = flag.String("key", "", "Path to key file")
		ifaceIP         = flag.String("ip", "10.100.0.1", "TUN interface IP address")
		ifaceMask       = flag.String("mask", "255.255.255.0", "TUN interface netmask")
		genKey          = flag.Bool("genkey", false, "Generate and print new keys")
		routes          = flag.String("routes", "", "Comma-separated list of routes")
		serverPubKeyHex = flag.String("server-pubkey", "", "Server public key in hexadecimal format")
		debug           = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	// Generate keys if requested
	if *genKey {
		keys, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}

		if *keyFile != "" {
			if err := crypto.SaveKeysToFile(*keyFile, keys); err != nil {
				log.Fatalf("Failed to save keys: %v", err)
			}
			log.Printf("Keys saved to %s", *keyFile)
		}

		fmt.Printf("Public key: %x\n", keys.PublicKey)
		fmt.Printf("Private key: %x\n", keys.PrivateKey)
		return
	}

	// Initialise configuration
	cfg := &config.Config{
		Mode:                *mode,
		ServerAddr:          *serverAddr,
		ListenPort:          *listenPort,
		InterfaceIP:         *ifaceIP,
		InterfaceMask:       *ifaceMask,
		PersistentKeepalive: true,
		Debug:               *debug,
	}

	// Set destination IP based on mode
	if *mode == "server" {
		cfg.DestinationIP = "10.100.0.2"
	} else {
		cfg.DestinationIP = "10.100.0.1"
		cfg.InterfaceIP = "10.100.0.2"
	}

	// Parse routes if provided
	if *routes != "" {
		cfg.Routes = append(cfg.Routes, *routes)
	}

	// Load or generate keys
	var keys crypto.KeyPair
	var err error

	if *keyFile != "" {
		keys, err = crypto.LoadKeysFromFile(*keyFile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("Key file not found, generating new keys")
				keys, err = crypto.GenerateKeyPair()
				if err != nil {
					log.Fatalf("Key generation failed: %v", err)
				}

				if err := crypto.SaveKeysToFile(*keyFile, keys); err != nil {
					log.Fatalf("Failed to save keys: %v", err)
				}
			} else {
				log.Fatalf("Failed to load keys: %v", err)
			}
		}
	} else {
		keys, err = crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Key generation failed: %v", err)
		}
		fmt.Printf("Public key: %x\n", keys.PublicKey)
	}

	// Set keys in config
	cfg.Keys = keys

	// Create root context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and configure TUN interface
	iface, err := network.CreateTUN(cfg)
	if err != nil {
		log.Fatalf("Failed to create TUN: %v", err)
	}
	defer iface.Close()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel() // Cancel the context to signal all goroutines

		// Give goroutines time to clean up
		time.Sleep(500 * time.Millisecond)

		// Force exit if still running after a timeout
		log.Println("Forcing shutdown...")
		os.Exit(0)
	}()

	// Start in appropriate mode
	var runErr error
	if cfg.Mode == "server" {
		log.Println("Starting server...")
		runErr = protocol.StartServer(ctx, cfg, iface)
	} else if cfg.Mode == "client" {
		if cfg.ServerAddr == "" {
			log.Fatal("Server address required in client mode")
		}
		if *serverPubKeyHex == "" {
			log.Fatal("Server public key required in client mode (-server-pubkey)")
		}
		log.Println("Starting client...")
		// Pass the server public key to the client
		runErr = protocol.StartClient(ctx, cfg, iface, *serverPubKeyHex)
	} else {
		log.Fatalf("Invalid mode: %s", cfg.Mode)
	}

	if runErr != nil {
		log.Fatalf("Error: %v", runErr)
	}
}
