package network

import (
	"fmt"
	"log"
	"runtime"

	"github.com/mjtas/customVPN/internal/config"
	"github.com/songgao/water"
)

// CreateTUN handles platform-specific TUN interface creation
func CreateTUN(cfg *config.Config) (*water.Interface, error) {
	tunConfig := water.Config{
		DeviceType: water.TUN,
	}

	// Platform-specific configuration
	switch runtime.GOOS {
	case "darwin":
		tunConfig.PlatformSpecificParams.Name = ""
	}

	var iface *water.Interface
	var err error

	// On macOS, special consideration for the interface creation
	if runtime.GOOS == "darwin" {
		// Try several utun devices if needed
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
	} else {
		// For linux and other platforms
		iface, err = water.New(tunConfig)
		if err != nil {
			return nil, fmt.Errorf("TUN creation failed: %w", err)
		}
	}

	log.Printf("Created TUN %s", iface.Name())

	// Configure the interface
	if err := ConfigureInterface(iface, cfg); err != nil {
		iface.Close()
		return nil, fmt.Errorf("interface configuration failed: %w", err)
	}

	return iface, nil
}

// ConfigureInterface sets up TUN device parameters using platform-specific utilities
func ConfigureInterface(iface *water.Interface, cfg *config.Config) error {
	// Set MTU and bring interface up
	if err := SetInterfaceMTU(iface.Name(), config.DefaultMTU); err != nil {
		return err
	}

	// Set IP address
	if cfg.InterfaceIP != "" {
		if err := AssignIP(iface.Name(), cfg.InterfaceIP, cfg.DestinationIP, cfg.InterfaceMask); err != nil {
			return err
		}
	}

	// Configure routes
	for _, route := range cfg.Routes {
		if err := AddRoute(route, iface.Name()); err != nil {
			log.Printf("Warning: could not add route %s: %v", route, err)
		}
	}

	return nil
}
