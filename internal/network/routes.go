package network

import (
	"fmt"
	"log"
	"net"
	"runtime"
)

// SetInterfaceMTU sets the MTU for a network interface
func SetInterfaceMTU(iface string, mtu int) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "ip"
		args = []string{"link", "set", "dev", iface, "mtu", fmt.Sprintf("%d", mtu), "up"}
	case "darwin":
		cmd = "ifconfig"
		args = []string{iface, "mtu", fmt.Sprintf("%d", mtu), "up"}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return ExecCommand(cmd, args...)
}

// AssignIP configures the TUN interface with specified IP address and netmask
func AssignIP(iface, ip, destIP, mask string) error {
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
			destIP,
			"netmask",
			mask,
			"up",
		}

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	if err := ExecCommand(cmd, args...); err != nil {
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	log.Printf("Configured %s with IP %s/%s", iface, ip, mask)
	return nil
}

// AddRoute creates a network route directing traffic through the TUN interface
func AddRoute(network, iface string) error {
	log.Printf("Adding route %s via %s", network, iface)

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

	return ExecCommand(cmd, args...)
}
