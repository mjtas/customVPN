package config

import (
	"github.com/mjtas/customVPN/internal/crypto"
)

const (
	DefaultPort       = 8080
	DefaultMTU        = 1420 // Reduced to account for encryption overhead
	ReadBufferSize    = 2048
	HeartbeatInterval = 30 // Seconds
)

// Config contains global tunnel configuration
type Config struct {
	Mode                string
	ServerAddr          string
	ListenPort          int
	Keys                crypto.KeyPair
	InterfaceIP         string
	DestinationIP       string
	InterfaceMask       string
	Routes              []string
	PersistentKeepalive bool
	Debug               bool
}

func NewDefaultConfig() *Config {
	return &Config{
		ListenPort:          DefaultPort,
		Routes:              []string{"0.0.0.0/0"},
		PersistentKeepalive: true,
	}
}
