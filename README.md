# CustomVPN
A lightweight, encrypted VPN tunnel implementation in Go that provides secure communication over UDP with ChaCha20-Poly1305 and NaCl's Box encryption.

## Features
- Uses X25519, XSalsa20, and Poly1305 for authenticated encryption 
- Works on Linux and macOS (Windows not supported)
- Client-server model with straightforward setup
- Low-overhead UDP transport for efficiency
- Automatic peer tracking and timeout handling
- Supports connection maintenance with keepalives
- Easy key generation and storage
- Automatic TUN interface setup
- Can route specific subnets through the VPN

## Requirements
- Go 1.16 or higher
- Root privileges (required for creating tunnel interfaces)

## Installation
```bash  
# Install dependencies  
go get github.com/songgao/water  
go get golang.org/x/crypto/chacha20poly1305  
go get golang.org/x/crypto/nacl/box  
# Build the binary
go build -o simplevpn .
```