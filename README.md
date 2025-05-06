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
go build -o myvpn .
```

## How to use
### Generate a key pair
```bash
./myvpn -genkey -key /path/to/keyfile
```
### Run as a server
```bash
sudo ./myvpn -mode server -key /path/to/server.key
```
- Starts a server listening on the default port (8080) with the TUN interface configured to use 10.100.0.1
- Key flag is optional - new keys generated if none provided
- Optional flags to modify port and add routes
### Run as a client
```bash
sudo ./myVPN -mode client -server-pubkey [SERVER PUBKEY HEX] -server [SERVER ADDRESS]
```
- Connects to a server at SERVER ADDRESS and sets up the TUN interface with IP 10.100.0.2
- Optional flag to add routes
## Architecture
### Network flow
1. Packets enter the TUN interface 
2. Packets are encrypted with the peer's public key 
3. Encrypted packets are sent over UDP to the appropriate endpoint 
4. Receiver decrypts packets and injects them into its TUN interface
### Security
- All packets are authenticated and encrypted 
- Timestamps are embedded in nonces to prevent replay attacks 
- Peers are authenticated by their public key 
- 30-second window for clock skew tolerance
### Peer authentication
1. Client sends a handshake containing its public key 
2. Server registers the client as a peer
3. Peers that have not communicated for 2 minutes are removed 

