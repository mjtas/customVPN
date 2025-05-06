package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// KeyPair represents a Curve25519 key pair
type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// GenerateKeyPair creates a new Curve25519 key pair
func GenerateKeyPair() (KeyPair, error) {
	var keyPair KeyPair
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return keyPair, fmt.Errorf("key generation failed: %w", err)
	}

	copy(keyPair.PublicKey[:], publicKey[:])
	copy(keyPair.PrivateKey[:], privateKey[:])

	return keyPair, nil
}

// LoadKeysFromFile reads a 64-byte key file containing a Curve25519 key pair
func LoadKeysFromFile(keyFile string) (KeyPair, error) {
	var keyPair KeyPair
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return keyPair, fmt.Errorf("key read error: %w", err)
	}

	if len(data) != 64 {
		return keyPair, fmt.Errorf("invalid key file format")
	}

	copy(keyPair.PrivateKey[:], data[:32])
	copy(keyPair.PublicKey[:], data[32:])

	return keyPair, nil
}

// SaveKeysToFile persists the X25519 key pair to disk in raw binary format
func SaveKeysToFile(keyFile string, keys KeyPair) error {
	data := make([]byte, 64)
	copy(data[:32], keys.PrivateKey[:])
	copy(data[32:], keys.PublicKey[:])

	return os.WriteFile(keyFile, data, 0600)
}

// ParsePublicKeyHex converts a hex-encoded public key string to a byte array
func ParsePublicKeyHex(keyHex string) ([32]byte, error) {
	var key [32]byte
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return key, fmt.Errorf("invalid public key format: %w", err)
	}

	if len(keyBytes) != 32 {
		return key, fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(keyBytes))
	}

	copy(key[:], keyBytes)
	return key, nil
}

// EncryptPacket implements authenticated encryption using NaCl box
func EncryptPacket(privateKey [32]byte, recipientKey [32]byte, plaintext []byte) ([]byte, error) {
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
	encrypted := box.Seal(nonce, plaintext, &nonceArray, &recipientKey, &privateKey)
	return encrypted, nil
}

// DecryptPacket verifies and decrypts a message using NaCl box
func DecryptPacket(privateKey [32]byte, senderKey [32]byte, ciphertext []byte) ([]byte, error) {
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

	decrypted, ok := box.Open(nil, ciphertext[24:], &nonceArray, &senderKey, &privateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}
