package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const encodedKeyLength = KeySize * 2

// LoadKey reads exactly one 32-byte PSK encoded as 64 hexadecimal characters.
func LoadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", path, err)
	}
	encoded := strings.TrimSpace(string(data))
	if len(encoded) != encodedKeyLength {
		return nil, fmt.Errorf("invalid key file %q: got %d hexadecimal characters, want %d", path, len(encoded), encodedKeyLength)
	}
	key, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal key in %q: %w", path, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key in %q: got %d bytes, want %d", path, len(key), KeySize)
	}
	return key, nil
}

// GenerateKeyFile securely creates a new non-overwritable mode-0600 PSK file.
func GenerateKeyFile(path string) (returnErr error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate PSK: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file %q: %w", path, err)
	}
	completed := false
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			returnErr = fmt.Errorf("close key file %q: %w", path, err)
		}
		if !completed {
			_ = os.Remove(path)
		}
	}()

	encoded := make([]byte, encodedKeyLength+1)
	hex.Encode(encoded[:encodedKeyLength], key)
	encoded[encodedKeyLength] = '\n'
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write key file %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync key file %q: %w", path, err)
	}
	completed = true
	return nil
}
