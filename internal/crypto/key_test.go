package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndLoadKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.key")
	if err := GenerateKeyFile(path); err != nil {
		t.Fatalf("GenerateKeyFile() error = %v", err)
	}
	key, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey() error = %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key length = %d, want %d", len(key), KeySize)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key file permissions = %o, want no group/other access", info.Mode().Perm())
	}
	if err := GenerateKeyFile(path); err == nil {
		t.Fatal("GenerateKeyFile() overwrote an existing key")
	}
	loadedAgain, _ := LoadKey(path)
	if !bytes.Equal(key, loadedAgain) {
		t.Fatal("existing key changed after refused overwrite")
	}
}

func TestLoadKeyRejectsMalformedFiles(t *testing.T) {
	for name, contents := range map[string]string{
		"short":   "abcd\n",
		"not-hex": string(bytes.Repeat([]byte{'z'}, encodedKeyLength)),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vpn.key")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadKey(path); err == nil {
				t.Fatal("LoadKey() accepted malformed key")
			}
		})
	}
}
