package config

import (
	"bytes"
	"errors"
	"flag"
	"testing"
)

func validArgs() []string {
	return []string{
		"--tun", "tun-test",
		"--tun-ip", "10.8.0.1/24",
		"--listen", "192.168.10.2:51820",
		"--peer", "192.168.20.2:51820",
		"--key", "vpn.key",
	}
}

func TestParseRunConfiguration(t *testing.T) {
	cfg, err := Parse(append(validArgs(), "--verbose", "--mtu", "1280"), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Action != ActionRun || cfg.TunName != "tun-test" || cfg.MTU != 1280 || !cfg.Verbose {
		t.Fatalf("Parse() = %#v", cfg)
	}
	if got := cfg.TunIP.String(); got != "10.8.0.1/24" {
		t.Fatalf("TunIP = %q", got)
	}
	if got := cfg.Peer.String(); got != "192.168.20.2:51820" {
		t.Fatalf("Peer = %q", got)
	}
}

func TestParseSpecialActions(t *testing.T) {
	cfg, err := Parse([]string{"--version"}, &bytes.Buffer{})
	if err != nil || cfg.Action != ActionVersion {
		t.Fatalf("version: cfg=%#v err=%v", cfg, err)
	}
	cfg, err = Parse([]string{"--generate-key", "secret.key"}, &bytes.Buffer{})
	if err != nil || cfg.Action != ActionGenerateKey || cfg.GenerateKeyPath != "secret.key" {
		t.Fatalf("generate: cfg=%#v err=%v", cfg, err)
	}
	_, err = Parse([]string{"--help"}, &bytes.Buffer{})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v, want flag.ErrHelp", err)
	}
}

func TestParseRejectsInvalidRunConfiguration(t *testing.T) {
	tests := map[string][]string{
		"missing":        {},
		"bad tun":        {"--tun", "bad/name", "--tun-ip", "10.8.0.1/24", "--listen", "1.1.1.1:1", "--peer", "2.2.2.2:2", "--key", "x"},
		"IPv6 tun":       {"--tun-ip", "fd00::1/64", "--listen", "1.1.1.1:1", "--peer", "2.2.2.2:2", "--key", "x"},
		"bad listen":     {"--tun-ip", "10.8.0.1/24", "--listen", "localhost:1", "--peer", "2.2.2.2:2", "--key", "x"},
		"zero peer port": {"--tun-ip", "10.8.0.1/24", "--listen", "1.1.1.1:1", "--peer", "2.2.2.2:0", "--key", "x"},
		"bad MTU":        append(validArgs(), "--mtu", "100"),
		"same endpoint":  {"--tun-ip", "10.8.0.1/24", "--listen", "1.1.1.1:1", "--peer", "1.1.1.1:1", "--key", "x"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(args, &bytes.Buffer{}); err == nil {
				t.Fatal("Parse() accepted invalid configuration")
			}
		})
	}
}
