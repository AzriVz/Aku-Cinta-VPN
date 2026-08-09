// Package config parses and validates command-line configuration.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

const DefaultMTU = 1300

type Action uint8

const (
	ActionRun Action = iota
	ActionVersion
	ActionGenerateKey
)

type Config struct {
	Action          Action
	TunName         string
	TunIP           netip.Prefix
	Listen          netip.AddrPort
	Peer            netip.AddrPort
	KeyPath         string
	GenerateKeyPath string
	MTU             int
	Verbose         bool
}

// Parse handles all supported CLI flags without terminating the process, which
// keeps both the main program and unit tests in control of errors.
func Parse(args []string, output io.Writer) (Config, error) {
	var cfg Config
	var tunIP, listen, peer string
	var showVersion bool

	fs := flag.NewFlagSet("aku-cinta-vpn", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.TunName, "tun", "tun0", "TUN interface name")
	fs.StringVar(&tunIP, "tun-ip", "", "TUN IPv4 address and prefix (for example 10.8.0.1/24)")
	fs.StringVar(&listen, "listen", "", "local underlay UDP IPv4 address (IP:port)")
	fs.StringVar(&peer, "peer", "", "peer underlay UDP IPv4 address (IP:port)")
	fs.StringVar(&cfg.KeyPath, "key", "", "path to a 32-byte PSK encoded as hexadecimal")
	fs.IntVar(&cfg.MTU, "mtu", DefaultMTU, "TUN interface MTU (576-9000)")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "enable per-packet debug logging")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&cfg.GenerateKeyPath, "generate-key", "", "securely create a new PSK file and exit")
	fs.Usage = func() {
		fmt.Fprintf(output, "Usage: aku-cinta-vpn [options]\n\n")
		fmt.Fprintf(output, "Encrypted point-to-point Layer 3 VPN for Linux.\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if showVersion {
		cfg.Action = ActionVersion
		return cfg, nil
	}
	if cfg.GenerateKeyPath != "" {
		cfg.Action = ActionGenerateKey
		return cfg, nil
	}

	cfg.Action = ActionRun
	if err := validateTunName(cfg.TunName); err != nil {
		return Config{}, err
	}
	if cfg.MTU < 576 || cfg.MTU > 9000 {
		return Config{}, fmt.Errorf("invalid --mtu %d: must be between 576 and 9000", cfg.MTU)
	}
	if tunIP == "" {
		return Config{}, errors.New("--tun-ip is required")
	}
	prefix, err := netip.ParsePrefix(tunIP)
	if err != nil || !prefix.Addr().Is4() {
		return Config{}, fmt.Errorf("invalid --tun-ip %q: expected an IPv4 CIDR such as 10.8.0.1/24", tunIP)
	}
	if prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
		return Config{}, fmt.Errorf("invalid --tun-ip %q: address must be a usable unicast IPv4 address", tunIP)
	}
	cfg.TunIP = prefix

	cfg.Listen, err = parseEndpoint("--listen", listen, true)
	if err != nil {
		return Config{}, err
	}
	cfg.Peer, err = parseEndpoint("--peer", peer, false)
	if err != nil {
		return Config{}, err
	}
	if cfg.Listen == cfg.Peer {
		return Config{}, errors.New("--listen and --peer must be different endpoints")
	}
	if cfg.KeyPath == "" {
		return Config{}, errors.New("--key is required")
	}
	return cfg, nil
}

func parseEndpoint(name, value string, allowUnspecified bool) (netip.AddrPort, error) {
	if value == "" {
		return netip.AddrPort{}, fmt.Errorf("%s is required", name)
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid %s %q: expected IPv4:port with a non-zero port", name, value)
	}
	address := endpoint.Addr().Unmap()
	if address.IsMulticast() || (!allowUnspecified && address.IsUnspecified()) {
		return netip.AddrPort{}, fmt.Errorf("invalid %s %q: address is not a usable unicast endpoint", name, value)
	}
	return netip.AddrPortFrom(address, endpoint.Port()), nil
}

func validateTunName(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("invalid --tun %q: interface name must contain 1-15 characters", name)
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return fmt.Errorf("invalid --tun %q: allowed characters are letters, digits, '.', '_' and '-'", name)
	}
	return nil
}
