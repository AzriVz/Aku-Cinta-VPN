package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AzriVz/Aku-Cinta-VPN/internal/config"
	vpncrypto "github.com/AzriVz/Aku-Cinta-VPN/internal/crypto"
	"github.com/AzriVz/Aku-Cinta-VPN/internal/tun"
	"github.com/AzriVz/Aku-Cinta-VPN/internal/tunnel"
)

var version = "0.1.0-dev"

type logger struct {
	base    *log.Logger
	verbose bool
}

func (l *logger) Infof(format string, args ...any) {
	l.base.Printf("[INFO] "+format, args...)
}

func (l *logger) Debugf(format string, args ...any) {
	if l.verbose {
		l.base.Printf("[DEBUG] "+format, args...)
	}
}

func (l *logger) Errorf(format string, args ...any) {
	l.base.Printf("[ERROR] "+format, args...)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\nUse --help to see valid options.\n", err)
		return 2
	}

	switch cfg.Action {
	case config.ActionVersion:
		fmt.Fprintf(stdout, "aku-cinta-vpn %s\n", version)
		return 0
	case config.ActionGenerateKey:
		if err := vpncrypto.GenerateKeyFile(cfg.GenerateKeyPath); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Created PSK file %s with mode 0600.\n", cfg.GenerateKeyPath)
		return 0
	}

	appLog := &logger{base: log.New(stderr, "", log.LstdFlags), verbose: cfg.Verbose}
	key, err := vpncrypto.LoadKey(cfg.KeyPath)
	if err != nil {
		appLog.Errorf("%v", err)
		return 1
	}
	box, err := vpncrypto.New(key)
	if err != nil {
		appLog.Errorf("initialize encryption: %v", err)
		return 1
	}
	prefix, err := vpncrypto.RandomPrefix()
	if err != nil {
		appLog.Errorf("%v", err)
		return 1
	}

	listenAddress := net.UDPAddrFromAddrPort(cfg.Listen)
	udp, err := net.ListenUDP("udp4", listenAddress)
	if err != nil {
		appLog.Errorf("listen on %s: %v", cfg.Listen, err)
		return 1
	}
	// Ownership transfers to Tunnel after it is constructed. Until then, make
	// sure all early returns release the socket.
	udpOwned := false
	defer func() {
		if !udpOwned {
			_ = udp.Close()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tunDevice, err := tun.OpenAndConfigure(ctx, cfg.TunName, cfg.TunIP, cfg.MTU)
	if err != nil {
		appLog.Errorf("create TUN interface: %v", err)
		return 1
	}

	vpnTunnel, err := tunnel.New(tunDevice, udp, cfg.Peer, box, prefix, cfg.MTU, appLog)
	if err != nil {
		_ = tunDevice.Close()
		appLog.Errorf("initialize tunnel: %v", err)
		return 1
	}
	udpOwned = true

	appLog.Infof("opened TUN interface %s", tunDevice.Name())
	appLog.Infof("configured %s as %s mtu=%d", tunDevice.Name(), cfg.TunIP, cfg.MTU)
	appLog.Infof("listening on %s", cfg.Listen)
	appLog.Infof("peer is %s", cfg.Peer)
	appLog.Infof("VPN tunnel ready")

	if err := vpnTunnel.Run(ctx); err != nil {
		appLog.Errorf("VPN tunnel stopped: %v", err)
		return 1
	}
	appLog.Infof("VPN tunnel stopped cleanly")
	return 0
}
