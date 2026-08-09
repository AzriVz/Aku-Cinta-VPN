//go:build linux

// Package tun creates and configures a native Linux Layer 3 TUN interface.
package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const cloneDevice = "/dev/net/tun"

// Device is an open, non-persistent TUN file descriptor. Closing it removes
// the interface once no process holds another descriptor.
type Device struct {
	*os.File
	name string
}

func (d *Device) Name() string { return d.name }

// OpenAndConfigure creates IFF_TUN|IFF_NO_PI, assigns its address and MTU, and
// brings it up using iproute2 in the current network namespace.
func OpenAndConfigure(ctx context.Context, name string, address netip.Prefix, mtu int) (*Device, error) {
	device, err := open(name)
	if err != nil {
		return nil, err
	}
	if err := configure(ctx, name, address, mtu); err != nil {
		_ = device.Close()
		return nil, err
	}
	return device, nil
}

func open(name string) (*Device, error) {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN interface name %q: %w", name, err)
	}
	file, err := os.OpenFile(cloneDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, permissionHint(fmt.Errorf("open %s: %w", cloneDevice, err))
	}

	request.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
		_ = file.Close()
		return nil, permissionHint(fmt.Errorf("TUNSETIFF for %q: %w", name, err))
	}
	return &Device{File: file, name: request.Name()}, nil
}

func configure(ctx context.Context, name string, address netip.Prefix, mtu int) error {
	commands := [][]string{
		{"address", "replace", address.String(), "dev", name},
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu)},
		{"link", "set", "dev", name, "up"},
	}
	for _, args := range commands {
		command := exec.CommandContext(ctx, "ip", args...)
		output, err := command.CombinedOutput()
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail != "" {
				err = fmt.Errorf("%w: %s", err, detail)
			}
			return permissionHint(fmt.Errorf("configure TUN with %q: %w", "ip "+strings.Join(args, " "), err))
		}
	}
	return nil
}

func permissionHint(err error) error {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%w (run as root or grant CAP_NET_ADMIN)", err)
	}
	return err
}
