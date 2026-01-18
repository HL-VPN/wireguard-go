/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"net/netip"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/winipcfg"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func main() {
	if len(os.Args) != 7 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface name> <mtu> <config> <ipv4> <ipv6> <endpoint>\n", os.Args[0])
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]
	mtu := os.Args[2]
	config := os.Args[3]
	ipv4 := os.Args[4]
	ipv6 := os.Args[5]
	endpoint := os.Args[6]

	parsedMtu, err := strconv.Atoi(mtu)
	parsedIpv4 := netip.MustParsePrefix(ipv4)
	parsedIpv6 := netip.MustParsePrefix(ipv6)

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting wireguard-go version %s", Version)

	tun, err := tun.CreateTUN(interfaceName, parsedMtu)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	err = device.IpcSet(config)
	if err != nil {
		logger.Errorf("Failed to configure: %v", err)
		os.Exit(ExitSetupFailed)
	}

	err = device.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		os.Exit(ExitSetupFailed)
	}
	logger.Verbosef("Device started")

	type luidGetter interface {
		LUID() uint64
	}

	if tunLUID, ok := tun.(luidGetter); ok {
		luid := winipcfg.LUID(tunLUID.LUID())

		if ipv4Interface, err := luid.IPInterface(windows.AF_INET); err == nil {
			ipv4Interface.NLMTU = uint32(parsedMtu)
			ipv4Interface.Set()
		}
		if ipv6Interface, err := luid.IPInterface(windows.AF_INET6); err == nil {
			ipv6Interface.NLMTU = uint32(parsedMtu)
			ipv6Interface.Set()
		}

		luid.SetIPAddresses([]netip.Prefix{parsedIpv4, parsedIpv6})

		routes, _ := winipcfg.GetIPForwardTable2(windows.AF_INET)
		for _, route := range routes {
			if route.DestinationPrefix.PrefixLength == 0 {
				route.InterfaceLUID.AddRoute(netip.MustParsePrefix(endpoint + "/32"), route.NextHop.Addr(), 0)
			}
		}
		luid.AddRoute(netip.MustParsePrefix("0.0.0.0/0"), netip.IPv4Unspecified(), 0)
		luid.AddRoute(netip.MustParsePrefix("::/0"), netip.IPv6Unspecified(), 0)
	}

	term := make(chan os.Signal, 1)

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up

	device.Close()

	logger.Verbosef("Shutting down")
}
