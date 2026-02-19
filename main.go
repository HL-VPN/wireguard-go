//go:build !windows

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
	//"net/netip"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func main() {
	if len(os.Args) != 7 {
		fmt.Printf("Usage: %s <interface name> <mtu> <config> <ipv4> <ipv6> <endpoint>\n", os.Args[0])
		return
	}
	interfaceName := os.Args[1]
	mtu := os.Args[2]
	config := os.Args[3]
	//ipv4 := os.Args[4]
	//ipv6 := os.Args[5]
	//endpoint := os.Args[6]

	parsedMtu, err := strconv.Atoi(mtu)
	//parsedIpv4 := netip.MustParsePrefix(ipv4)
	//parsedIpv6 := netip.MustParsePrefix(ipv6)

	// open TUN device

	tdev, err := tun.CreateTUN(interfaceName, parsedMtu)
	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	err = device.IpcSet(config)
	if err != nil {
		logger.Errorf("Failed to configure: %v", err)
		os.Exit(ExitSetupFailed)
	}

	logger.Verbosef("Device started")

	term := make(chan os.Signal, 1)

	// wait for program to terminate

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-device.Wait():
	}

	// clean up

	device.Close()

	logger.Verbosef("Shutting down")
}
