// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"database/sql/driver"
	"fmt"
	"net"
	"strings"
)

// MacAddr wraps net.HardwareAddr to provide proper SQL driver support for PostgreSQL macaddr type.
type MacAddr net.HardwareAddr

// Value implements driver.Valuer for MacAddr.
// Converts the MAC address to a string format that PostgreSQL's macaddr type expects.
func (m MacAddr) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return net.HardwareAddr(m).String(), nil
}

// Scan implements sql.Scanner for MacAddr.
// Handles both string and []byte inputs from PostgreSQL.
func (m *MacAddr) Scan(src interface{}) error {
	if src == nil {
		*m = nil
		return nil
	}

	var macStr string
	switch v := src.(type) {
	case string:
		macStr = v
	case []byte:
		macStr = string(v)
	default:
		return fmt.Errorf("cannot scan %T into MacAddr", src)
	}

	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("failed to parse MAC address %q: %w", macStr, err)
	}
	*m = MacAddr(mac)
	return nil
}

// HardwareAddr returns the underlying net.HardwareAddr.
func (m MacAddr) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(m)
}

// String returns the MAC address as a string.
func (m MacAddr) String() string {
	return net.HardwareAddr(m).String()
}

// IPAddr wraps net.IP to provide proper SQL driver support for PostgreSQL inet type.
type IPAddr net.IP

// Value implements driver.Valuer for IPAddr.
// Converts the IP address to a string format that PostgreSQL's inet type expects.
func (ip IPAddr) Value() (driver.Value, error) {
	if ip == nil {
		return nil, nil
	}
	return net.IP(ip).String(), nil
}

// Scan implements sql.Scanner for IPAddr.
// Handles both string and []byte inputs from PostgreSQL.
func (ip *IPAddr) Scan(src interface{}) error {
	if src == nil {
		*ip = nil
		return nil
	}

	var ipStr string
	switch v := src.(type) {
	case string:
		ipStr = v
	case []byte:
		ipStr = string(v)
	default:
		return fmt.Errorf("cannot scan %T into IPAddr", src)
	}

	// PostgreSQL inet type may include CIDR notation, strip it if present
	if i := strings.LastIndexByte(ipStr, '/'); i >= 0 {
		ipStr = ipStr[:i]
	}

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return fmt.Errorf("failed to parse IP address %q", ipStr)
	}
	*ip = IPAddr(parsed)
	return nil
}

// IP returns the underlying net.IP.
func (ip IPAddr) IP() net.IP {
	return net.IP(ip)
}

// String returns the IP address as a string.
func (ip IPAddr) String() string {
	return net.IP(ip).String()
}

// Equal returns true if the two IPAddr are equal.
func (ip IPAddr) Equal(other IPAddr) bool {
	return net.IP(ip).Equal(net.IP(other))
}
