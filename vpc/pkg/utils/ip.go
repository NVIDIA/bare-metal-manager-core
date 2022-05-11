/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package utils

import (
	"encoding/binary"
	"net"
)

func Ip2int(ip net.IP) uint32 {
	// nil IP same as 0.0.0.0
	if ip == nil {
		return 0
	}
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
