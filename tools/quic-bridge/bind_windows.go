package main

import (
	"encoding/binary"
	"syscall"
)

func bindInterface(raw syscall.RawConn, index uint32) error {
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		var order [4]byte
		binary.BigEndian.PutUint32(order[:], index)
		// IP_UNICAST_IF takes the interface index in network byte order.
		bindErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31, int(binary.NativeEndian.Uint32(order[:])))
	}); err != nil {
		return err
	}
	return bindErr
}
