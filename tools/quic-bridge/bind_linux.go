package main

import (
	"fmt"
	"syscall"
)

func bindInterface(_ syscall.RawConn, index uint32) error {
	if index != 0 {
		return fmt.Errorf("Windows interface required for this client")
	}
	return nil
}
