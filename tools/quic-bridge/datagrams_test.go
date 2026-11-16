package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestFragmentedPacketReassemblesOutOfOrder(t *testing.T) {
	for _, size := range []int{1400, 2000, maxUDP} {
		input := bytes.Repeat([]byte{1, 2, 3, 4}, (size+3)/4)[:size]
		var frames [][]byte
		sender := datagramSender{send: func(frame []byte) error {
			if len(frame) > 1100 {
				return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1100}
			}
			frames = append(frames, frame)
			return nil
		}}
		if err := sender.data(input); err != nil {
			t.Fatal(err)
		}
		pending := make(reassembly)
		now := time.Now()
		for i := len(frames) - 1; i > 0; i-- {
			if pending.data(frames[i], now) != nil || pending.data(frames[i], now) != nil {
				t.Fatal("incomplete or duplicate fragment delivered a packet")
			}
		}
		if output := pending.data(frames[0], now); !bytes.Equal(output, input) {
			t.Fatalf("round trip changed a %d-byte packet", size)
		}
	}
}

func TestIncompletePacketExpires(t *testing.T) {
	var frames [][]byte
	sender := datagramSender{send: func(frame []byte) error {
		if len(frame) > 1100 {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1100}
		}
		frames = append(frames, frame)
		return nil
	}}
	if err := sender.data(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pending := make(reassembly)
	pending.data(frames[0], now)
	if pending.data(frames[1], now.Add(fragmentTTL)) != nil {
		t.Fatal("expired fragments were delivered")
	}
}
