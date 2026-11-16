package main

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	maxUDP       = 65507
	fragmentSize = 1000
	fragmentHead = 7
	fragmentTTL  = 500 * time.Millisecond
)

type datagramSender struct {
	send func([]byte) error
	next uint32
}

func (s *datagramSender) data(data []byte) error {
	if len(data) == 0 || len(data) > maxUDP {
		return nil
	}
	err := s.send(append([]byte{'D'}, data...))
	var large *quic.DatagramTooLargeError
	if !errors.As(err, &large) {
		return err
	}
	if large.MaxDatagramPayloadSize < fragmentSize+fragmentHead {
		return err
	}
	s.next++
	for offset := 0; offset < len(data); offset += fragmentSize {
		part := data[offset:min(offset+fragmentSize, len(data))]
		frame := make([]byte, fragmentHead+len(part))
		binary.BigEndian.PutUint32(frame[1:5], s.next)
		binary.BigEndian.PutUint16(frame[5:7], uint16(len(data)))
		// The low byte of the marker is the fragment index. 0x80 distinguishes it from D and P.
		frame[0] = 0x80 | byte(offset/fragmentSize)
		copy(frame[fragmentHead:], part)
		if err := s.send(frame); err != nil {
			return err
		}
	}
	return nil
}

type fragments struct {
	body    []byte
	seen    [66]bool
	count   int
	expires time.Time
}

type reassembly map[uint32]*fragments

func (r reassembly) data(frame []byte, now time.Time) []byte {
	if len(frame) > 1 && frame[0] == 'D' && len(frame)-1 <= maxUDP {
		return frame[1:]
	}
	if len(frame) <= fragmentHead || frame[0]&0x80 == 0 {
		return nil
	}
	id := binary.BigEndian.Uint32(frame[1:5])
	total := int(binary.BigEndian.Uint16(frame[5:7]))
	index := int(frame[0] & 0x7f)
	offset := index * fragmentSize
	if total > maxUDP || offset >= total || len(frame)-fragmentHead != min(fragmentSize, total-offset) {
		return nil
	}
	for key, message := range r {
		if !now.Before(message.expires) {
			delete(r, key)
		}
	}
	message := r[id]
	if message == nil {
		if len(r) == 32 {
			return nil
		}
		message = &fragments{body: make([]byte, total), expires: now.Add(fragmentTTL)}
		r[id] = message
	}
	if len(message.body) != total || message.seen[index] {
		return nil
	}
	copy(message.body[offset:], frame[fragmentHead:])
	message.seen[index] = true
	message.count++
	if message.count == (total+fragmentSize-1)/fragmentSize {
		delete(r, id)
		return message.body
	}
	return nil
}
