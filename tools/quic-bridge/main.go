package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const protocol = "vpslink-datagram/1"

type settings struct {
	Key, Pin, Host, Source, Target string
	Port                           uint16
	Interface                      uint32
}

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true, HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 12 * time.Second,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: -1, InitialPacketSize: 1200,
	}
}

func certificate() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	pin := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(pin[:]), err
}

func authenticate(conn *quic.Conn, key []byte, server bool) error {
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		return errors.New("QUIC peer disabled datagrams")
	}
	ctx, cancel := context.WithTimeout(conn.Context(), 4*time.Second)
	defer cancel()
	var stream *quic.Stream
	var err error
	if server {
		stream, err = conn.AcceptStream(ctx)
	} else {
		stream, err = conn.OpenStreamSync(ctx)
	}
	if err != nil {
		return err
	}
	defer stream.Close()
	deadline, _ := ctx.Deadline()
	stream.SetDeadline(deadline)
	if server {
		var remote [32]byte
		if _, err := io.ReadFull(stream, remote[:]); err != nil || !hmac.Equal(remote[:], key) {
			return errors.New("QUIC authentication failed")
		}
		_, err = stream.Write([]byte{1})
		return err
	}
	if _, err := stream.Write(key); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != 1 {
		return errors.New("QUIC authentication failed")
	}
	return nil
}

func runServer(s settings, key []byte) error {
	target, err := netip.ParseAddrPort(s.Target)
	if err != nil || target.Port() == 0 {
		return errors.New("invalid UDP target from SSH")
	}
	cert, pin, err := certificate()
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	defer udp.Close()
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()
	listener, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol}}, quicConfig())
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"Port": udp.LocalAddr().(*net.UDPAddr).Port, "Pin": pin,
	}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	for {
		remote, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		if authenticate(remote, key, true) == nil {
			defer remote.CloseWithError(0, "closed")
			return forwardTarget(remote, target)
		}
		remote.CloseWithError(1, "authentication failed")
	}
}

func forwardTarget(remote *quic.Conn, target netip.AddrPort) error {
	vpn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return err
	}
	defer vpn.Close()
	vpn.SetReadBuffer(256 * 1024)
	// The UDP reader owns the serializer for outgoing packets and pong frames.
	outgoing := make(chan []byte, 64)
	pongs := make(chan []byte, 4)
	done := remote.Context().Done()
	fail := make(chan error, 1)
	go func() {
		buffer := make([]byte, maxUDP)
		for {
			n, err := vpn.Read(buffer)
			if err != nil {
				if errors.Is(err, syscall.ECONNREFUSED) {
					continue
				}
				return
			}
			select {
			case outgoing <- append([]byte(nil), buffer[:n]...):
			default:
			}
		}
	}()
	go func() {
		sender := datagramSender{send: remote.SendDatagram}
		for {
			var err error
			select {
			case <-done:
				return
			case pong := <-pongs:
				err = remote.SendDatagram(pong)
			case data := <-outgoing:
				err = sender.data(data)
			}
			if err != nil {
				fail <- err
				remote.CloseWithError(2, "UDP forwarding stopped")
				return
			}
		}
	}()
	assemble := make(reassembly)
	for {
		packet, err := remote.ReceiveDatagram(remote.Context())
		if err != nil {
			select {
			case reason := <-fail:
				return reason
			default:
				return err
			}
		}
		if len(packet) == 9 && packet[0] == 'P' {
			select {
			case pongs <- packet:
			default:
			}
		} else if data := assemble.data(packet, time.Now()); data != nil {
			vpn.Write(data)
		}
	}
}

func runClient(s settings, key []byte, input io.Reader) error {
	peer := net.ParseIP(s.Host).To4()
	source := net.ParseIP(s.Source).To4()
	if peer == nil || source == nil || s.Port == 0 {
		return errors.New("invalid client endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	options := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return bindInterface(raw, s.Interface)
	}}
	udp, err := options.ListenPacket(ctx, "udp4", net.JoinHostPort(source.String(), "0"))
	if err != nil {
		return err
	}
	defer udp.Close()
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()
	tlsConfig := &tls.Config{NextProtos: []string{protocol}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 1 {
				pin := sha256.Sum256(state.PeerCertificates[0].Raw)
				if hex.EncodeToString(pin[:]) == s.Pin {
					return nil
				}
			}
			return errors.New("QUIC certificate fingerprint does not match")
		}}
	remote, err := tr.Dial(ctx, &net.UDPAddr{IP: peer, Port: int(s.Port)}, tlsConfig, quicConfig())
	if err != nil {
		return err
	}
	defer remote.CloseWithError(0, "closed")
	if err := authenticate(remote, key, false); err != nil {
		return err
	}
	if err := writeFrame('H', []byte(protocol)); err != nil {
		return err
	}
	go func() {
		defer remote.CloseWithError(0, "local input closed")
		sender := datagramSender{send: remote.SendDatagram}
		for {
			kind, data, err := readFrame(input)
			if err != nil {
				return
			}
			switch kind {
			case 'D':
				err = sender.data(data)
			case 'P':
				if len(data) == 8 {
					err = remote.SendDatagram(append([]byte{'P'}, data...))
				}
			default:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	assemble := make(reassembly)
	for {
		packet, err := remote.ReceiveDatagram(remote.Context())
		if err != nil {
			return err
		}
		if len(packet) == 9 && packet[0] == 'P' {
			err = writeFrame('P', packet[1:])
		} else if data := assemble.data(packet, time.Now()); data != nil {
			err = writeFrame('D', data)
		}
		if err != nil {
			return err
		}
	}
}

func writeFrame(kind byte, data []byte) error {
	frame := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	frame[4] = kind
	copy(frame[5:], data)
	_, err := os.Stdout.Write(frame)
	return err
}

func readFrame(input io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[:4])
	if size > maxUDP {
		return 0, nil, errors.New("invalid frame length")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(input, data)
	return header[4], data, err
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("expected client or server")
	}
	input := bufio.NewReader(os.Stdin)
	line, err := input.ReadSlice('\n')
	if err != nil {
		return err
	}
	var s settings
	if err := json.Unmarshal(line, &s); err != nil {
		return err
	}
	key, err := hex.DecodeString(s.Key)
	if err != nil || len(key) != 32 {
		return errors.New("invalid session key")
	}
	switch os.Args[1] {
	case "server":
		return runServer(s, key)
	case "client":
		return runClient(s, key, input)
	default:
		return errors.New("unknown role")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
