package localproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"mschapv3proxy/internal/wire"
)

type mockUDPSession struct {
	recvChan chan udpPacket
	sendChan chan udpPacket
}

type udpPacket struct {
	host    string
	port    uint16
	payload []byte
}

func (m *mockUDPSession) SendUDP(host string, port uint16, payload []byte) error {
	m.sendChan <- udpPacket{host: host, port: port, payload: payload}
	// Echo back with modified payload
	m.recvChan <- udpPacket{host: host, port: port, payload: append([]byte("echo: "), payload...)}
	return nil
}

func (m *mockUDPSession) ReceiveUDP(ctx context.Context) (string, uint16, []byte, error) {
	select {
	case p := <-m.recvChan:
		return p.host, p.port, p.payload, nil
	case <-ctx.Done():
		return "", 0, nil, ctx.Err()
	}
}

func (m *mockUDPSession) Close() error {
	return nil
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sess := &mockUDPSession{
		recvChan: make(chan udpPacket, 10),
		sendChan: make(chan udpPacket, 10),
	}

	dialUDP := func(ctx context.Context) (UDPSession, error) {
		return sess, nil
	}

	go ServeWithUDP(ln, nil, dialUDP)

	// Connect TCP control
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS5 greeting
	conn.Write([]byte{5, 1, 0})
	var greetingResp [2]byte
	if _, err := io.ReadFull(conn, greetingResp[:]); err != nil || greetingResp[0] != 5 || greetingResp[1] != 0 {
		t.Fatalf("greeting failed: %v", err)
	}

	// UDP ASSOCIATE request
	conn.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 0})
	var assocResp [10]byte
	if _, err := io.ReadFull(conn, assocResp[:]); err != nil || assocResp[0] != 5 || assocResp[1] != 0 {
		t.Fatalf("udp associate failed: %v, resp: %v", err, assocResp)
	}

	bndPort := binary.BigEndian.Uint16(assocResp[8:10])
	bndAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(bndPort)}

	// Open client UDP socket
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	// Build SOCKS5 UDP packet: dst 127.0.0.1:9090 payload "ping"
	socksHeader, err := buildSocks5UDPHeader("127.0.0.1", 9090, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := clientUDP.WriteToUDP(socksHeader, bndAddr); err != nil {
		t.Fatal(err)
	}

	// Wait for echo packet from proxy
	buf := make([]byte, 1024)
	clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := clientUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read response error: %v", err)
	}

	host, port, payload, err := parseSocks5UDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parse response header error: %v", err)
	}

	if host != "127.0.0.1" || port != 9090 || string(payload) != "echo: ping" {
		t.Fatalf("unexpected echo response: %s:%d %q", host, port, string(payload))
	}
}

func TestSocksCode(t *testing.T) {
	if socksCode(&wire.StatusError{Code: wire.StatusNotAllowed}) != 0x02 {
		t.Fatal("expected 0x02")
	}
	if socksCode(&wire.StatusError{Code: wire.StatusHostUnreach}) != 0x04 {
		t.Fatal("expected 0x04")
	}
	if socksCode(&wire.StatusError{Code: wire.StatusRefused}) != 0x05 {
		t.Fatal("expected 0x05")
	}
}
