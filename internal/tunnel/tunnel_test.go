package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"mschapv3proxy/internal/wire"
	"mschapv3proxy/mschapv3"
)

func generateTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

func startTestQUICServer(t *testing.T) (addr string, auth *mschapv3.Server, stop func()) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatal(err)
	}

	cred, err := mschapv3.NewCredential("alice", "secret123", 1000)
	if err != nil {
		t.Fatal(err)
	}

	auth = &mschapv3.Server{
		Lookup: func(u string) (*mschapv3.Credential, bool) {
			if u == "alice" {
				return cred, true
			}
			return nil, false
		},
		Secret:         []byte("01234567890123456789012345678901"),
		FakeIterations: 1000,
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"mschapv3-quic"},
	}

	qconf := &quic.Config{
		EnableDatagrams: true,
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, qconf)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			qconn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go handleTestQUICConn(t, qconn, auth)
		}
	}()

	stop = func() {
		cancel()
		listener.Close()
	}

	return listener.Addr().String(), auth, stop
}

type testStreamConn struct {
	quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (s *testStreamConn) LocalAddr() net.Addr  { return s.laddr }
func (s *testStreamConn) RemoteAddr() net.Addr { return s.raddr }
func (s *testStreamConn) CloseWrite() error    { return s.Stream.Close() }

func handleTestQUICConn(t *testing.T, qconn quic.Connection, auth *mschapv3.Server) {
	ctx := context.Background()
	st, err := qconn.AcceptStream(ctx)
	if err != nil {
		return
	}
	defer st.Close()

	cs := qconn.ConnectionState().TLS
	binding, err := cs.ExportKeyingMaterial("EXPORTER-MSCHAPV3", nil, 32)
	if err != nil {
		return
	}

	conn := &testStreamConn{Stream: st, laddr: qconn.LocalAddr(), raddr: qconn.RemoteAddr()}
	br := bufio.NewReader(conn)

	sess, _, err := wire.ServerAccept(conn, br, wire.ServerParams{
		Auth: auth, TLSBinding: binding, Encrypt: false,
	})
	if err != nil {
		return
	}

	if sess.Cmd != wire.CmdUDP {
		sess.Stream.Write([]byte{wire.StatusFail})
		return
	}

	sess.Stream.Write([]byte{wire.StatusOK})

	// Serve datagrams
	for {
		data, err := qconn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		dstHost, dstPort, payload, err := wire.DecodeUDPDatagram(data)
		if err != nil {
			continue
		}

		addr := net.JoinHostPort(dstHost, fmt.Sprint(dstPort))
		uConn, err := net.Dial("udp", addr)
		if err == nil {
			uConn.SetDeadline(time.Now().Add(2 * time.Second))
			uConn.Write(payload)
			reply := make([]byte, 2048)
			n, err := uConn.Read(reply)
			uConn.Close()
			if err == nil {
				enc, _ := wire.EncodeUDPDatagram(dstHost, dstPort, reply[:n])
				qconn.SendDatagram(enc)
			}
		}
	}
}

func TestQUICUDPTunnel(t *testing.T) {
	// 1. Start target UDP echo server
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer targetConn.Close()

	targetAddr := targetConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 1024)
		for {
			targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, clientAddr, err := targetConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			targetConn.WriteToUDP(append([]byte("echo: "), buf[:n]...), clientAddr)
		}
	}()

	// 2. Start test QUIC server
	serverAddr, _, stopServer := startTestQUICServer(t)
	defer stopServer()

	// 3. Create client config
	cfg := &Config{
		Server:   serverAddr,
		Username: "alice",
		Password: "secret123",
		TLS: TLSConfig{
			Enabled:  true,
			Insecure: true,
		},
		MinKDFIterations: 1000,
	}

	cl, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Dial UDP over QUIC
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := cl.DialUDP(ctx)
	if err != nil {
		t.Fatalf("DialUDP error: %v", err)
	}
	defer sess.Close()

	// 5. Send UDP packet to target
	if err := sess.SendUDP("127.0.0.1", uint16(targetAddr.Port), []byte("ping quic")); err != nil {
		t.Fatalf("SendUDP error: %v", err)
	}

	// 6. Receive UDP reply from QUIC
	host, port, payload, err := sess.ReceiveUDP(ctx)
	if err != nil {
		t.Fatalf("ReceiveUDP error: %v", err)
	}

	if host != "127.0.0.1" || port != uint16(targetAddr.Port) || string(payload) != "echo: ping quic" {
		t.Fatalf("Unexpected reply: %s:%d %q", host, port, string(payload))
	}
}
