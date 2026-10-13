// Package tunnel — клиентское ядро: соединение с сервером (TCP/TLS),
// аутентификация MS-CHAPv3 и запрос на соединение с целевым хостом.
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"mschapv3proxy/internal/localproxy"
	"mschapv3proxy/internal/wire"
	"mschapv3proxy/mschapv3"
)

type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name"`
	PinSHA256  string `json:"pin_sha256"` // SHA-256 сертификата сервера (hex); позволяет self-signed
	Insecure   bool   `json:"insecure"`   // НЕ проверять сертификат (только для отладки)
}

type Config struct {
	Server           string    `json:"server"`
	Username         string    `json:"username"`
	Password         string    `json:"password"`
	Listen           string    `json:"listen"`
	TLS              TLSConfig `json:"tls"`
	DNS              string    `json:"dns"` // свой DNS для резолва адреса сервера (нужен в Termux), напр. "1.1.1.1:53"
	MinKDFIterations uint32    `json:"min_kdf_iterations"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Server == "" || c.Username == "" || c.Password == "" {
		return nil, errors.New("config: server, username and password are required")
	}
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return nil, fmt.Errorf("config: server must be host:port: %w", err)
	}
	return &c, nil
}

type Client struct {
	cfg    *Config
	cache  *mschapv3.KeyCache
	dialer *net.Dialer
	tlsCfg *tls.Config
}

func New(cfg *Config) (*Client, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if cfg.DNS != "" {
		dns := cfg.DNS
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var nd net.Dialer
				return nd.DialContext(ctx, "udp", dns)
			},
		}
	}
	c := &Client{cfg: cfg, cache: mschapv3.NewKeyCache(), dialer: d}

	if cfg.TLS.Enabled {
		host, _, _ := net.SplitHostPort(cfg.Server)
		tc := &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"},
			ServerName: cfg.TLS.ServerName,
		}
		if tc.ServerName == "" && net.ParseIP(host) == nil {
			tc.ServerName = host
		}
		switch {
		case cfg.TLS.PinSHA256 != "":
			want := strings.ToLower(strings.ReplaceAll(cfg.TLS.PinSHA256, ":", ""))
			tc.InsecureSkipVerify = true // проверка заменена пином ниже
			tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no server certificate")
				}
				sum := sha256.Sum256(raw[0])
				if hex.EncodeToString(sum[:]) != want {
					return errors.New("server certificate does not match pin_sha256")
				}
				return nil
			}
		case cfg.TLS.Insecure:
			tc.InsecureSkipVerify = true
		case tc.ServerName == "":
			return nil, errors.New("config: tls.server_name required when server is an IP (or set pin_sha256)")
		}
		c.tlsCfg = tc
	}
	return c, nil
}

// Dial открывает туннель до host:port через прокси-сервер.
func (c *Client) Dial(host string, port uint16) (wire.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := c.dialer.DialContext(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	raw.SetDeadline(time.Now().Add(30 * time.Second))

	var conn net.Conn = raw
	var binding []byte
	if c.tlsCfg != nil {
		tc := tls.Client(raw, c.tlsCfg.Clone())
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		cs := tc.ConnectionState()
		binding, err = cs.ExportKeyingMaterial("EXPORTER-MSCHAPV3", nil, 32)
		if err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls exporter: %w", err)
		}
		conn = tc
	}
	st, err := wire.ClientConnect(conn, wire.ClientParams{
		Username: c.cfg.Username, Password: c.cfg.Password, Cache: c.cache,
		TLSBinding: binding, Encrypt: c.tlsCfg == nil, MinIterations: c.cfg.MinKDFIterations,
	}, host, port)
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return st, nil
}

type quicStreamConn struct {
	quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (s *quicStreamConn) LocalAddr() net.Addr  { return s.laddr }
func (s *quicStreamConn) RemoteAddr() net.Addr { return s.raddr }
func (s *quicStreamConn) CloseWrite() error    { return s.Stream.Close() }

type quicUDPSession struct {
	qconn      quic.Connection
	ctrlStream wire.Stream
}

func (s *quicUDPSession) SendUDP(host string, port uint16, payload []byte) error {
	b, err := wire.EncodeUDPDatagram(host, port, payload)
	if err != nil {
		return err
	}
	return s.qconn.SendDatagram(b)
}

func (s *quicUDPSession) ReceiveUDP(ctx context.Context) (string, uint16, []byte, error) {
	b, err := s.qconn.ReceiveDatagram(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	return wire.DecodeUDPDatagram(b)
}

func (s *quicUDPSession) Close() error {
	if s.ctrlStream != nil {
		s.ctrlStream.Close()
	}
	return s.qconn.CloseWithError(0, "")
}

func (c *Client) DialUDP(ctx context.Context) (localproxy.UDPSession, error) {
	tc := c.tlsCfg
	if tc == nil {
		host, _, _ := net.SplitHostPort(c.cfg.Server)
		tc = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			NextProtos:         []string{"mschapv3-quic"},
			ServerName:         host,
		}
	} else {
		tc = tc.Clone()
		tc.NextProtos = append([]string{"mschapv3-quic"}, tc.NextProtos...)
	}

	qconf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	}

	qconn, err := quic.DialAddr(ctx, c.cfg.Server, tc, qconf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	st, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	cs := qconn.ConnectionState().TLS
	binding, err := cs.ExportKeyingMaterial("EXPORTER-MSCHAPV3", nil, 32)
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("quic tls exporter: %w", err)
	}

	streamConn := &quicStreamConn{
		Stream: st,
		laddr:  qconn.LocalAddr(),
		raddr:  qconn.RemoteAddr(),
	}

	wireStream, err := wire.ClientConnectCmd(streamConn, wire.ClientParams{
		Username: c.cfg.Username, Password: c.cfg.Password, Cache: c.cache,
		TLSBinding: binding, Encrypt: false, MinIterations: c.cfg.MinKDFIterations,
	}, wire.CmdUDP, "udp", 0)
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, err
	}

	return &quicUDPSession{
		qconn:      qconn,
		ctrlStream: wireStream,
	}, nil
}
