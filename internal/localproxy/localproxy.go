// Package localproxy — локальный слушатель: SOCKS5 (CONNECT) и HTTP-прокси
// (CONNECT + обычные http://) на одном порту, определяется по первому байту.
package localproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"mschapv3proxy/internal/wire"
)

type DialFunc func(host string, port uint16) (wire.Stream, error)

type UDPSession interface {
	SendUDP(host string, port uint16, payload []byte) error
	ReceiveUDP(ctx context.Context) (host string, port uint16, payload []byte, err error)
	Close() error
}

type DialUDPFunc func(ctx context.Context) (UDPSession, error)

// Serve принимает соединения до закрытия ln.
func Serve(ln net.Listener, dial DialFunc) error {
	return ServeWithUDP(ln, dial, nil)
}

// ServeWithUDP принимает соединения до закрытия ln и поддерживает UDP ASSOCIATE.
func ServeWithUDP(ln net.Listener, dial DialFunc, dialUDP DialUDPFunc) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(c, dial, dialUDP)
	}
}

func handle(c net.Conn, dial DialFunc, dialUDP DialUDPFunc) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 5 {
		handleSocks5(c, br, dial, dialUDP)
	} else {
		handleHTTP(c, br, dial)
	}
}

func socksCode(err error) byte {
	var se *wire.StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case wire.StatusNotAllowed:
			return 0x02
		case wire.StatusHostUnreach:
			return 0x04
		case wire.StatusRefused:
			return 0x05
		}
	}
	return 0x01
}

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func handleSocks5(c net.Conn, br *bufio.Reader, dial DialFunc, dialUDP DialUDPFunc) {
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		c.Write([]byte{5, 0xFF})
		return
	}
	c.Write([]byte{5, 0})

	var r [4]byte
	if _, err := io.ReadFull(br, r[:]); err != nil || r[0] != 5 {
		return
	}
	var host string
	switch r[3] {
	case 1, 4:
		n := 4
		if r[3] == 4 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil || l == 0 {
			return
		}
		d := make([]byte, l)
		if _, err := io.ReadFull(br, d); err != nil {
			return
		}
		host = string(d)
	default:
		socksReply(c, 0x08)
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return
	}
	port := uint16(p[0])<<8 | uint16(p[1])

	if r[1] == 3 { // UDP ASSOCIATE
		if dialUDP == nil {
			socksReply(c, 0x07)
			return
		}
		handleSocks5UDPAssociate(c, dialUDP)
		return
	}

	if r[1] != 1 { // только CONNECT или UDP ASSOCIATE
		socksReply(c, 0x07)
		return
	}
	st, err := dial(host, port)
	if err != nil {
		log.Printf("socks5 %s:%d: %v", host, port, err)
		socksReply(c, socksCode(err))
		return
	}
	socksReply(c, 0)
	c.SetDeadline(time.Time{})
	wire.Relay(wire.NewConnStream(c, br), st)
}

func parseSocks5UDPHeader(buf []byte) (string, uint16, []byte, error) {
	if len(buf) < 6 {
		return "", 0, nil, errors.New("socks5 udp header too short")
	}
	if buf[2] != 0 {
		return "", 0, nil, errors.New("socks5 udp fragmentation not supported")
	}
	atyp := buf[3]
	idx := 4
	var host string
	switch atyp {
	case 1:
		if len(buf) < 4+4+2 {
			return "", 0, nil, errors.New("malformed socks5 udp ipv4")
		}
		host = net.IP(buf[4:8]).String()
		idx = 8
	case 4:
		if len(buf) < 4+16+2 {
			return "", 0, nil, errors.New("malformed socks5 udp ipv6")
		}
		host = net.IP(buf[4:20]).String()
		idx = 20
	case 3:
		if len(buf) < 5 {
			return "", 0, nil, errors.New("malformed socks5 udp domain")
		}
		l := int(buf[4])
		if l == 0 || len(buf) < 5+l+2 {
			return "", 0, nil, errors.New("malformed socks5 udp domain length")
		}
		host = string(buf[5 : 5+l])
		idx = 5 + l
	default:
		return "", 0, nil, errors.New("unsupported socks5 udp atyp")
	}
	port := binary.BigEndian.Uint16(buf[idx : idx+2])
	idx += 2
	return host, port, buf[idx:], nil
}

func buildSocks5UDPHeader(srcHost string, srcPort uint16, payload []byte) ([]byte, error) {
	b := []byte{0, 0, 0}
	if ip := net.ParseIP(srcHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(srcHost) == 0 || len(srcHost) > 255 {
			return nil, errors.New("invalid host length")
		}
		b = append(b, 3, byte(len(srcHost)))
		b = append(b, srcHost...)
	}
	b = append(b, byte(srcPort>>8), byte(srcPort))
	b = append(b, payload...)
	return b, nil
}

func handleSocks5UDPAssociate(c net.Conn, dialUDP DialUDPFunc) {
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		socksReply(c, 0x01)
		return
	}
	defer udpListener.Close()

	laddr := udpListener.LocalAddr().(*net.UDPAddr)
	bndIP := laddr.IP.To4()
	if bndIP == nil {
		bndIP = laddr.IP.To16()
	}

	reply := []byte{5, 0, 0, 1}
	reply = append(reply, bndIP...)
	reply = append(reply, byte(laddr.Port>>8), byte(laddr.Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := dialUDP(ctx)
	if err != nil {
		log.Printf("socks5 udp associate dial: %v", err)
		return
	}
	defer sess.Close()

	c.SetDeadline(time.Time{})

	var clientAddrMu sync.Mutex
	var clientAddr *net.UDPAddr

	// Goroutine watching TCP control connection: when TCP closes, cancel context.
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := c.Read(buf)
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Server -> Client forwarding
	go func() {
		for {
			srcHost, srcPort, payload, err := sess.ReceiveUDP(ctx)
			if err != nil {
				cancel()
				return
			}
			clientAddrMu.Lock()
			targetAddr := clientAddr
			clientAddrMu.Unlock()

			if targetAddr == nil {
				continue
			}

			hdr, err := buildSocks5UDPHeader(srcHost, srcPort, payload)
			if err != nil {
				continue
			}
			udpListener.WriteToUDP(hdr, targetAddr)
		}
	}()

	// Client -> Server forwarding
	buf := make([]byte, 65535)
	for {
		udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := udpListener.ReadFromUDP(buf)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		clientAddrMu.Lock()
		clientAddr = addr
		clientAddrMu.Unlock()

		dstHost, dstPort, payload, err := parseSocks5UDPHeader(buf[:n])
		if err != nil {
			continue
		}

		if err := sess.SendUDP(dstHost, dstPort, payload); err != nil {
			log.Printf("socks5 udp send: %v", err)
		}
	}
}

func httpError(c net.Conn, code int, msg string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, msg)
}

func hostPort(hostport, defPort string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		h, p = hostport, defPort
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || h == "" {
		return "", 0, errors.New("bad host")
	}
	return h, uint16(n), nil
}

func handleHTTP(c net.Conn, br *bufio.Reader, dial DialFunc) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		host, port, err := hostPort(req.Host, "443")
		if err != nil {
			httpError(c, 400, "Bad Request")
			return
		}
		st, err := dial(host, port)
		if err != nil {
			log.Printf("connect %s:%d: %v", host, port, err)
			httpError(c, 502, "Bad Gateway")
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		c.SetDeadline(time.Time{})
		wire.Relay(wire.NewConnStream(c, br), st)
		return
	}
	// обычный http://host/path
	if req.URL.Host == "" {
		httpError(c, 400, "Bad Request")
		return
	}
	host, port, err := hostPort(req.URL.Host, "80")
	if err != nil {
		httpError(c, 400, "Bad Request")
		return
	}
	st, err := dial(host, port)
	if err != nil {
		log.Printf("http %s:%d: %v", host, port, err)
		httpError(c, 502, "Bad Gateway")
		return
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Set("Connection", "close")
	req.RequestURI = ""
	if err := req.Write(st); err != nil {
		st.Close()
		return
	}
	c.SetDeadline(time.Time{})
	wire.Relay(wire.NewConnStream(c, br), st)
}
