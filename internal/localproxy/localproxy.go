// Package localproxy — локальный слушатель: SOCKS5 (CONNECT) и HTTP-прокси
// (CONNECT + обычные http://) на одном порту, определяется по первому байту.
package localproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"mschapv3proxy/internal/wire"
)

type DialFunc func(host string, port uint16) (wire.Stream, error)

// Serve принимает соединения до закрытия ln.
func Serve(ln net.Listener, dial DialFunc) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(c, dial)
	}
}

func handle(c net.Conn, dial DialFunc) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 5 {
		handleSocks5(c, br, dial)
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

func handleSocks5(c net.Conn, br *bufio.Reader, dial DialFunc) {
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
	if r[1] != 1 { // только CONNECT
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
