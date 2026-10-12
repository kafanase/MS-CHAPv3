package wire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"mschapv3proxy/mschapv3"
)

func authServer(t *testing.T) *mschapv3.Server {
	cred, err := mschapv3.NewCredential("alice", "secret-pass", 2000)
	if err != nil {
		t.Fatal(err)
	}
	return &mschapv3.Server{
		Lookup: func(u string) (*mschapv3.Credential, bool) {
			if u == "alice" {
				return cred, true
			}
			return nil, false
		},
		Secret:         bytes.Repeat([]byte{9}, 32),
		FakeIterations: 2000,
	}
}

// сервер: принимает одно соединение, эхо-отвечает; результат ServerAccept в канал
func runServer(t *testing.T, encrypt bool, binding []byte) (addr string, res chan error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	res = make(chan error, 1)
	auth := authServer(t)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			res <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		sess, _, err := ServerAccept(c, br, ServerParams{Auth: auth, TLSBinding: binding, Encrypt: encrypt})
		if err != nil {
			res <- err
			return
		}
		if sess.Host != "example.org" || sess.Port != 443 {
			res <- errors.New("bad request parsed")
			return
		}
		sess.Stream.Write([]byte{StatusOK})
		_, err = io.Copy(sess.Stream, sess.Stream) // эхо до FIN
		sess.Stream.CloseWrite()
		res <- err
	}()
	return ln.Addr().String(), res
}

func clientParams(pass string, enc bool, binding []byte) ClientParams {
	return ClientParams{Username: "alice", Password: pass, Cache: mschapv3.NewKeyCache(),
		TLSBinding: binding, Encrypt: enc, MinIterations: 1000}
}

func TestEchoBothModes(t *testing.T) {
	for _, enc := range []bool{false, true} {
		addr, res := runServer(t, enc, []byte("bind"))
		c, _ := net.Dial("tcp", addr)
		c.SetDeadline(time.Now().Add(10 * time.Second))
		st, err := ClientConnect(c, clientParams("secret-pass", enc, []byte("bind")), "example.org", 443)
		if err != nil {
			t.Fatalf("enc=%v: %v", enc, err)
		}
		payload := bytes.Repeat([]byte("0123456789abcdef"), 5000) // 80 КБ > одного фрейма
		go func() { st.Write(payload); st.CloseWrite() }()
		got, err := io.ReadAll(st)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("enc=%v echo mismatch: %v (%d bytes)", enc, err, len(got))
		}
		st.Close()
		if err := <-res; err != nil {
			t.Fatalf("enc=%v server: %v", enc, err)
		}
	}
}

func TestWrongPassword(t *testing.T) {
	addr, res := runServer(t, false, nil)
	c, _ := net.Dial("tcp", addr)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := ClientConnect(c, clientParams("wrong", false, nil), "example.org", 443); err == nil {
		t.Fatal("must fail")
	}
	if err := <-res; !errors.Is(err, mschapv3.ErrAuthFailed) {
		t.Fatalf("server err: %v", err)
	}
}

func TestBindingMismatch(t *testing.T) {
	addr, res := runServer(t, false, []byte("A"))
	c, _ := net.Dial("tcp", addr)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := ClientConnect(c, clientParams("secret-pass", false, []byte("B")), "example.org", 443); err == nil {
		t.Fatal("MITM relay must fail")
	}
	if err := <-res; !errors.Is(err, mschapv3.ErrAuthFailed) {
		t.Fatalf("server err: %v", err)
	}
}

func TestNotProtocolFallbackAndNoConsume(t *testing.T) {
	addr, res := runServer(t, false, nil)
	c, _ := net.Dial("tcp", addr)
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err := <-res; !errors.Is(err, ErrNotProtocol) {
		t.Fatalf("got %v", err)
	}
}

func TestTruncationDetected(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		br := bufio.NewReader(c)
		sess, _, err := ServerAccept(c, br, ServerParams{Auth: authServer(t), Encrypt: true})
		if err != nil {
			return
		}
		sess.Stream.Write([]byte{StatusOK})
		sess.Stream.Write([]byte("hello"))
		c.Close() // обрыв без авторизованного FIN
	}()
	c, _ := net.Dial("tcp", ln.Addr().String())
	c.SetDeadline(time.Now().Add(10 * time.Second))
	st, err := ClientConnect(c, clientParams("secret-pass", true, nil), "example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(st)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation not detected: %v", err)
	}
}

func TestRequestCodec(t *testing.T) {
	for _, h := range []string{"example.org", "1.2.3.4", "2001:db8::1"} {
		var b bytes.Buffer
		if err := WriteRequest(&b, h, 8080); err != nil {
			t.Fatal(err)
		}
		host, port, err := ReadRequest(&b)
		if err != nil || host != h || port != 8080 {
			t.Fatalf("%s -> %s %d %v", h, host, port, err)
		}
	}
}
