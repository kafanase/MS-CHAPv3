// Package wire — протокол прокси поверх MS-CHAPv3.
//
// Один проксируемый TCP-поток = одно соединение с сервером:
//
//	C→S  [frame] ClientFirst   "M3\x01" | user | cnonce | cpub(X25519)
//	S→C  [frame] ServerFirst   salt | iter | nonce | spub(X25519)
//	C→S  [frame] ClientFinal   nonce | proof
//	C→S  (stream) Request      cmd=1 | atyp | addr | port      ← конвейером
//	S→C  [frame] ServerFinal   signature
//	S→C  (stream) Status       1 байт (0 = OK)
//	     ... двусторонний поток данных ...
//
// frame  = u16 длина + данные. Поля внутри = u16 длина + данные.
// stream = TLS-соединение как есть, либо (если TLS выключен) AEAD-слой
// AES-256-GCM с раздельными ключами направлений и счётчиками nonce.
//
// В AuthMessage (а значит и в Proof/ServerSignature/SessionKey) входят
// channel binding от TLS и обе эфемерные публичные ключа: подмена любого
// из них ломает аутентификацию.
package wire

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"mschapv3proxy/mschapv3"
)

const (
	maxHSFrame = 2048
	maxChunk   = 16384
)

var magic = []byte{'M', '3', 0x01}

var (
	// ErrNotProtocol — первые байты не похожи на наш протокол (пробинг,
	// браузер и т.п.); соединение можно отдать на fallback.
	ErrNotProtocol = errors.New("wire: not a mschapv3 proxy stream")
	ErrMalformed   = errors.New("wire: malformed message")
	ErrAuth        = errors.New("wire: authentication failed")
)

// Коды команд запроса.
const (
	CmdConnect byte = 1
	CmdUDP     byte = 3
)

// Коды статуса ответа сервера на запрос соединения.
const (
	StatusOK          byte = 0
	StatusFail        byte = 1
	StatusNotAllowed  byte = 2
	StatusHostUnreach byte = 3
	StatusRefused     byte = 4
)

type StatusError struct{ Code byte }

func (e *StatusError) Error() string {
	switch e.Code {
	case StatusNotAllowed:
		return "target not allowed by server"
	case StatusHostUnreach:
		return "host unreachable"
	case StatusRefused:
		return "connection refused"
	}
	return fmt.Sprintf("server error (code %d)", e.Code)
}

// ---------- Stream ----------

type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type connStream struct {
	net.Conn
	r io.Reader
}

// NewConnStream оборачивает net.Conn; r — источник чтения (например, bufio.Reader,
// уже прочитавший часть данных).
func NewConnStream(c net.Conn, r io.Reader) Stream { return &connStream{Conn: c, r: r} }

func (s *connStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *connStream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return s.Conn.Close()
}

// Relay гоняет данные в обе стороны с корректным half-close и закрывает оба потока.
func Relay(a, b Stream) {
	var wg sync.WaitGroup
	cp := func(dst, src Stream) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			src.Close()
			return
		}
		dst.CloseWrite()
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// ---------- кодирование ----------

func putField(b, f []byte) []byte {
	b = append(b, byte(len(f)>>8), byte(len(f)))
	return append(b, f...)
}

func getFields(b []byte, n int) ([][]byte, error) {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 2 {
			return nil, ErrMalformed
		}
		l := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+l {
			return nil, ErrMalformed
		}
		out = append(out, b[2:2+l])
		b = b[2+l:]
	}
	if len(b) != 0 {
		return nil, ErrMalformed
	}
	return out, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return ErrMalformed
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > max {
		return nil, ErrMalformed
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func bindingFor(tlsBinding, cpub, spub []byte) []byte {
	var b []byte
	b = putField(b, tlsBinding)
	b = putField(b, cpub)
	b = putField(b, spub)
	return b
}

// ---------- запрос на соединение ----------

func WriteRequestCmd(w io.Writer, cmd byte, host string, port uint16) error {
	b := []byte{cmd, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b[1] = 1
			b = append(b, v4...)
		} else {
			b[1] = 4
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return ErrMalformed
		}
		b[1] = 3
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	_, err := w.Write(b)
	return err
}

func WriteRequest(w io.Writer, host string, port uint16) error {
	return WriteRequestCmd(w, CmdConnect, host, port)
}

func ReadRequestCmd(r io.Reader) (cmd byte, host string, port uint16, err error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, "", 0, err
	}
	cmd = h[0]
	if cmd != CmdConnect && cmd != CmdUDP {
		return 0, "", 0, ErrMalformed
	}
	switch h[1] {
	case 1, 4:
		n := 4
		if h[1] == 4 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(ip).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return 0, "", 0, err
		}
		if l[0] == 0 {
			return 0, "", 0, ErrMalformed
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(r, d); err != nil {
			return 0, "", 0, err
		}
		host = string(d)
	default:
		return 0, "", 0, ErrMalformed
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, "", 0, err
	}
	return cmd, host, binary.BigEndian.Uint16(p[:]), nil
}

func ReadRequest(r io.Reader) (string, uint16, error) {
	_, host, port, err := ReadRequestCmd(r)
	return host, port, err
}

// EncodeUDPDatagram кодирует хост, порт и данные пакета в компактный бинарный кадр:
// [ATYP 1b][ADDR][PORT 2b][PAYLOAD...]
func EncodeUDPDatagram(host string, port uint16, payload []byte) ([]byte, error) {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, ErrMalformed
		}
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	b = append(b, payload...)
	return b, nil
}

// DecodeUDPDatagram декодирует бинарный кадр пакета в (host, port, payload).
func DecodeUDPDatagram(data []byte) (host string, port uint16, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, ErrMalformed
	}
	atyp := data[0]
	idx := 1
	switch atyp {
	case 1: // IPv4
		if len(data) < 1+4+2 {
			return "", 0, nil, ErrMalformed
		}
		host = net.IP(data[1:5]).String()
		idx = 5
	case 4: // IPv6
		if len(data) < 1+16+2 {
			return "", 0, nil, ErrMalformed
		}
		host = net.IP(data[1:17]).String()
		idx = 17
	case 3: // Domain
		if len(data) < 2 {
			return "", 0, nil, ErrMalformed
		}
		l := int(data[1])
		if l == 0 || len(data) < 2+l+2 {
			return "", 0, nil, ErrMalformed
		}
		host = string(data[2 : 2+l])
		idx = 2 + l
	default:
		return "", 0, nil, ErrMalformed
	}
	port = binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2
	payload = data[idx:]
	return host, port, payload, nil
}

// ---------- AEAD-слой (режим без TLS) ----------

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func deriveKeys(dh, sessionKey []byte) (c2s, s2c []byte) {
	prk := hmacSHA256(sessionKey, dh)
	c2s = hmacSHA256(prk, []byte("mschapv3 c2s key\x01"))
	s2c = hmacSHA256(prk, []byte("mschapv3 s2c key\x01"))
	return
}

func nonceFor(ctr uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// secureStream: фрейм = u16 длина шифртекста | AES-256-GCM(ключ направления,
// nonce = счётчик, AAD = заголовок). Пустой открытый текст = авторизованный
// «конец потока»: обрыв TCP без него считается усечением (io.ErrUnexpectedEOF).
type secureStream struct {
	conn net.Conn
	r    io.Reader
	rd   cipher.AEAD
	wr   cipher.AEAD

	rctr uint64
	rbuf []byte
	eof  bool
	rerr error
	wmu  sync.Mutex
	wctr uint64
	fin  bool
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func newSecure(conn net.Conn, r io.Reader, dh, sessionKey []byte, isClient bool) (*secureStream, error) {
	c2s, s2c := deriveKeys(dh, sessionKey)
	wk, rk := c2s, s2c
	if !isClient {
		wk, rk = s2c, c2s
	}
	w, err := newAEAD(wk)
	if err != nil {
		return nil, err
	}
	rd, err := newAEAD(rk)
	if err != nil {
		return nil, err
	}
	return &secureStream{conn: conn, r: r, rd: rd, wr: w}, nil
}

func (s *secureStream) sealLocked(pt []byte) error {
	var hdr [2]byte
	ov := s.wr.Overhead()
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pt)+ov))
	buf := append(make([]byte, 0, 2+len(pt)+ov), hdr[:]...)
	buf = s.wr.Seal(buf, nonceFor(s.wctr), pt, hdr[:])
	s.wctr++
	_, err := s.conn.Write(buf)
	return err
}

func (s *secureStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.fin {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if err := s.sealLocked(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *secureStream) readFrame() (pt []byte, fin bool, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(s.r, hdr[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF // конец без авторизованного FIN
		}
		return nil, false, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < s.rd.Overhead() || n > maxChunk+s.rd.Overhead() {
		return nil, false, ErrMalformed
	}
	ct := make([]byte, n)
	if _, err = io.ReadFull(s.r, ct); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, false, err
	}
	pt, err = s.rd.Open(nil, nonceFor(s.rctr), ct, hdr[:])
	if err != nil {
		return nil, false, ErrAuth
	}
	s.rctr++
	return pt, len(pt) == 0, nil
}

func (s *secureStream) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		if s.eof {
			return 0, io.EOF
		}
		if s.rerr != nil {
			return 0, s.rerr
		}
		pt, fin, err := s.readFrame()
		if err != nil {
			s.rerr = err
			return 0, err
		}
		if fin {
			s.eof = true
			return 0, io.EOF
		}
		s.rbuf = pt
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *secureStream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	var err error
	if !s.fin {
		s.fin = true
		err = s.sealLocked(nil)
	}
	if cw, ok := s.conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	return err
}

func (s *secureStream) Close() error {
	s.wmu.Lock()
	if !s.fin {
		s.fin = true
		s.conn.SetWriteDeadline(time.Now().Add(time.Second))
		s.sealLocked(nil)
	}
	s.wmu.Unlock()
	return s.conn.Close()
}

// ---------- клиент ----------

type ClientParams struct {
	Username, Password string
	Cache              *mschapv3.KeyCache
	TLSBinding         []byte // nil, если TLS не используется
	Encrypt            bool   // true: включить AEAD-слой (когда нет TLS)
	MinIterations      uint32 // 0 = значение по умолчанию (100k)
}

// ClientConnect выполняет handshake и запрос соединения с host:port.
// conn — уже установленное соединение (TCP или TLS).
func ClientConnect(conn net.Conn, p ClientParams, host string, port uint16) (Stream, error) {
	return ClientConnectCmd(conn, p, CmdConnect, host, port)
}

// ClientConnectCmd выполняет handshake и запрос с указанной командой (CmdConnect или CmdUDP).
func ClientConnectCmd(conn net.Conn, p ClientParams, cmd byte, host string, port uint16) (Stream, error) {
	br := bufio.NewReader(conn)
	cl := mschapv3.NewClient(p.Username, p.Password, nil)
	cl.Cache = p.Cache
	if p.MinIterations != 0 {
		cl.MinIterations = p.MinIterations
	}
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cpub := priv.PublicKey().Bytes()

	cf, err := cl.First()
	if err != nil {
		return nil, err
	}
	msg := append([]byte(nil), magic...)
	msg = putField(msg, []byte(cf.Username))
	msg = putField(msg, cf.ClientNonce)
	msg = putField(msg, cpub)
	if err := writeFrame(conn, msg); err != nil {
		return nil, err
	}

	raw, err := readFrame(br, maxHSFrame)
	if err != nil {
		return nil, fmt.Errorf("server-first: %w", err)
	}
	f, err := getFields(raw, 4)
	if err != nil || len(f[1]) != 4 {
		return nil, ErrMalformed
	}
	spubKey, err := curve.NewPublicKey(f[3])
	if err != nil {
		return nil, ErrMalformed
	}
	cl.Binding = bindingFor(p.TLSBinding, cpub, f[3])
	fin, err := cl.Final(mschapv3.ServerFirst{Salt: f[0], Iterations: binary.BigEndian.Uint32(f[1]), Nonce: f[2]})
	if err != nil {
		return nil, err
	}
	out := putField(nil, fin.Nonce)
	out = putField(out, fin.Proof)
	if err := writeFrame(conn, out); err != nil {
		return nil, err
	}

	var st Stream = NewConnStream(conn, br)
	if p.Encrypt {
		dh, err := priv.ECDH(spubKey)
		if err != nil {
			return nil, err
		}
		prov, err := cl.ProvisionalSessionKey()
		if err != nil {
			return nil, err
		}
		if st, err = newSecure(conn, br, dh, prov, true); err != nil {
			return nil, err
		}
	}
	// Запрос уходит сразу, не дожидаясь ответа сервера (экономия RTT).
	if err := WriteRequestCmd(st, cmd, host, port); err != nil {
		return nil, err
	}

	raw, err = readFrame(br, maxHSFrame)
	if err != nil {
		return nil, fmt.Errorf("%w (server closed connection)", ErrAuth)
	}
	g, err := getFields(raw, 1)
	if err != nil {
		return nil, err
	}
	if _, err := cl.Verify(mschapv3.ServerFinal{Signature: g[0]}); err != nil {
		return nil, fmt.Errorf("server authentication failed: %w", err)
	}
	var status [1]byte
	if _, err := io.ReadFull(st, status[:]); err != nil {
		return nil, err
	}
	if status[0] != StatusOK {
		return nil, &StatusError{Code: status[0]}
	}
	return st, nil
}

// ---------- сервер ----------

type ServerParams struct {
	Auth       *mschapv3.Server
	TLSBinding []byte
	Encrypt    bool
}

type Session struct {
	Stream Stream
	Cmd    byte
	User   string
	Host   string
	Port   uint16
}

// ServerAccept выполняет серверную часть handshake и читает запрос.
// br — bufio.Reader над conn. При ErrNotProtocol из br ничего не потреблено,
// и соединение можно целиком передать на fallback.
// user заполняется, как только он известен (для логов/ограничения попыток).
func ServerAccept(conn net.Conn, br *bufio.Reader, p ServerParams) (sess *Session, user string, err error) {
	hdr, err := br.Peek(2 + len(magic))
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(hdr[2:], magic) || int(binary.BigEndian.Uint16(hdr)) > maxHSFrame {
		return nil, "", ErrNotProtocol
	}
	raw, err := readFrame(br, maxHSFrame)
	if err != nil {
		return nil, "", err
	}
	f, err := getFields(raw[len(magic):], 3)
	if err != nil {
		return nil, "", ErrMalformed
	}
	user = string(f[0])
	curve := ecdh.X25519()
	cpubKey, err := curve.NewPublicKey(f[2])
	if err != nil {
		return nil, user, ErrMalformed
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, user, err
	}
	spub := priv.PublicKey().Bytes()

	ms, sf, err := p.Auth.Start(mschapv3.ClientFirst{Username: user, ClientNonce: f[1]}, bindingFor(p.TLSBinding, f[2], spub))
	if err != nil {
		return nil, user, err
	}
	var it [4]byte
	binary.BigEndian.PutUint32(it[:], sf.Iterations)
	out := putField(nil, sf.Salt)
	out = putField(out, it[:])
	out = putField(out, sf.Nonce)
	out = putField(out, spub)
	if err := writeFrame(conn, out); err != nil {
		return nil, user, err
	}

	raw, err = readFrame(br, maxHSFrame)
	if err != nil {
		return nil, user, err
	}
	g, err := getFields(raw, 2)
	if err != nil {
		return nil, user, ErrMalformed
	}
	sfin, sk, err := ms.Finish(mschapv3.ClientFinal{Nonce: g[0], Proof: g[1]})
	if err != nil {
		return nil, user, err
	}
	if err := writeFrame(conn, putField(nil, sfin.Signature)); err != nil {
		return nil, user, err
	}

	var st Stream = NewConnStream(conn, br)
	if p.Encrypt {
		dh, err := priv.ECDH(cpubKey)
		if err != nil {
			return nil, user, err
		}
		if st, err = newSecure(conn, br, dh, sk, false); err != nil {
			return nil, user, err
		}
	}
	cmd, host, port, err := ReadRequestCmd(st)
	if err != nil {
		return nil, user, err
	}
	return &Session{Stream: st, Cmd: cmd, User: user, Host: host, Port: port}, user, nil
}
