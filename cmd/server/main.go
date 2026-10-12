// mschapv3-server — прокси-сервер с аутентификацией MS-CHAPv3 (Linux).
//
//	mschapv3-server -genconfig                 создать config.json
//	mschapv3-server -gencert example.com       self-signed сертификат (+ отпечаток для клиента)
//	mschapv3-server -adduser alice             добавить пользователя (пароль сгенерируется)
//	mschapv3-server -deluser alice
//	mschapv3-server -c config.json             запуск (SIGHUP — перечитать пользователей)
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mschapv3proxy/internal/wire"
	"mschapv3proxy/mschapv3"
)

// ---------- конфигурация ----------

type UserEntry struct {
	Username   string `json:"username"`
	Salt       string `json:"salt"`
	Iterations uint32 `json:"iterations"`
	StoredKey  string `json:"stored_key"`
	ServerKey  string `json:"server_key"`
}

type Config struct {
	Listen string `json:"listen"`
	TLS    struct {
		Enabled bool   `json:"enabled"`
		Cert    string `json:"cert"`
		Key     string `json:"key"`
	} `json:"tls"`
	// Fallback: куда отправлять соединения, не похожие на наш протокол
	// (браузеры, сканеры). Например "127.0.0.1:8080" с обычным сайтом.
	Fallback       string      `json:"fallback"`
	KDFIterations  uint32      `json:"kdf_iterations"`
	AllowPrivate   bool        `json:"allow_private_targets"`
	ConnectTimeout int         `json:"connect_timeout_sec"`
	LogTargets     bool        `json:"log_targets"`
	Secret         string      `json:"secret"` // base64, ≥32 байт; для фиктивных профилей несуществующих пользователей
	Users          []UserEntry `json:"users"`
}

func defaultConfig() *Config {
	c := &Config{Listen: "0.0.0.0:8443", KDFIterations: mschapv3.DefaultIterations, ConnectTimeout: 10}
	c.TLS.Enabled = true
	c.TLS.Cert = "cert.pem"
	c.TLS.Key = "key.pem"
	return c
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := defaultConfig()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.KDFIterations == 0 {
		c.KDFIterations = mschapv3.DefaultIterations
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 10
	}
	return c, nil
}

func saveConfig(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ensureSecret(c *Config) {
	if b, err := base64.StdEncoding.DecodeString(c.Secret); err == nil && len(b) >= 32 {
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	c.Secret = base64.StdEncoding.EncodeToString(b)
}

// ---------- управление пользователями ----------

func cmdGenConfig(path string) {
	if _, err := os.Stat(path); err == nil {
		log.Fatalf("%s already exists", path)
	}
	c := defaultConfig()
	ensureSecret(c)
	c.Users = []UserEntry{}
	if err := saveConfig(path, c); err != nil {
		log.Fatal(err)
	}
	fmt.Println("created", path)
}

func cmdAddUser(path, name, pass string) {
	cfg, err := loadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg, err = defaultConfig(), nil
	}
	if err != nil {
		log.Fatal(err)
	}
	generated := false
	if pass == "" {
		b := make([]byte, 16)
		rand.Read(b)
		pass = base64.RawURLEncoding.EncodeToString(b)
		generated = true
	} else if len(pass) < 8 {
		log.Fatal("password must be at least 8 characters")
	}
	cred, err := mschapv3.NewCredential(name, pass, cfg.KDFIterations)
	if err != nil {
		log.Fatal(err)
	}
	e := UserEntry{
		Username: name, Iterations: cred.Iterations,
		Salt:      base64.StdEncoding.EncodeToString(cred.Salt),
		StoredKey: base64.StdEncoding.EncodeToString(cred.StoredKey),
		ServerKey: base64.StdEncoding.EncodeToString(cred.ServerKey),
	}
	replaced := false
	for i := range cfg.Users {
		if cfg.Users[i].Username == name {
			cfg.Users[i], replaced = e, true
		}
	}
	if !replaced {
		cfg.Users = append(cfg.Users, e)
	}
	ensureSecret(cfg)
	if err := saveConfig(path, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user %q saved in %s (send SIGHUP or restart the server)\n", name, path)
	if generated {
		fmt.Printf("password (shown once): %s\n", pass)
	}
}

func cmdDelUser(path, name string) {
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	out := cfg.Users[:0]
	for _, u := range cfg.Users {
		if u.Username != name {
			out = append(out, u)
		}
	}
	if len(out) == len(cfg.Users) {
		log.Fatalf("user %q not found", name)
	}
	cfg.Users = out
	if err := saveConfig(path, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user %q removed\n", name)
}

func cmdGenCert(host string, cfg *Config) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(cfg.TLS.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(cfg.TLS.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(der)
	fmt.Printf("written %s, %s\nclient config: \"pin_sha256\": \"%s\"\n", cfg.TLS.Cert, cfg.TLS.Key, hex.EncodeToString(sum[:]))
}

// ---------- защита от перебора ----------

type failRec struct {
	n     int
	first time.Time
}

type failTracker struct {
	mu sync.Mutex
	m  map[string]*failRec
}

const (
	failLimit  = 10
	failWindow = 5 * time.Minute
)

func (t *failTracker) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.m[ip]
	return r != nil && r.n >= failLimit && time.Since(r.first) < failWindow
}

func (t *failTracker) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.m[ip]
	if r == nil || time.Since(r.first) >= failWindow {
		r = &failRec{first: time.Now()}
		t.m[ip] = r
	}
	r.n++
}

func (t *failTracker) gc() {
	for range time.Tick(time.Minute) {
		t.mu.Lock()
		for k, r := range t.m {
			if time.Since(r.first) >= failWindow {
				delete(t.m, k)
			}
		}
		t.mu.Unlock()
	}
}

// ---------- сервер ----------

type server struct {
	cfg    *Config
	tlsCfg *tls.Config
	auth   *mschapv3.Server
	users  atomic.Pointer[map[string]*mschapv3.Credential]
	ft     *failTracker
}

func decodeUsers(cfg *Config) (map[string]*mschapv3.Credential, error) {
	m := make(map[string]*mschapv3.Credential, len(cfg.Users))
	for _, u := range cfg.Users {
		salt, e1 := base64.StdEncoding.DecodeString(u.Salt)
		sk, e2 := base64.StdEncoding.DecodeString(u.StoredKey)
		srv, e3 := base64.StdEncoding.DecodeString(u.ServerKey)
		if e1 != nil || e2 != nil || e3 != nil || len(sk) != mschapv3.KeySize || len(srv) != mschapv3.KeySize || u.Iterations == 0 {
			return nil, fmt.Errorf("user %q: invalid credential record", u.Username)
		}
		m[u.Username] = &mschapv3.Credential{Username: u.Username, Salt: salt, Iterations: u.Iterations, StoredKey: sk, ServerKey: srv}
	}
	return m, nil
}

func isBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if ip4[0] == 100 && ip4[1]&0xC0 == 64 { // 100.64.0.0/10 CGNAT
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func (s *server) dialTarget(host string, port uint16) (net.Conn, byte) {
	timeout := time.Duration(s.cfg.ConnectTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, wire.StatusHostUnreach
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	var allowed []net.IP
	for _, ip := range ips {
		if s.cfg.AllowPrivate || !isBlockedIP(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, wire.StatusNotAllowed
	}
	code := wire.StatusFail
	var d net.Dialer
	for _, ip := range allowed {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(port)))
		if err == nil {
			return c, wire.StatusOK
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			code = wire.StatusRefused
		}
	}
	return nil, code
}

func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if s.ft.blocked(ip) {
		return
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	var nc net.Conn = conn
	var binding []byte
	if s.tlsCfg != nil {
		tc := tls.Server(conn, s.tlsCfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		cs := tc.ConnectionState()
		var err error
		if binding, err = cs.ExportKeyingMaterial("EXPORTER-MSCHAPV3", nil, 32); err != nil {
			return
		}
		nc = tc
	}
	br := bufio.NewReader(nc)
	sess, user, err := wire.ServerAccept(nc, br, wire.ServerParams{Auth: s.auth, TLSBinding: binding, Encrypt: s.tlsCfg == nil})
	switch {
	case errors.Is(err, wire.ErrNotProtocol):
		s.fallback(nc, br)
		return
	case errors.Is(err, mschapv3.ErrAuthFailed):
		s.ft.fail(ip)
		log.Printf("auth failed: user=%q from=%s", user, ip)
		return
	case err != nil:
		s.ft.fail(ip)
		return
	}

	tc, code := s.dialTarget(sess.Host, sess.Port)
	if code != wire.StatusOK {
		sess.Stream.Write([]byte{code})
		sess.Stream.Close()
		return
	}
	if _, err := sess.Stream.Write([]byte{wire.StatusOK}); err != nil {
		tc.Close()
		return
	}
	if s.cfg.LogTargets {
		log.Printf("user=%q from=%s -> %s:%d", sess.User, ip, sess.Host, sess.Port)
	}
	conn.SetDeadline(time.Time{})
	wire.Relay(sess.Stream, wire.NewConnStream(tc, tc))
}

func (s *server) fallback(nc net.Conn, br *bufio.Reader) {
	if s.cfg.Fallback == "" {
		return
	}
	fb, err := net.DialTimeout("tcp", s.cfg.Fallback, 5*time.Second)
	if err != nil {
		return
	}
	nc.SetDeadline(time.Time{})
	wire.Relay(wire.NewConnStream(nc, br), wire.NewConnStream(fb, fb))
}

func run(cfgPath string) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{cfg: cfg, ft: &failTracker{m: map[string]*failRec{}}}
	users, err := decodeUsers(cfg)
	if err != nil {
		log.Fatal(err)
	}
	s.users.Store(&users)
	if len(users) == 0 {
		log.Println("warning: no users configured (use -adduser)")
	}

	secret, err := base64.StdEncoding.DecodeString(cfg.Secret)
	if err != nil || len(secret) < 32 {
		log.Println("warning: config 'secret' missing; using a random one (fake-user profiles will change on restart)")
		secret = make([]byte, 32)
		rand.Read(secret)
	}
	s.auth = &mschapv3.Server{
		Lookup: func(u string) (*mschapv3.Credential, bool) {
			c, ok := (*s.users.Load())[u]
			return c, ok
		},
		Secret:         secret,
		FakeIterations: cfg.KDFIterations,
	}

	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			log.Fatalf("tls: %v (create one with -gencert HOST)", err)
		}
		s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	} else {
		log.Println("warning: TLS disabled; traffic is protected by the built-in AEAD layer only (not stealthy, username is sent in clear)")
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s (tls=%v, users=%d)", cfg.Listen, cfg.TLS.Enabled, len(users))
	go s.ft.gc()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sg := range sig {
			if sg == syscall.SIGHUP {
				nc, err := loadConfig(cfgPath)
				if err == nil {
					var m map[string]*mschapv3.Credential
					if m, err = decodeUsers(nc); err == nil {
						s.users.Store(&m)
						log.Printf("users reloaded: %d", len(m))
						continue
					}
				}
				log.Printf("reload failed: %v", err)
				continue
			}
			log.Println("shutting down")
			ln.Close()
			return
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

func main() {
	cfgPath := flag.String("c", "config.json", "path to config.json")
	genconfig := flag.Bool("genconfig", false, "create a new config.json")
	adduser := flag.String("adduser", "", "add/replace user")
	password := flag.String("password", "", "password for -adduser (random if empty; visible in shell history!)")
	deluser := flag.String("deluser", "", "remove user")
	gencert := flag.String("gencert", "", "generate self-signed cert for HOST/IP")
	flag.Parse()
	log.SetFlags(log.LstdFlags)

	switch {
	case *genconfig:
		cmdGenConfig(*cfgPath)
	case *adduser != "":
		cmdAddUser(*cfgPath, *adduser, *password)
	case *deluser != "":
		cmdDelUser(*cfgPath, *deluser)
	case *gencert != "":
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			cfg = defaultConfig()
		}
		cmdGenCert(*gencert, cfg)
	default:
		run(*cfgPath)
	}
}
