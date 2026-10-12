// Package mschapv3 — взаимная challenge-response аутентификация по паролю,
// задуманная как замена MS-CHAPv2.
//
// ВАЖНО: это не стандартизированный протокол. По конструкции он близок к
// SCRAM-SHA-256 (RFC 5802/7677). Для продакшена сначала рассмотрите
// SCRAM, OPAQUE (RFC 9807), EAP-TLS или PEAP/TTLS поверх TLS.
//
// Что исправлено относительно MS-CHAPv2:
//
//	MS-CHAPv2                               | MS-CHAPv3
//	----------------------------------------|----------------------------------------
//	NT-hash = MD4(пароль), без соли         | PBKDF2-HMAC-SHA256, соль, 600k итераций
//	NT-hash — password-equivalent: утечка   | в БД StoredKey/ServerKey: по ним нельзя
//	БД == вход от имени пользователя        | сформировать Proof (нужен ClientKey)
//	3×DES с ключами 56+56+16 бит → взлом    | только HMAC-SHA256 и SHA-256
//	NT-hash за ~сутки (chapcrack/crack.sh)  |
//	Challenge 8 байт (16 байт у peer)       | 32-байтные nonce с обеих сторон
//	SHA-1 в расчёте ответа сервера          | HMAC-SHA256, сравнение constant-time
//	Нет привязки к каналу (MITM-релей)      | опциональный channel binding (TLS exporter)
//	Раскрывает существование пользователя   | фиктивные соль/параметры для неизвестных
//	Неоднозначная сериализация              | length-prefixed кодирование AuthMessage
//	Клиент принимает любые параметры        | клиент проверяет границы итераций (downgrade)
//
// Протокол (все значения — []byte, сериализацию сообщений выбирает транспорт):
//
//	C→S  ClientFirst{Username, ClientNonce}
//	S→C  ServerFirst{Salt, Iterations, Nonce = ClientNonce||ServerNonce}
//	C→S  ClientFinal{Nonce, Proof}
//	S→C  ServerFinal{Signature}
//
//	SaltedPassword  = PBKDF2(HMAC-SHA256, password, salt, iter)
//	ClientKey       = HMAC(SaltedPassword, "MS-CHAPv3 Client Key")
//	StoredKey       = SHA256(ClientKey)
//	ServerKey       = HMAC(SaltedPassword, "MS-CHAPv3 Server Key")
//	AuthMessage     = lp(version)|lp(user)|lp(cnonce)|lp(salt)|iter|lp(nonce)|lp(binding)
//	Proof           = ClientKey XOR HMAC(StoredKey, AuthMessage)
//	ServerSignature = HMAC(ServerKey, AuthMessage)
//	SessionKey      = HMAC(ClientKey, "MS-CHAPv3 Session Key"|AuthMessage|ServerSignature)
//
// Ограничения (честно):
//   - Без TLS протокол не даёт конфиденциальности. Атакующий, укравший БД
//     и записавший хендшейк, может вычислить ClientKey (и SessionKey) —
//     как и в SCRAM. Используйте channel binding поверх TLS.
//   - Оффлайн-перебор слабого пароля по перехваченному хендшейку возможен
//     (медленный KDF лишь удорожает его). От этого защищает только PAKE
//     (OPAQUE/SRP) или туннель TLS.
//   - Rate limiting / lockout — задача вызывающего кода.
//   - Нормализация пароля (SASLprep/NFKC) не выполняется: сделайте её
//     до вызова, иначе пароли на разных платформах могут не совпасть.
package mschapv3

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
)

const (
	Version = "MS-CHAPv3"

	NonceSize = 32
	SaltSize  = 16
	KeySize   = sha256.Size

	DefaultIterations uint32 = 600_000 // OWASP 2023 для PBKDF2-HMAC-SHA256
	MaxIterations     uint32 = 10_000_000
	MinSaltSize              = 8
	MaxUsernameLen           = 255
)

var (
	// ErrAuthFailed намеренно единственная ошибка аутентификации:
	// не различаем «нет пользователя» и «неверный пароль».
	ErrAuthFailed = errors.New("mschapv3: authentication failed")
	ErrProtocol   = errors.New("mschapv3: protocol violation")
	ErrParams     = errors.New("mschapv3: unacceptable parameters")
)

// ---------- сообщения ----------

type ClientFirst struct {
	Username    string
	ClientNonce []byte
}

type ServerFirst struct {
	Salt       []byte
	Iterations uint32
	Nonce      []byte // ClientNonce || ServerNonce
}

type ClientFinal struct {
	Nonce []byte
	Proof []byte
}

type ServerFinal struct {
	Signature []byte
}

// ---------- примитивы ----------

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// pbkdf2 — RFC 8018, без внешних зависимостей (в Go ≥1.24 можно crypto/pbkdf2).
func pbkdf2(h func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var ctr [4]byte
	for i := 1; i <= blocks; i++ {
		binary.BigEndian.PutUint32(ctr[:], uint32(i))
		prf.Reset()
		prf.Write(salt)
		prf.Write(ctr[:])
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for n := 1; n < iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func saltedPassword(password string, salt []byte, iter uint32) []byte {
	return pbkdf2(sha256.New, []byte(password), salt, int(iter), KeySize)
}

func clientKeyOf(sp []byte) []byte { return hmacSHA256(sp, []byte(Version+" Client Key")) }
func serverKeyOf(sp []byte) []byte { return hmacSHA256(sp, []byte(Version+" Server Key")) }

// lp — length-prefixed поле: однозначное кодирование без инъекций разделителей.
func lp(buf []byte, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	return append(append(buf, l[:]...), field...)
}

func authMessage(user string, cnonce, salt []byte, iter uint32, nonce, binding []byte) []byte {
	var b []byte
	b = lp(b, []byte(Version))
	b = lp(b, []byte(user))
	b = lp(b, cnonce)
	b = lp(b, salt)
	var it [4]byte
	binary.BigEndian.PutUint32(it[:], iter)
	b = append(b, it[:]...)
	b = lp(b, nonce)
	b = lp(b, binding)
	return b
}

func sessionKey(clientKey, authMsg, serverSig []byte) []byte {
	return hmacSHA256(clientKey, []byte(Version+" Session Key"), authMsg, serverSig)
}

// ---------- учётные данные на сервере ----------

// Credential — то, что хранится в БД. Пароля и ClientKey здесь нет.
type Credential struct {
	Username   string
	Salt       []byte
	Iterations uint32
	StoredKey  []byte
	ServerKey  []byte
}

// NewCredential создаёт запись при регистрации / смене пароля.
func NewCredential(username, password string, iterations uint32) (*Credential, error) {
	if username == "" || len(username) > MaxUsernameLen {
		return nil, ErrParams
	}
	if iterations == 0 {
		iterations = DefaultIterations
	}
	if iterations > MaxIterations {
		return nil, ErrParams
	}
	salt, err := randomBytes(SaltSize)
	if err != nil {
		return nil, err
	}
	sp := saltedPassword(password, salt, iterations)
	return &Credential{
		Username:   username,
		Salt:       salt,
		Iterations: iterations,
		StoredKey:  sha256Sum(clientKeyOf(sp)),
		ServerKey:  serverKeyOf(sp),
	}, nil
}

// ---------- сервер ----------

type LookupFunc func(username string) (*Credential, bool)

type Server struct {
	Lookup LookupFunc
	// Secret (≥32 байт, постоянный) — для детерминированных фиктивных
	// параметров неизвестных пользователей (защита от user enumeration).
	Secret []byte
	// Iterations для фиктивных пользователей; должно совпадать с обычным.
	FakeIterations uint32
}

type ServerSession struct {
	cred    *Credential
	fake    bool
	cnonce  []byte
	nonce   []byte
	binding []byte
	user    string
	used    bool
}

// Start обрабатывает ClientFirst. binding — channel binding данные
// (например, tls.ConnectionState.ExportKeyingMaterial), либо nil.
func (s *Server) Start(cf ClientFirst, binding []byte) (*ServerSession, ServerFirst, error) {
	if len(s.Secret) < 32 {
		return nil, ServerFirst{}, fmt.Errorf("%w: Secret too short", ErrParams)
	}
	if len(cf.ClientNonce) != NonceSize || cf.Username == "" || len(cf.Username) > MaxUsernameLen {
		return nil, ServerFirst{}, ErrProtocol
	}
	cred, ok := s.Lookup(cf.Username)
	fake := !ok || cred == nil
	if fake {
		it := s.FakeIterations
		if it == 0 {
			it = DefaultIterations
		}
		cred = &Credential{
			Username:   cf.Username,
			Salt:       hmacSHA256(s.Secret, []byte("fake salt"), []byte(cf.Username))[:SaltSize],
			Iterations: it,
			StoredKey:  hmacSHA256(s.Secret, []byte("fake stored"), []byte(cf.Username)),
			ServerKey:  hmacSHA256(s.Secret, []byte("fake server"), []byte(cf.Username)),
		}
	}
	snonce, err := randomBytes(NonceSize)
	if err != nil {
		return nil, ServerFirst{}, err
	}
	nonce := append(append([]byte(nil), cf.ClientNonce...), snonce...)
	sess := &ServerSession{
		cred: cred, fake: fake, cnonce: cf.ClientNonce,
		nonce: nonce, binding: binding, user: cf.Username,
	}
	return sess, ServerFirst{Salt: cred.Salt, Iterations: cred.Iterations, Nonce: nonce}, nil
}

// Finish проверяет доказательство клиента. Сессия одноразовая.
// Возвращает подпись сервера (для взаимной аутентификации) и session key.
func (ss *ServerSession) Finish(cf ClientFinal) (ServerFinal, []byte, error) {
	if ss.used {
		return ServerFinal{}, nil, ErrProtocol
	}
	ss.used = true

	if len(cf.Proof) != KeySize {
		return ServerFinal{}, nil, ErrAuthFailed
	}
	nonceOK := subtle.ConstantTimeCompare(cf.Nonce, ss.nonce)

	am := authMessage(ss.user, ss.cnonce, ss.cred.Salt, ss.cred.Iterations, ss.nonce, ss.binding)
	clientSig := hmacSHA256(ss.cred.StoredKey, am)
	clientKey := xorBytes(cf.Proof, clientSig)
	keyOK := subtle.ConstantTimeCompare(sha256Sum(clientKey), ss.cred.StoredKey)

	fakeOK := 1
	if ss.fake {
		fakeOK = 0
	}
	if nonceOK&keyOK&fakeOK != 1 {
		return ServerFinal{}, nil, ErrAuthFailed
	}
	sig := hmacSHA256(ss.cred.ServerKey, am)
	return ServerFinal{Signature: sig}, sessionKey(clientKey, am, sig), nil
}

// ---------- клиент ----------

type Client struct {
	Username string
	Password string
	Binding  []byte // тот же channel binding, что на сервере

	// Границы допустимых параметров от сервера (защита от downgrade/DoS).
	MinIterations uint32
	MaxIterations uint32

	// Cache (необязателен) хранит результат PBKDF2 между соединениями,
	// чтобы дорогой KDF считался один раз на (пароль, соль, iter).
	Cache *KeyCache

	cnonce    []byte
	authMsg   []byte
	clientKey []byte
	serverKey []byte
	state     int
}

func NewClient(username, password string, binding []byte) *Client {
	return &Client{
		Username: username, Password: password, Binding: binding,
		MinIterations: 100_000, MaxIterations: MaxIterations,
	}
}

func (c *Client) First() (ClientFirst, error) {
	if c.state != 0 {
		return ClientFirst{}, ErrProtocol
	}
	n, err := randomBytes(NonceSize)
	if err != nil {
		return ClientFirst{}, err
	}
	c.cnonce, c.state = n, 1
	return ClientFirst{Username: c.Username, ClientNonce: n}, nil
}

func (c *Client) Final(sf ServerFirst) (ClientFinal, error) {
	if c.state != 1 {
		return ClientFinal{}, ErrProtocol
	}
	c.state = 2
	if len(sf.Nonce) != 2*NonceSize || subtle.ConstantTimeCompare(sf.Nonce[:NonceSize], c.cnonce) != 1 {
		return ClientFinal{}, ErrProtocol
	}
	if len(sf.Salt) < MinSaltSize || sf.Iterations < c.MinIterations || sf.Iterations > c.MaxIterations {
		return ClientFinal{}, ErrParams
	}
	var ck, srvk []byte
	if c.Cache != nil {
		ck, srvk = c.Cache.derive(c.Password, sf.Salt, sf.Iterations)
	} else {
		sp := saltedPassword(c.Password, sf.Salt, sf.Iterations)
		ck, srvk = clientKeyOf(sp), serverKeyOf(sp)
	}
	stored := sha256Sum(ck)
	am := authMessage(c.Username, c.cnonce, sf.Salt, sf.Iterations, sf.Nonce, c.Binding)

	c.authMsg, c.clientKey, c.serverKey = am, ck, srvk
	c.state = 3
	return ClientFinal{Nonce: sf.Nonce, Proof: xorBytes(ck, hmacSHA256(stored, am))}, nil
}

// Verify проверяет подпись сервера (взаимная аутентификация) и возвращает session key.
func (c *Client) Verify(sf ServerFinal) ([]byte, error) {
	if c.state != 3 {
		return nil, ErrProtocol
	}
	c.state = 4
	want := hmacSHA256(c.serverKey, c.authMsg)
	if !hmac.Equal(want, sf.Signature) {
		return nil, ErrAuthFailed
	}
	return sessionKey(c.clientKey, c.authMsg, want), nil
}

// ProvisionalSessionKey возвращает ожидаемый session key сразу после Final,
// не дожидаясь ServerFinal. Это позволяет отправить первые данные
// (конвейеризация, экономия одного RTT). Взаимная аутентификация считается
// состоявшейся только после успешного Verify.
func (c *Client) ProvisionalSessionKey() ([]byte, error) {
	if c.state != 3 {
		return nil, ErrProtocol
	}
	return sessionKey(c.clientKey, c.authMsg, hmacSHA256(c.serverKey, c.authMsg)), nil
}

// KeyCache кэширует производные ключи клиента. Потокобезопасен.
type KeyCache struct {
	mu sync.Mutex
	m  map[[32]byte][2][]byte
}

func NewKeyCache() *KeyCache { return &KeyCache{m: make(map[[32]byte][2][]byte)} }

func (kc *KeyCache) derive(password string, salt []byte, iter uint32) (clientKey, serverKey []byte) {
	var it [4]byte
	binary.BigEndian.PutUint32(it[:], iter)
	var idx []byte
	idx = lp(idx, []byte(Version+" cache"))
	idx = lp(idx, []byte(password))
	idx = lp(idx, salt)
	idx = append(idx, it[:]...)
	key := sha256.Sum256(idx)

	// Под замком: параллельные первые соединения не дублируют работу.
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if v, ok := kc.m[key]; ok {
		return v[0], v[1]
	}
	sp := saltedPassword(password, salt, iter)
	v := [2][]byte{clientKeyOf(sp), serverKeyOf(sp)}
	if len(kc.m) >= 16 { // злой сервер не должен раздувать память
		kc.m = make(map[[32]byte][2][]byte)
	}
	kc.m[key] = v
	return v[0], v[1]
}
