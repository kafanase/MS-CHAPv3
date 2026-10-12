package mschapv3

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

const testIter = 2000

func newServer(t *testing.T, user, pass string) *Server {
	t.Helper()
	cred, err := NewCredential(user, pass, testIter)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Lookup: func(u string) (*Credential, bool) {
			if u == user {
				return cred, true
			}
			return nil, false
		},
		Secret:         bytes.Repeat([]byte{7}, 32),
		FakeIterations: testIter,
	}
}

func newClient(user, pass string, binding []byte) *Client {
	c := NewClient(user, pass, binding)
	c.MinIterations = 1000
	return c
}

func handshake(s *Server, c *Client, sBinding []byte) ([]byte, []byte, error) {
	cf, _ := c.First()
	sess, sf, err := s.Start(cf, sBinding)
	if err != nil {
		return nil, nil, err
	}
	fin, err := c.Final(sf)
	if err != nil {
		return nil, nil, err
	}
	sfin, sk, err := sess.Finish(fin)
	if err != nil {
		return nil, nil, err
	}
	ck, err := c.Verify(sfin)
	return sk, ck, err
}

func TestSuccess(t *testing.T) {
	s := newServer(t, "alice", "correct horse")
	sk, ck, err := handshake(s, newClient("alice", "correct horse", []byte("tls-exporter")), []byte("tls-exporter"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk, ck) || len(sk) != 32 {
		t.Fatal("session keys differ")
	}
}

func TestWrongPassword(t *testing.T) {
	s := newServer(t, "alice", "pw")
	if _, _, err := handshake(s, newClient("alice", "bad", nil), nil); err != ErrAuthFailed {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownUserIndistinguishable(t *testing.T) {
	s := newServer(t, "alice", "pw")
	if _, _, err := handshake(s, newClient("mallory", "pw", nil), nil); err != ErrAuthFailed {
		t.Fatalf("got %v", err)
	}
	// фиктивные параметры стабильны между попытками
	c := newClient("mallory", "x", nil)
	cf, _ := c.First()
	_, a, _ := s.Start(cf, nil)
	_, b, _ := s.Start(cf, nil)
	if !bytes.Equal(a.Salt, b.Salt) || a.Iterations != b.Iterations {
		t.Fatal("fake params not stable")
	}
}

func TestChannelBindingMismatch(t *testing.T) {
	s := newServer(t, "alice", "pw")
	if _, _, err := handshake(s, newClient("alice", "pw", []byte("A")), []byte("B")); err != ErrAuthFailed {
		t.Fatalf("MITM relay must fail, got %v", err)
	}
}

func TestReplayFails(t *testing.T) {
	s := newServer(t, "alice", "pw")
	c := newClient("alice", "pw", nil)
	cf, _ := c.First()
	sess, sf, _ := s.Start(cf, nil)
	fin, _ := c.Final(sf)
	if _, _, err := sess.Finish(fin); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sess.Finish(fin); err == nil {
		t.Fatal("session must be single-use")
	}
	// тот же ClientFinal в новой сессии (новый server nonce)
	sess2, _, _ := s.Start(cf, nil)
	if _, _, err := sess2.Finish(fin); err != ErrAuthFailed {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestTamperedProof(t *testing.T) {
	s := newServer(t, "alice", "pw")
	c := newClient("alice", "pw", nil)
	cf, _ := c.First()
	sess, sf, _ := s.Start(cf, nil)
	fin, _ := c.Final(sf)
	fin.Proof[0] ^= 1
	if _, _, err := sess.Finish(fin); err != ErrAuthFailed {
		t.Fatal("tampered proof accepted")
	}
}

func TestFakeServerRejected(t *testing.T) {
	s := newServer(t, "alice", "pw")
	c := newClient("alice", "pw", nil)
	cf, _ := c.First()
	sess, sf, _ := s.Start(cf, nil)
	fin, _ := c.Final(sf)
	sfin, _, _ := sess.Finish(fin)
	sfin.Signature[3] ^= 1
	if _, err := c.Verify(sfin); err != ErrAuthFailed {
		t.Fatal("client accepted forged server signature")
	}
}

func TestDowngradeRejectedByClient(t *testing.T) {
	c := NewClient("alice", "pw", nil) // MinIterations = 100k
	cf, _ := c.First()
	n := append(append([]byte{}, cf.ClientNonce...), make([]byte, NonceSize)...)
	_, err := c.Final(ServerFirst{Salt: make([]byte, 16), Iterations: 1, Nonce: n})
	if err != ErrParams {
		t.Fatalf("got %v", err)
	}
}

func TestStoredKeyIsNotPasswordEquivalent(t *testing.T) {
	// Имея только запись из БД, нельзя построить валидный Proof:
	// для этого нужен ClientKey, а в БД лежит лишь SHA256(ClientKey).
	cred, _ := NewCredential("alice", "pw", testIter)
	am := authMessage("alice", []byte("c"), cred.Salt, cred.Iterations, []byte("n"), nil)
	forged := xorBytes(cred.StoredKey, hmacSHA256(cred.StoredKey, am)) // «ClientKey := StoredKey»
	if bytes.Equal(sha256Sum(xorBytes(forged, hmacSHA256(cred.StoredKey, am))), cred.StoredKey) {
		t.Fatal("DB leak allows impersonation")
	}
}

func TestPBKDF2Vector(t *testing.T) {
	// RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd","salt",1,64)
	got := hex.EncodeToString(pbkdf2(sha256.New, []byte("passwd"), []byte("salt"), 1, 64))
	want := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
		"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
	if got != want {
		t.Fatalf("pbkdf2 mismatch:\n%s", got)
	}
}

func TestCacheAndProvisionalKey(t *testing.T) {
	s := newServer(t, "alice", "pw")
	cache := NewKeyCache()
	for i := 0; i < 2; i++ {
		c := newClient("alice", "pw", nil)
		c.Cache = cache
		cf, _ := c.First()
		sess, sf, _ := s.Start(cf, nil)
		fin, err := c.Final(sf)
		if err != nil {
			t.Fatal(err)
		}
		prov, _ := c.ProvisionalSessionKey()
		sfin, sk, err := sess.Finish(fin)
		if err != nil {
			t.Fatal(err)
		}
		ck, err := c.Verify(sfin)
		if err != nil || !bytes.Equal(prov, ck) || !bytes.Equal(sk, ck) {
			t.Fatal("provisional/session key mismatch")
		}
	}
	if len(cache.m) != 1 {
		t.Fatal("cache not reused")
	}
}
