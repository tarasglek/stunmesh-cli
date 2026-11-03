// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jpillora/sshd-lite/sshd"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newKey(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, s
}

func pemKey(t *testing.T, k ed25519.PrivateKey, pass string) []byte {
	t.Helper()
	var b *pem.Block
	var err error
	if pass == "" {
		b, err = ssh.MarshalPrivateKey(k, "")
	} else {
		b, err = ssh.MarshalPrivateKeyWithPassphrase(k, "", []byte(pass))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(b)
}

// server is an in-process sshd-lite with TCP forwarding, authorizing user.
type server struct {
	addr string
	host ssh.PublicKey
}

func startServer(t *testing.T, user ssh.PublicKey) server {
	t.Helper()
	hk, hs := newKey(t)
	srv, err := sshd.NewServer(sshd.Config{
		KeyBytes: pemKey(t, hk, ""), AuthKeys: []ssh.PublicKey{user}, Shell: "/bin/sh",
		WorkDir: t.TempDir(), NoInheritEnv: true, NoGlobalEnv: true, LogQuiet: true, TCPForwarding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.StartWithContext(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return server{addr: ln.Addr().String(), host: hs.PublicKey()}
}

func knownFile(t *testing.T, host string, key ssh.PublicKey) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(f, []byte(knownhosts.Line([]string{knownhosts.Normalize(host)}, key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// dial connects to the server and runs the handshake as host "remote-01",
// the name the user typed, the way the ssh applet dials over the mesh.
func dial(t *testing.T, s server, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	t.Helper()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	return Client(context.Background(), conn, "remote-01:22", cfg)
}

func run(t *testing.T, c *ssh.Client, cmd string) string {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		t.Fatalf("%s: %v: %s", cmd, err, out)
	}
	return string(out)
}

func TestClientKnownHost(t *testing.T) {
	uk, us := newKey(t)
	s := startServer(t, us.PublicKey())
	idFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(idFile, pemKey(t, uk, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	methods, closeAuth, err := Auth{Identities: []string{idFile}}.Methods()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuth()
	hk, err := HostKeys([]string{knownFile(t, "remote-01:22", s.host)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(t, s, &ssh.ClientConfig{User: "alice", Auth: methods, HostKeyCallback: hk})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if out := run(t, c, "echo hi"); out != "hi\n" {
		t.Errorf("echo hi = %q", out)
	}
}

// Unknown hosts need confirmation, which persists them; a changed key is
// refused however confirm answers.
func TestHostKeys(t *testing.T) {
	_, us := newKey(t)
	s := startServer(t, us.PublicKey())
	cfg := func(hk ssh.HostKeyCallback) *ssh.ClientConfig {
		return &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: hk}
	}
	f := filepath.Join(t.TempDir(), "known_hosts") // not there yet

	hk, err := HostKeys([]string{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(t, s, cfg(hk)); err == nil || !strings.Contains(err.Error(), "is not known") {
		t.Fatalf("unknown host without confirm: %v", err)
	}

	asked := ""
	hk, _ = HostKeys([]string{f}, func(host string, _ ssh.PublicKey) bool { asked = host; return true })
	c, err := dial(t, s, cfg(hk))
	if err != nil || asked != "remote-01:22" {
		t.Fatalf("confirmed host: %v, asked %q", err, asked)
	}
	c.Close()
	b, _ := os.ReadFile(f)
	if !strings.HasPrefix(string(b), "|1|") || strings.Contains(string(b), "remote-01") {
		t.Errorf("known_hosts entry not hashed: %q", b)
	}
	hk, _ = HostKeys([]string{f}, nil) // now known, from the file
	if c, err := dial(t, s, cfg(hk)); err != nil {
		t.Fatalf("host added by confirm: %v", err)
	} else {
		c.Close()
	}

	_, other := newKey(t)
	hk, _ = HostKeys([]string{knownFile(t, "remote-01:22", other.PublicKey())}, func(string, ssh.PublicKey) bool { return true })
	if _, err := dial(t, s, cfg(hk)); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Errorf("changed key: %v", err)
	}
}

func TestAuthIdentities(t *testing.T) {
	dir := t.TempDir()
	k, s := newKey(t)
	enc := filepath.Join(dir, "enc")
	if err := os.WriteFile(enc, pemKey(t, k, "sekrit"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, s.PublicKey())
	login := func(a Auth) error {
		methods, closeAuth, err := a.Methods()
		if err != nil {
			return err
		}
		defer closeAuth()
		c, err := dial(t, srv, &ssh.ClientConfig{User: "u", Auth: methods, HostKeyCallback: ssh.FixedHostKey(srv.host)})
		if err == nil {
			c.Close()
		}
		return err
	}

	// The passphrase is asked for when the key is tried, not before.
	prompted := ""
	a := Auth{Identities: []string{enc}, Prompt: func(p string, echo bool) (string, error) { prompted = p; return "sekrit", nil }}
	if _, closeAuth, err := a.Methods(); err != nil || prompted != "" {
		t.Fatalf("Methods: %v, prompted %q before any connection", err, prompted)
	} else {
		closeAuth()
	}
	if err := login(a); err != nil || !strings.Contains(prompted, enc) {
		t.Errorf("encrypted identity: %v, prompt %q", err, prompted)
	}
	// With no one to ask, it fails at authentication, saying why.
	if err := login(Auth{Identities: []string{enc}}); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("encrypted identity, no prompt: %v", err)
	}
	if _, _, err := (Auth{Identities: []string{filepath.Join(dir, "nosuch")}}).Methods(); err == nil {
		t.Error("missing -i identity accepted")
	}
	// A missing default is skipped; a usable one after it still logs in.
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, pemKey(t, k, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := login(Auth{Defaults: []string{filepath.Join(dir, "nosuch"), enc, plain}}); err != nil {
		t.Errorf("defaults with a missing and an encrypted key before a usable one: %v", err)
	}
}

// An agent key the server accepts logs in without the identity files
// being read: an encrypted default key never prompts.
func TestAuthAgentFirst(t *testing.T) {
	k, s := newKey(t)
	srv := startServer(t, s.PublicKey())
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(keyring, c) }()
		}
	}()
	enc := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(enc, pemKey(t, k, "sekrit"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Auth{AgentSock: sock, Defaults: []string{enc}, Prompt: func(p string, _ bool) (string, error) {
		t.Errorf("prompted %q though the agent key was accepted", p)
		return "", io.EOF
	}}
	methods, closeAuth, err := a.Methods()
	if err != nil {
		t.Fatal(err)
	}
	defer closeAuth()
	c, err := dial(t, srv, &ssh.ClientConfig{User: "u", Auth: methods, HostKeyCallback: ssh.FixedHostKey(srv.host)})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// A peer that accepts the connection but never speaks SSH is abandoned
// when the context ends, and the connection is closed.
func TestClientCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Client(ctx, conn, "x:22", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != context.DeadlineExceeded || time.Since(start) > 2*time.Second {
		t.Fatalf("Client = %v after %v", err, time.Since(start))
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Error("connection left open")
	}
}

// A server with ecdsa and ed25519 host keys, known by its ed25519 one: the
// known type is asked for first and the host passes, where x/crypto's
// default order would take ecdsa and see a changed key.
func TestKnownAlgorithms(t *testing.T) {
	_, us := newKey(t)
	_, edSigner := newKey(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, _ := ssh.NewSignerFromKey(ec)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(ecSigner)
	cfg.AddHostKey(edSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for ch := range chans {
							_ = ch.Reject(ssh.Prohibited, "")
						}
					}()
					_ = sc.Wait()
				}
			}()
		}
	}()
	s := server{addr: ln.Addr().String()}
	known := knownFile(t, "remote-01:22", edSigner.PublicKey())
	hk, _ := HostKeys([]string{known}, nil)

	base := ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: hk}
	plain := base
	if _, err := dial(t, s, &plain); err == nil {
		t.Fatal("default algorithm order passed; the test no longer shows the problem")
	}
	algos, err := KnownAlgorithms([]string{known}, "remote-01:22", ln.Addr())
	if err != nil || len(algos) < 2 || algos[0] != ssh.KeyAlgoED25519 || !slices.Contains(algos, ssh.KeyAlgoECDSA256) {
		t.Fatalf("KnownAlgorithms = %v, %v; want ed25519 first, then the defaults", algos, err)
	}
	pref := base
	pref.HostKeyAlgorithms = algos
	c, err := dial(t, s, &pref)
	if err != nil {
		t.Fatalf("with known algorithms: %v", err)
	}
	c.Close()

	if a, err := KnownAlgorithms([]string{known}, "other:22", ln.Addr()); err != nil || a != nil {
		t.Errorf("unknown host: %v, %v", a, err)
	}
	// Reinstalled with an ecdsa key only: the defaults after the known type
	// keep it negotiable, so the user hears the key changed.
	ecOnly := &ssh.ServerConfig{NoClientAuth: true}
	ecOnly.AddHostKey(ecSigner)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		if c, err := ln2.Accept(); err == nil {
			defer c.Close()
			_, _, _, _ = ssh.NewServerConn(c, ecOnly)
		}
	}()
	rotated := base
	rotated.HostKeyAlgorithms = algos
	if _, err := dial(t, server{addr: ln2.Addr().String()}, &rotated); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Errorf("rotated host key: %v, want CHANGED", err)
	}

	rsa := algorithmsFor(ssh.KeyAlgoRSA)
	if len(rsa) != 3 || rsa[0] != ssh.KeyAlgoRSASHA512 {
		t.Errorf("rsa algorithms %v", rsa)
	}
}
