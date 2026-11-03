// SPDX-License-Identifier: LGPL-3.0-or-later

package moshc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpillora/sshd-lite/mosh"
	"github.com/jpillora/sshd-lite/sshd"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
)

func TestServerCommand(t *testing.T) {
	if got := ServerCommand(Server{}); got != "'mosh-server' new -s -c 256 -l LANG=C.UTF-8" {
		t.Errorf("default = %q", got)
	}
	got := ServerCommand(Server{Path: "/opt/mosh server", Command: []string{"tmux", "new", "-s", "it's"}})
	if want := `'/opt/mosh server' new -s -c 256 -l LANG=C.UTF-8 -- 'tmux' 'new' '-s' 'it'\''s'`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseConnect(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAA"
	port, k, err := ParseConnect("Welcome to remote-02\r\n\r\nMOSH CONNECT 60001 " + key + "\r\n\nmosh-server (mosh 1.3.2)\n")
	if err != nil || port != 60001 || k != key {
		t.Errorf("ParseConnect = %d %q %v", port, k, err)
	}
	for name, out := range map[string]string{
		"none":       "mosh-server: command not found\n",
		"twice":      "MOSH CONNECT 1 " + key + "\nMOSH CONNECT 2 " + key + "\n",
		"short key":  "MOSH CONNECT 60001 AAAA\n",
		"padded key": "MOSH CONNECT 60001 " + key + "==\n",
		"bad port":   "MOSH CONNECT 0 " + key + "\n",
		"big port":   "MOSH CONNECT 70000 " + key + "\n",
		"extra":      "MOSH CONNECT 60001 " + key + " x\n",
	} {
		if _, _, err := ParseConnect(out); err == nil {
			t.Errorf("%s: accepted %q", name, out)
		}
	}
	if _, _, err := ParseConnect("bash: mosh-server: command not found"); err == nil || !strings.Contains(err.Error(), "command not found") {
		t.Errorf("error should carry the output: %v", err)
	}
}

func TestEscape(t *testing.T) {
	for _, tc := range []struct {
		feeds []string
		out   string
		quit  bool
	}{
		{[]string{"ls\r"}, "ls\r", false},
		{[]string{"a\x1e.b"}, "a", true},
		{[]string{"a\x1e", ".b"}, "a", true}, // split across reads
		{[]string{"\x1e^"}, "\x1e", false},
		{[]string{"\x1ex"}, "\x1ex", false},
		{[]string{"\x1e\x1e."}, "\x1e.", false},           // Ctrl-^ Ctrl-^ is a literal Ctrl-^
		{[]string{"\x1e", "\x1e", "\x1e."}, "\x1e", true}, // then a fresh escape quits
	} {
		var e Escape
		var out []byte
		quit := false
		for _, f := range tc.feeds {
			o, q := e.Feed([]byte(f))
			out = append(out, o...)
			if q {
				quit = true
				break
			}
		}
		if string(out) != tc.out || quit != tc.quit {
			t.Errorf("Feed(%q) = %q, %v; want %q, %v", tc.feeds, out, quit, tc.out, tc.quit)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// The applet's path against sshd-lite's own mosh server: bootstrap over an
// SSH client, then the session on a datagram conn the caller dialed.
func TestBootstrapConnect(t *testing.T) {
	key := func() (ed25519.PrivateKey, ssh.Signer) {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(k)
		return k, s
	}
	hk, hs := key()
	_, us := key()
	b, _ := ssh.MarshalPrivateKey(hk, "")
	srv, err := sshd.NewServer(sshd.Config{Attach: mosh.Attach, KeyBytes: pem.EncodeToMemory(b), AuthKeys: []ssh.PublicKey{us.PublicKey()},
		Shell: "/bin/sh", WorkDir: t.TempDir(), NoInheritEnv: true, NoGlobalEnv: true, LogQuiet: true})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.StartWithContext(sctx, ln) }()
	defer func() { scancel(); <-done }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := sshc.Client(ctx, conn, "h:22", &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: ssh.FixedHostKey(hs.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	port, mkey, err := Bootstrap(ctx, c, Server{Columns: 80, Rows: 24})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	s, err := mosh.Connect(ctx, udp, mkey, mosh.ClientConfig{Columns: 80, Rows: 24, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Write([]byte("echo MOSH_$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "MOSH_42") {
		if time.Now().After(deadline) {
			t.Fatalf("no output: %q", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
