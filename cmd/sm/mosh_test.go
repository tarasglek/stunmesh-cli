// SPDX-License-Identifier: LGPL-3.0-or-later

package main

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

	"github.com/creack/pty"
	"github.com/jpillora/sshd-lite/mosh"
	"github.com/jpillora/sshd-lite/sshd"
	"github.com/tarasglek/stunmesh-cli/moshc"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
)

func TestScreenTracker(t *testing.T) {
	for _, tc := range []struct {
		writes []string
		alt    bool
	}{
		{[]string{"plain"}, false},
		{[]string{"x\x1b[?1049hvim"}, true},
		{[]string{"\x1b[?1049hvim\x1b[?1049lback"}, false},
		{[]string{"\x1b[?10", "49hsplit"}, true}, // switch split across writes
		{[]string{"\x1b[?1049h", "a", "b\x1b[?104", "9l"}, false},
	} {
		var out bytes.Buffer
		tr := &screenTracker{w: &out}
		for _, w := range tc.writes {
			if n, err := tr.Write([]byte(w)); n != len(w) || err != nil {
				t.Fatal(n, err)
			}
		}
		if tr.alternate != tc.alt {
			t.Errorf("%q: alternate = %v", tc.writes, tr.alternate)
		}
		if out.String() != strings.Join(tc.writes, "") {
			t.Errorf("%q: passed on %q", tc.writes, out.String())
		}
		tr.restore()
		if got := strings.HasSuffix(out.String(), altLeave) && !strings.HasSuffix(strings.Join(tc.writes, ""), altLeave); got != tc.alt {
			t.Errorf("%q: restore wrote leave = %v", tc.writes, got)
		}
	}
}

// Bad arguments, -L/-R/-N and a stdin that is not a terminal fail before
// the key or the network.
func TestMoshRejects(t *testing.T) {
	env := map[string]string{"config": testConfig, "HOME": t.TempDir(), "USER": "me", "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	for _, tc := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"mosh"}, 2, "no destination"},
		{[]string{"mosh", "-L", "8080:x:80", "remote-01"}, 2, "no -L, -R or -N"},
		{[]string{"mosh", "-N", "remote-01"}, 2, "no -L, -R or -N"},
		{[]string{"mosh", "remote-01"}, 1, "stdin is not a terminal"},
	} {
		code, _, errs := runEnv(env, append([]string{"sm"}, tc.args...)...)
		if code != tc.code || !strings.Contains(errs, tc.err) {
			t.Errorf("%v: %d %q, want %d and %q", tc.args, code, errs, tc.code, tc.err)
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// runMosh end to end on a pty, against sshd-lite's embedded mosh server:
// keys typed on the terminal reach the shell, Ctrl-^ . ends the session
// with status 0, and the screen output starts by putting cursor keys in
// application mode and ends by resetting the terminal's modes.
func TestRunMosh(t *testing.T) {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	_, uk, _ := ed25519.GenerateKey(rand.Reader)
	us, _ := ssh.NewSignerFromKey(uk)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshc.Client(ctx, conn, "h:22", &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: ssh.FixedHostKey(hs.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	port, key, err := moshc.Bootstrap(ctx, c, moshc.Server{Columns: 80, Rows: 24})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}

	keyboard, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer keyboard.Close()
	defer tty.Close()
	screen := &lockedBuffer{}
	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		code, err := runMosh(udp, key, tty, screen, "xterm-256color", 80, 24)
		res <- result{code, err}
	}()
	if _, err := keyboard.Write([]byte("echo MOSH_$((40+2))\r")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(screen.String(), "MOSH_42") {
		if time.Now().After(deadline) {
			t.Fatalf("no output on the screen: %q", screen.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := keyboard.Write([]byte{moshc.EscapeKey, '.'}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.code != 0 || r.err != nil {
			t.Errorf("runMosh after Ctrl-^ . = %d, %v", r.code, r.err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Ctrl-^ . did not end the session")
	}
	out := screen.String()
	if !strings.HasPrefix(out, "\x1b[?1h") || !strings.HasSuffix(out, terminalModeReset) {
		t.Errorf("screen output should start with DECCKM and end with the mode reset: %q ... %q", out[:min(len(out), 16)], out[max(0, len(out)-40):])
	}
}
