// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/jpillora/sshd-lite/mosh"
	"github.com/jpillora/sshd-lite/sshd"
	"github.com/tarasglek/stunmesh-cli/moshc"
	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
)

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

// The relay path end to end with the real mosh-client on a pty, against
// sshd-lite's mosh server: mosh-client talks to the relay's loopback port
// with the bootstrapped key, keys typed on the terminal reach the shell,
// and Ctrl-^ . ends the client with status 0.
func TestMoshClientThroughRelay(t *testing.T) {
	client, err := exec.LookPath("mosh-client")
	if err != nil {
		t.Skip("mosh-client not installed")
	}
	t.Setenv("LANG", "C.UTF-8") // mosh-client wants a UTF-8 locale
	t.Setenv("TERM", "xterm-256color")
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
	// The relay as UDPRelay runs it, with the server on loopback in place
	// of the mesh.
	remote, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go relay.UDP(local, remote, nil)

	keyboard, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer keyboard.Close()
	defer tty.Close()
	if err := pty.Setsize(keyboard, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	screen := &lockedBuffer{}
	go func() { _, _ = io.Copy(screen, keyboard) }()
	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		code, err := runMoshClient(client, uint16(local.LocalAddr().(*net.UDPAddr).Port), key, tty, tty, tty)
		res <- result{code, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(screen.String(), "MOSH_42") {
		if time.Now().After(deadline) {
			t.Fatalf("no output on the screen: %q", screen.String())
		}
		// Typed until the shell is there to read it.
		if _, err := keyboard.Write([]byte("echo MOSH_$((40+2))\r")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := keyboard.Write([]byte{0x1e, '.'}); err != nil { // Ctrl-^ .
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.code != 0 || r.err != nil {
			t.Errorf("mosh-client after Ctrl-^ . = %d, %v", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ctrl-^ . did not end mosh-client")
	}
}
