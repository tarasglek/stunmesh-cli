// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tarasglek/stunmesh-cli/moshc"
	"github.com/tarasglek/stunmesh-cli/relay"
)

// Bad arguments, ssh's options and a stdin that is not a terminal fail
// before the key or the network.
func TestMoshRejects(t *testing.T) {
	env := map[string]string{"config": testConfig, "HOME": t.TempDir(), "USER": "me", "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	for _, tc := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"mosh"}, 2, "no destination"},
		{[]string{"mosh", "-v"}, 2, "no destination"},
		{[]string{"mosh", "-L", "8080:x:80", "remote-01"}, 2, "unsupported option -L"},
		{[]string{"mosh", "-p", "22", "remote-01"}, 2, "unsupported option -p"},
		{[]string{"mosh", "remote-01"}, 1, "stdin is not a terminal"},
	} {
		code, _, errs := runEnv(env, append([]string{"sm"}, tc.args...)...)
		if code != tc.code || !strings.Contains(errs, tc.err) {
			t.Errorf("%v: %d %q, want %d and %q", tc.args, code, errs, tc.code, tc.err)
		}
	}
}

func TestMoshSSHArgs(t *testing.T) {
	got := moshSSHArgs("me@remote-01", []string{"tmux", "a b"}, 2)
	want := []string{"-n", "-tt", "-v", "-v", "me@remote-01", "--", "mosh-server new -s -c 256 -l LANG=C.UTF-8 -- 'tmux' 'a b'"}
	if !slices.Equal(got, want) {
		t.Errorf("moshSSHArgs = %q, want %q", got, want)
	}
}

// fakeSSH writes a shell script standing in for ssh.
func fakeSSH(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// bootstrap reads MOSH CONNECT from ssh's output among a banner and the
// pty's CRs, reports ssh's failures, and gives up on a hung ssh.
func TestBootstrap(t *testing.T) {
	ssh := fakeSSH(t, `printf 'motd\r\nMOSH CONNECT 60001 AAAAAAAAAAAAAAAAAAAAAA\r\n'`)
	port, key, err := bootstrap(t.Context(), ssh, nil, io.Discard)
	if err != nil || port != 60001 || key != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("bootstrap = %d %q %v", port, key, err)
	}

	var errb bytes.Buffer
	ssh = fakeSSH(t, "echo 'ssh: connect to host remote-01 port 22: refused' >&2; exit 255")
	if _, _, err := bootstrap(t.Context(), ssh, nil, &errb); err == nil || !strings.Contains(err.Error(), "exit status 255") || !strings.Contains(errb.String(), "refused") {
		t.Errorf("failing ssh: %v, stderr %q", err, errb.String())
	}

	ssh = fakeSSH(t, "exec sleep 30")
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := bootstrap(ctx, ssh, nil, io.Discard); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("hung ssh: %v after %v", err, time.Since(start))
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

// The relay path end to end with the real mosh-server and mosh-client,
// the client on a pty: it talks to the relay's loopback port with the
// key from MOSH CONNECT, keys typed on the terminal reach the shell, and
// the shell's exit ends the client with status 0.
func TestMoshClientThroughRelay(t *testing.T) {
	client, err := exec.LookPath("mosh-client")
	if err != nil {
		t.Skip("mosh-client not installed")
	}
	server, err := exec.LookPath("mosh-server")
	if err != nil {
		t.Skip("mosh-server not installed")
	}
	t.Setenv("LANG", "C.UTF-8") // mosh-client wants a UTF-8 locale
	t.Setenv("TERM", "xterm-256color")
	var errb bytes.Buffer
	srv := exec.Command(server, "new", "-i", "127.0.0.1", "-c", "256", "-l", "LANG=C.UTF-8", "--", "/bin/sh")
	srv.Stderr = &errb
	out, err := srv.Output()
	if err != nil {
		t.Fatalf("mosh-server: %v %s", err, errb.String())
	}
	if m := regexp.MustCompile(`pid = (\d+)`).FindStringSubmatch(errb.String()); m != nil {
		pid, _ := strconv.Atoi(m[1])
		defer syscall.Kill(pid, syscall.SIGKILL)
	}
	port, key, err := moshc.ParseConnect(string(out))
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

	keyboard, tty, err := openPTY(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer keyboard.Close()
	defer tty.Close()
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
	if _, err := keyboard.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-res:
		if r.code != 0 || r.err != nil {
			t.Errorf("mosh-client after the shell's exit = %d, %v", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shell's exit did not end mosh-client")
	}
}
