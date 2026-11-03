// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jpillora/sshd-lite/sshd"
	"github.com/tarasglek/stunmesh-cli/mesh"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
)

func TestParseSSHArgs(t *testing.T) {
	fwd := func(s string) sshc.Forward {
		f, err := sshc.ParseForward(s)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	for _, tc := range []struct {
		args []string
		want sshArgs
	}{
		{[]string{"remote-01"}, sshArgs{port: 22, user: "me", host: "remote-01"}},
		{[]string{"root@desk", "uname", "-a"}, sshArgs{port: 22, user: "root", host: "desk", command: "uname -a", args: []string{"uname", "-a"}}},
		{[]string{"remote-01", "--", "uname", "-a"}, sshArgs{port: 22, user: "me", host: "remote-01", command: "uname -a", args: []string{"uname", "-a"}}},
		{[]string{"h", "-p", "2222", "ls", "-p"}, sshArgs{port: 2222, user: "me", host: "h", command: "ls -p", args: []string{"ls", "-p"}}},
		{[]string{"h", "ls", "--", "x"}, sshArgs{port: 22, user: "me", host: "h", command: "ls -- x", args: []string{"ls", "--", "x"}}},
		{[]string{"-p", "2222", "-l", "alice", "x@h"}, sshArgs{port: 2222, user: "alice", host: "h"}},
		{[]string{"-p2222", "-i", "k1", "-ik2", "h"}, sshArgs{port: 2222, user: "me", host: "h", identities: []string{"k1", "k2"}}},
		{[]string{"-N", "-L", "8080:127.0.0.1:80", "-R2222:127.0.0.1:22", "h"},
			sshArgs{port: 22, user: "me", host: "h", noCommand: true, local: []sshc.Forward{fwd("8080:127.0.0.1:80")}, remote: []sshc.Forward{fwd("2222:127.0.0.1:22")}}},
		{[]string{"--", "h", "ls"}, sshArgs{port: 22, user: "me", host: "h", command: "ls", args: []string{"ls"}}},
		{[]string{"-v", "h"}, sshArgs{port: 22, user: "me", host: "h", verbose: 1}},
		{[]string{"-vv", "-v", "h"}, sshArgs{port: 22, user: "me", host: "h", verbose: 3}},
	} {
		got, err := parseSSHArgs(tc.args, "me")
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseSSHArgs(%q) = %+v, %v\nwant %+v", tc.args, got, err, tc.want)
		}
	}
	for _, args := range [][]string{nil, {"-p"}, {"-vx", "h"}, {"-p", "x", "h"}, {"-p", "0", "h"}, {"-X", "h"}, {"-L", "bad", "h"},
		{"-N", "h", "ls"}, {"@h"}, {"u@"}} {
		if a, err := parseSSHArgs(args, "me"); err == nil {
			t.Errorf("parseSSHArgs(%q) = %+v, want error", args, a)
		}
	}
	if _, err := parseSSHArgs([]string{"h"}, ""); err == nil {
		t.Error("no user anywhere accepted")
	}
}

// sessionClient is an SSH client of an in-process sshd-lite.
func sessionClient(t *testing.T) *ssh.Client {
	t.Helper()
	key := func() (ed25519.PrivateKey, ssh.Signer) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := ssh.NewSignerFromKey(k)
		return k, s
	}
	hk, hs := key()
	_, us := key()
	b, _ := ssh.MarshalPrivateKey(hk, "")
	srv, err := sshd.NewServer(sshd.Config{KeyBytes: pem.EncodeToMemory(b), AuthKeys: []ssh.PublicKey{us.PublicKey()},
		Shell: "/bin/sh", WorkDir: t.TempDir(), NoInheritEnv: true, NoGlobalEnv: true, LogQuiet: true})
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
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshc.Client(context.Background(), conn, "h:22", &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: ssh.FixedHostKey(hs.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRunSession(t *testing.T) {
	c := sessionClient(t)
	var out, errb bytes.Buffer

	code, err := runSession(c, "echo hi; echo oops >&2; exit 3", testProc(nil, &out, &errb))
	if err != nil || code != 3 || out.String() != "hi\n" || errb.String() != "oops\n" {
		t.Errorf("exec: %d %v %q %q", code, err, out.String(), errb.String())
	}

	// No terminal here: the shell reads its commands from stdin. (sshd-lite
	// runs every shell on a pty, so its echo is in the output too.)
	out.Reset()
	p := testProc(nil, &out, &errb)
	p.in = strings.NewReader("echo from-stdin\nexit 5\n")
	if code, err := runSession(c, "", p); err != nil || code != 5 || !strings.Contains(out.String(), "from-stdin\r\n$ ") {
		t.Errorf("shell: %d %v %q", code, err, out.String())
	}

	// A command that ends returns at once, though stdin never does.
	stdin, w := io.Pipe()
	defer w.Close()
	p.in = stdin
	start := time.Now()
	if code, err := runSession(c, "exit 4", p); err != nil || code != 4 || time.Since(start) > 3*time.Second {
		t.Errorf("exit with open stdin: %d %v after %v", code, err, time.Since(start))
	}
}

// Bad arguments and hosts fail before the key or the network.
func TestSSHRejects(t *testing.T) {
	env := map[string]string{"config": testConfig, "HOME": t.TempDir(), "USER": "me", "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"ssh"}, "no destination"},
		{[]string{"ssh", "nosuch"}, "not in the compiled-in hosts table"},
		{[]string{"ssh", "-L", "x", "remote-01"}, "forward"},
		{[]string{"ssh", "alice@remote-01"}, "run sm keygen"},
		{[]string{"ssh", "-i", "/nonexistent/id", "alice@remote-01"}, "/nonexistent/id"}, // -i reaches Auth
	} {
		code, _, errs := runEnv(env, append([]string{"sm"}, tc.args...)...)
		if code != 255 || !strings.Contains(errs, tc.err) {
			t.Errorf("%v: %d %q, want 255 and %q", tc.args, code, errs, tc.err)
		}
	}
}

func TestExitStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
		msg  string
	}{
		{nil, 0, ""},
		{&ssh.ExitMissingError{}, 255, "exited without status"},
		{fmt.Errorf("wait: %w", &ssh.ExitMissingError{}), 255, "exited without status"},
		{io.ErrUnexpectedEOF, 255, "unexpected EOF"},
	} {
		code, err := exitStatus(tc.err)
		if code != tc.code || (tc.msg == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.msg)) {
			t.Errorf("exitStatus(%v) = %d, %v", tc.err, code, err)
		}
	}
	// The ExitError path, from a real session.
	c := sessionClient(t)
	sess, _ := c.NewSession()
	defer sess.Close()
	if code, err := exitStatus(sess.Run("exit 9")); code != 9 || err != nil {
		t.Errorf("exit 9 = %d, %v", code, err)
	}
}

// The pty carries the TERM of proc's environment, default xterm-256color.
func TestRequestPty(t *testing.T) {
	c := sessionClient(t)
	for termName, want := range map[string]string{"screen-256color": "screen-256color", "": "xterm-256color"} {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := requestPty(sess, termName, 80, 24); err != nil {
			t.Fatal(err)
		}
		out, err := sess.Output("echo $TERM")
		sess.Close()
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("TERM %q: remote saw %q, %v", termName, out, err)
		}
	}
}

// An unreadable known_hosts stops the applet before the node starts, and
// says why.
func TestSSHBadKnownHosts(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "known_hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"config": testConfig, "HOME": home, "USER": "me", "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	code, _, errs := runEnv(env, "sm", "ssh", "remote-01")
	if code != 255 || !strings.Contains(errs, "known_hosts") || strings.Contains(errs, "keygen") {
		t.Errorf("known_hosts a directory: %d %q", code, errs)
	}
}

func TestHostAliases(t *testing.T) {
	cfg, err := mesh.ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string][]string{
		"remote-01":               {"remote-01.mesh.internal:22"},
		"remote-01.mesh.internal": {"remote-01:22"},
		"Remote-01":               {"remote-01:22", "remote-01.mesh.internal:22"},
		"10.200.0.5":              nil,
	} {
		if got := hostAliases(cfg, host, 22); !slices.Equal(got, want) {
			t.Errorf("hostAliases(%q) = %v, want %v", host, got, want)
		}
	}
}

// -v traces each step to stderr, and the node's log at info; without it
// both are silent. Here the run stops at the missing mesh key, after the
// lookup and the keys were traced.
func TestSSHVerbose(t *testing.T) {
	home := t.TempDir()
	env := map[string]string{"config": testConfig, "HOME": home, "USER": "me", "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	_, _, quiet := runEnv(env, "sm", "ssh", "remote-01")
	if strings.Contains(quiet, "debug1") {
		t.Errorf("trace without -v: %q", quiet)
	}
	_, _, errs := runEnv(env, "sm", "ssh", "-v", "remote-01")
	for _, want := range []string{"sm ssh: debug1: remote-01 is 10.200.0.5 in the hosts table; node narrowed to 1 peer(s)", "agent: no SSH_AUTH_SOCK", "run sm keygen"} {
		if !strings.Contains(errs, want) {
			t.Errorf("-v output lacks %q:\n%s", want, errs)
		}
	}
	p := testProc(map[string]string{}, &bytes.Buffer{}, &bytes.Buffer{})
	for v, want := range map[int]bool{0: false, 1: true} {
		if got := logger(p, v) != nil; got != want {
			t.Errorf("logger at -v x%d: %v", v, got)
		}
	}
}
