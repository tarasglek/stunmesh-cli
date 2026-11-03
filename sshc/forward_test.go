// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseForward(t *testing.T) {
	var lo netip.Addr // loopback
	for spec, want := range map[string]Forward{
		"8080:127.0.0.1:80":                {lo, 8080, "127.0.0.1", 80},
		"2222:localhost:22":                {lo, 2222, "localhost", 22},
		"localhost:8080:web:80":            {lo, 8080, "web", 80},
		"*:8080:web:80":                    {netip.IPv4Unspecified(), 8080, "web", 80},
		"10.200.0.8:2222:desk:22":          {netip.MustParseAddr("10.200.0.8"), 2222, "desk", 22},
		"[::1]:8080:[fd00::5]:80":          {netip.MustParseAddr("::1"), 8080, "fd00::5", 80},
		"0:127.0.0.1:22":                   {lo, 0, "127.0.0.1", 22},
		":8080:remote-01.mesh.internal:80": {lo, 8080, "remote-01.mesh.internal", 80},
	} {
		got, err := ParseForward(spec)
		if err != nil || got != want {
			t.Errorf("ParseForward(%q) = %+v, %v; want %+v", spec, got, err, want)
		}
	}
	for _, spec := range []string{"8080", "8080:web", "a:b:c:d:e", "x:web:80", "8080:web:0", "8080::80",
		"8080:web:99999", "host.example:8080:web:80", "[::1:8080:web:80", "::1]:8080:web:80"} {
		if f, err := ParseForward(spec); err == nil {
			t.Errorf("ParseForward(%q) = %+v, want error", spec, f)
		}
	}
	f, _ := ParseForward("[::1]:8080:[fd00::5]:80")
	if f.ListenAddr() != "[::1]:8080" || f.Target() != "[fd00::5]:80" {
		t.Errorf("addrs %s %s", f.ListenAddr(), f.Target())
	}
	if f, _ := ParseForward("8080:web:80"); f.ListenAddr() != "localhost:8080" {
		t.Errorf("loopback ListenAddr = %s", f.ListenAddr())
	}
}

// answerAfterEOF serves one connection: read to EOF, then answer.
func answerAfterEOF(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("got "), b...))
			}()
		}
	}()
	return ln
}

// talk sends msg on a fresh connection to addr, half-closes and reads the
// answer.
func talk(t *testing.T, addr, msg string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func forwardClient(t *testing.T) *ssh.Client {
	t.Helper()
	_, us := newKey(t)
	s := startServer(t, us.PublicKey())
	c, err := dial(t, s, &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: ssh.FixedHostKey(s.host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// -L: a local listener whose connections the server makes, end to end
// with half close, twice on one forward.
func TestLocalForward(t *testing.T) {
	c := forwardClient(t)
	target := answerAfterEOF(t)
	f, err := ParseForward("0:" + target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	lns, err := ListenLocal(f, t.Logf)
	if err != nil || len(lns) != 1 {
		t.Fatalf("ListenLocal port 0: %v, %v", lns, err)
	}
	ln := lns[0]
	done := make(chan error, 1)
	go func() {
		done <- Serve(ln, func() (net.Conn, error) { return c.Dial("tcp", f.Target()) }, t.Logf)
	}()
	for _, msg := range []string{"one", "two"} {
		if got := talk(t, ln.Addr().String(), msg); got != "got "+msg {
			t.Errorf("-L %s = %q", msg, got)
		}
	}
	ln.Close()
	if err := <-done; err != nil {
		t.Errorf("Serve after close: %v", err)
	}
}

// -R: the server listens, on loopback with a port it picks, and its
// connections come back to a target dialed on our side.
func TestRemoteForward(t *testing.T) {
	c := forwardClient(t)
	target := answerAfterEOF(t)
	f, err := ParseForward("0:" + target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenRemote(c, f)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if a := netip.MustParseAddrPort(ln.Addr().String()); !a.Addr().IsLoopback() || a.Port() == 0 {
		t.Fatalf("remote listener at %v", ln.Addr())
	}
	go func() { _ = Serve(ln, func() (net.Conn, error) { return net.Dial("tcp", f.Target()) }, t.Logf) }()
	if got := talk(t, ln.Addr().String(), "back"); got != "got back" {
		t.Errorf("-R = %q", got)
	}
}

// A target that refuses closes just that connection; the forward lives on.
func TestServeDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	target := answerAfterEOF(t)
	var dials atomic.Int32
	logged := make(chan string, 1)
	go func() {
		_ = Serve(ln, func() (net.Conn, error) {
			if dials.Add(1) == 1 {
				return nil, io.ErrUnexpectedEOF
			}
			return net.Dial("tcp", target.Addr().String())
		}, func(f string, a ...any) { logged <- f })
	}()
	// Closed with our bytes unread, the connection may end in a reset
	// rather than EOF; either way nothing comes back.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("x"))
	if b, _ := io.ReadAll(c); len(b) != 0 {
		t.Errorf("failed dial answered %q", b)
	}
	c.Close()
	<-logged
	if got := talk(t, ln.Addr().String(), "y"); got != "got y" {
		t.Errorf("after a failed dial: %q", got)
	}
}

// Loopback -L listens on both families, as ssh binds localhost; an
// explicit bind address gets just that one.
func TestListenLocal(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	f, _ := ParseForward(net.JoinHostPort("localhost", strconv.Itoa(port)) + ":web:80")
	lns, err := ListenLocal(f, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ln := range lns {
		got = append(got, ln.Addr().String())
		ln.Close()
	}
	want := []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port)}
	if v6, err := net.Listen("tcp", "[::1]:0"); err != nil {
		want = want[:1] // no IPv6 loopback on this host
	} else {
		v6.Close()
	}
	if !slices.Equal(got, want) {
		t.Errorf("ListenLocal = %v, want %v", got, want)
	}
	f, _ = ParseForward("127.0.0.1:0:web:80")
	if lns, err := ListenLocal(f, t.Logf); err != nil || len(lns) != 1 {
		t.Errorf("explicit bind: %v, %v", lns, err)
	} else {
		lns[0].Close()
	}
}
