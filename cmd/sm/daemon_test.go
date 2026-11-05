// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// fakeNode is a node whose mesh hosts are all one loopback TCP server
// that reads to EOF and answers, and one UDP echo server.
type fakeNode struct {
	cfg      mesh.Config
	tcp, udp string
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	cfg, err := mesh.ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
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
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(append([]byte("echo "), b[:n]...), from)
		}
	}()
	return &fakeNode{cfg: cfg, tcp: ln.Addr().String(), udp: echo.LocalAddr().String()}
}

func (f *fakeNode) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if _, err := f.cfg.Lookup(host); err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.tcp)
}

func (f *fakeNode) DialUDP(host string, port uint16) (net.Conn, error) {
	if _, err := f.cfg.Lookup(host); err != nil {
		return nil, err
	}
	return net.Dial("udp", f.udp)
}

func (f *fakeNode) Peers() ([]mesh.PeerStatus, error) {
	return []mesh.PeerStatus{{Name: "remote-01", Addr: f.cfg.Hosts["remote-01"]}}, nil
}

// testDaemon serves a fakeNode on a socket in a temporary directory, as
// sm daemon would, and returns a client of it and a channel closed once
// it has stopped.
func testDaemon(t *testing.T, idle time.Duration) (*daemonClient, *server, *fakeNode, chan struct{}) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "sm.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeNode(t)
	s := newServer(f, f.cfg, "node", t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		if err := serve(ctx, ln, s, idle); err != nil {
			t.Errorf("serve: %v", err)
		}
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return &daemonClient{cfg: f.cfg, sock: sock, id: "node"}, s, f, stopped
}

// talk writes msg to c, half-closes it and reads the answer.
func talk(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A dial becomes a stream to the mesh host that passes a half close on,
// and outlives the context it was dialed with; names outside the hosts
// table are refused.
func TestDaemonDial(t *testing.T) {
	d, _, _, _ := testDaemon(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := d.DialTCP(ctx, "remote-01", 22)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// known_hosts checks the host by the dialed address.
	if a := c.RemoteAddr().String(); a != "10.200.0.5:22" {
		t.Errorf("RemoteAddr %s, want the mesh host's", a)
	}
	if got := talk(t, c, "ping"); got != "got ping" {
		t.Errorf("stream answered %q", got)
	}
	if _, err := d.DialTCP(t.Context(), "example.com", 22); err == nil || !strings.Contains(err.Error(), "not in the compiled-in hosts table") {
		t.Errorf("dial outside the mesh: %v", err)
	}
}

// A client of another node config or key is refused, but may stop the
// daemon.
func TestDaemonOtherNode(t *testing.T) {
	d, _, _, stopped := testDaemon(t, 0)
	other := &daemonClient{sock: d.sock, id: "other"}
	if _, err := other.Peers(); err == nil || !strings.Contains(err.Error(), "another node config") {
		t.Errorf("another node's status: %v", err)
	}
	if err := other.down(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("down did not stop the daemon")
	}
}

func TestDaemonStatus(t *testing.T) {
	d, _, f, _ := testDaemon(t, 0)
	peers, err := d.Peers()
	if err != nil || len(peers) != 1 || peers[0].Name != "remote-01" || peers[0].Addr != f.cfg.Hosts["remote-01"] {
		t.Errorf("Peers = %+v, %v", peers, err)
	}
}

func udpRoundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1500)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "echo "+msg {
		t.Fatalf("got %q, %v; want %q", b[:n], err, "echo "+msg)
	}
}

func relayCount(s *server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.relays)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// A relay carries datagrams while its request is held, and stop ends it.
func TestDaemonUDP(t *testing.T) {
	d, s, _, _ := testDaemon(t, 0)
	port, stop, err := d.UDPRelay("remote-01", 60001)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	udpRoundTrip(t, c, "one")
	stop()
	if n := relayCount(s); n != 0 {
		t.Errorf("%d relays after stop", n)
	}
}

// A relay whose client is gone stays while the program it relays for
// still has its port, and goes with it; then the daemon, idle, stops.
func TestDaemonUDPOrphan(t *testing.T) {
	idle := 300 * time.Millisecond
	d, s, _, stopped := testDaemon(t, idle)
	res, release, err := d.hold("/v0/udp", http.Header{"Dial-Host": {"remote-01"}, "Dial-Port": {"60001"}})
	if err != nil {
		t.Fatal(err)
	}
	prog, err := net.Dial("udp", "127.0.0.1:"+res.Header.Get("Relay-Port"))
	if err != nil {
		t.Fatal(err)
	}
	udpRoundTrip(t, prog, "hello")
	release()
	// Past the request's close and an idle check: still relaying.
	time.Sleep(2 * idle)
	udpRoundTrip(t, prog, "still here")
	select {
	case <-stopped:
		t.Fatal("daemon stopped while a program used its relay")
	default:
	}
	prog.Close()
	waitFor(t, "the relay to go", func() bool { return relayCount(s) == 0 })
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("idle daemon did not stop")
	}
}

// A relay whose program never sent has no one to serve once its request
// closes.
func TestDaemonUDPOrphanUnused(t *testing.T) {
	d, s, _, _ := testDaemon(t, 0)
	_, release, err := d.hold("/v0/udp", http.Header{"Dial-Host": {"remote-01"}, "Dial-Port": {"60001"}})
	if err != nil {
		t.Fatal(err)
	}
	release()
	waitFor(t, "the relay to go", func() bool { return relayCount(s) == 0 })
}

// An orphaned relay follows the program to a new port, as mosh-client's
// hops need, and checks that one.
func TestDaemonUDPOrphanHop(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the relay's 6 s hop rule")
	}
	t.Parallel()
	d, s, _, _ := testDaemon(t, 0)
	res, release, err := d.hold("/v0/udp", http.Header{"Dial-Host": {"remote-01"}, "Dial-Port": {"60001"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:" + res.Header.Get("Relay-Port")
	first, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	udpRoundTrip(t, first, "one")
	time.Sleep(6500 * time.Millisecond)
	hopped, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer hopped.Close()
	udpRoundTrip(t, hopped, "after the hop")
	release()
	first.Close() // the old port is free; the relay follows the new one
	time.Sleep(100 * time.Millisecond)
	if s.reap(); relayCount(s) != 1 {
		t.Fatal("relay ended while the program had its new port")
	}
	udpRoundTrip(t, hopped, "still")
	hopped.Close()
	if s.reap() {
		t.Error("relay kept after the program's port was freed")
	}
}

// bound tells a bound UDP port from a free one, probing 127.0.0.1 as reap
// does, whatever address the program bound: mosh-client's socket is
// unconnected and bound to the wildcard by its first send, and a
// dual-stack [::] socket holds the IPv4 port too.
func TestBound(t *testing.T) {
	for _, network := range []string{"udp4/127.0.0.1", "udp4/0.0.0.0", "udp/[::]"} {
		n, host, _ := strings.Cut(network, "/")
		c, err := net.ListenPacket(n, net.JoinHostPort(strings.Trim(host, "[]"), "0"))
		if err != nil {
			t.Fatal(err)
		}
		a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}
		if !bound(a) {
			t.Errorf("%s: a bound port reads as free", network)
		}
		c.Close()
		if bound(a) {
			t.Errorf("%s: a free port reads as bound", network)
		}
	}
}

// The daemon stays up while a stream is open, and stops after idle once
// none is.
func TestDaemonIdle(t *testing.T) {
	idle := 200 * time.Millisecond
	d, _, _, stopped := testDaemon(t, idle)
	c, err := d.DialTCP(t.Context(), "remote-01", 22)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * idle)
	select {
	case <-stopped:
		t.Fatal("stopped with a stream open")
	default:
	}
	if got := talk(t, c, "late"); got != "got late" {
		t.Errorf("stream answered %q", got)
	}
	c.Close()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop when idle")
	}
	if _, err := d.Peers(); err == nil {
		t.Error("a stopped daemon answered")
	}
}

func TestPeerUID(t *testing.T) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if uid, err := peerUID(a); err != nil || uid != os.Getuid() {
		t.Errorf("peerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}

// A connection the daemon closes before answering, as one stopping for
// idle does, is tried again.
func TestDaemonClientRetry(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f := newFakeNode(t)
	s := newServer(f, f.cfg, "node", t.Logf)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
		_ = http.Serve(ln, s.handler())
	}()
	d := &daemonClient{cfg: f.cfg, sock: sock, id: "node"}
	if peers, err := d.Peers(); err != nil || len(peers) != 1 {
		t.Errorf("Peers after a dropped connection = %v, %v", peers, err)
	}
}
