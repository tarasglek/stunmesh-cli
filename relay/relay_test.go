// SPDX-License-Identifier: LGPL-3.0-or-later

package relay

import (
	"errors"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// answerAfterEOF serves connections: read to EOF, then answer.
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

// Each accepted connection is carried to its own dialed one, EOF passed
// on as a half close, and Serve ends cleanly when the listener closes.
func TestServe(t *testing.T) {
	target := answerAfterEOF(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		Serve(ln, func() (net.Conn, error) { return net.Dial("tcp", target.Addr().String()) }, t.Logf)
		close(done)
	}()
	for _, msg := range []string{"one", "two"} {
		if got := talk(t, ln.Addr().String(), msg); got != "got "+msg {
			t.Errorf("relay %s = %q", msg, got)
		}
	}
	ln.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Serve still running after its listener closed")
	}
}

// A target that refuses closes just that connection; the relay lives on.
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
		Serve(ln, func() (net.Conn, error) {
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

// flakyListener fails its first accepts with a non-closing error, then
// hands out the real listener's connections; Close closes the real one.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("transient")}
	}
	return f.Listener.Accept()
}

// A transient accept error is retried with a growing pause instead of
// ending the relay with the listener still open.
func TestServeRetriesAccept(t *testing.T) {
	var pauses []time.Duration
	sleep = func(d time.Duration) { pauses = append(pauses, d) }
	defer func() { sleep = time.Sleep }()
	target := answerAfterEOF(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: inner}
	ln.fails.Store(3)
	done := make(chan struct{})
	go func() {
		Serve(ln, func() (net.Conn, error) { return net.Dial("tcp", target.Addr().String()) }, t.Logf)
		close(done)
	}()
	if got := talk(t, inner.Addr().String(), "after"); got != "got after" {
		t.Errorf("after transient errors: %q", got)
	}
	ln.Close()
	<-done
	if want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}; !slices.Equal(pauses, want) {
		t.Errorf("pauses = %v, want %v", pauses, want)
	}
}

// udpRelay runs UDP between a fresh loopback socket and a conn to an echo
// server that prefixes what it sends back, and returns the socket's address.
// sender, if not nil, is UDP's.
func udpRelay(t *testing.T, sender func(net.Addr)) (net.Addr, func()) {
	t.Helper()
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
	remote, err := net.Dial("udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { UDP(local, remote, sender); close(done) }()
	stop := func() {
		local.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("UDP did not return after its local socket closed")
		}
	}
	return local.LocalAddr(), stop
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
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

// Datagrams cross the relay both ways, and answers follow the client to a
// new source port once the old one has gone quiet, as mosh-client's port
// hops need.
func TestUDP(t *testing.T) {
	defer func(d time.Duration) { hopAfter = d }(hopAfter)
	hopAfter = 100 * time.Millisecond
	senders := make(chan net.Addr, 4)
	addr, stop := udpRelay(t, func(a net.Addr) { senders <- a })
	first, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	roundTrip(t, first, "one")
	roundTrip(t, first, "two")
	if a := <-senders; a.String() != first.LocalAddr().String() {
		t.Errorf("sender %v, want %v", a, first.LocalAddr())
	}

	time.Sleep(2 * hopAfter)
	hopped, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer hopped.Close()
	roundTrip(t, hopped, "after the hop")
	stop()
	if a := <-senders; a.String() != hopped.LocalAddr().String() {
		t.Errorf("sender after the hop %v, want %v", a, hopped.LocalAddr())
	}
	if len(senders) != 0 {
		t.Errorf("sender called %d more times for known senders", len(senders))
	}
}

// While the client is active, another local sender neither gets its
// answers nor reaches the far end.
func TestUDPKeepsActiveClient(t *testing.T) {
	addr, stop := udpRelay(t, nil)
	defer stop()
	client, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	roundTrip(t, client, "mine")

	other, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Write([]byte("steal")); err != nil {
		t.Fatal(err)
	}
	// Were "steal" forwarded, its echo would come to client first and
	// break this round trip; were the answers diverted, client would get
	// nothing.
	roundTrip(t, client, "still mine")
	_ = other.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := other.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("another sender got %d bytes while the client was active", n)
	}
}
