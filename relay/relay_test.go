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
