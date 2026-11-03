// SPDX-License-Identifier: LGPL-3.0-or-later

// Package relay carries TCP connections between a listener and a dialer:
// ssh's -L and -R forwards and the listen applet's inbound ones.
package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Serve carries every connection accepted on ln to a connection from dial,
// copying both ways until each side is done. It returns when ln is
// closed, that is when Accept fails with net.ErrClosed or, as x/crypto's
// remote listeners do, io.EOF. Any other accept error is logged and
// retried after a pause that doubles up to a second, as net/http does, so
// one bad accept does not leave an open listener that no one serves. A
// failed dial closes only that connection and is reported to logf.
func Serve(ln net.Listener, dial func() (net.Conn, error), logf func(format string, args ...any)) {
	var pause time.Duration
	for {
		a, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			logf("accept on %s: %v; retrying in %v", ln.Addr(), err, pause)
			sleep(pause)
			continue
		}
		pause = 0
		go func() {
			b, err := dial()
			if err != nil {
				logf("forward from %s: %v", a.RemoteAddr(), err)
				a.Close()
				return
			}
			pipe(a, b)
		}()
	}
}

// sleep is time.Sleep, swapped out by tests.
var sleep = time.Sleep

// pipe copies a to b and b to a, passing each EOF on as a half close so
// protocols that answer after EOF work, and closes both when both
// directions are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	half := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go half(a, b)
	go half(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
