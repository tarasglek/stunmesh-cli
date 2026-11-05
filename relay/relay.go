// SPDX-License-Identifier: LGPL-3.0-or-later

// Package relay carries traffic between two ends: Pipe a stream, such as
// sm daemon's dialed connections, and UDP datagrams, such as mosh's.
package relay

import (
	"io"
	"net"
	"sync"
)

// Pipe copies a to b and b to a, passing each EOF on as a half close so
// protocols that answer after EOF work, and closes both when both
// directions are done.
func Pipe(a, b net.Conn) {
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
