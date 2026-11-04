// SPDX-License-Identifier: LGPL-3.0-or-later

package relay

import (
	"net"
	"sync"
	"time"
)

// hopAfter is how long the local sender must have been silent before
// another address takes its place; tests shorten it.
var hopAfter = 6 * time.Second

// UDP carries datagrams between local, a socket that a program on this
// host sends to, and remote, a connected datagram conn: what the program
// sends goes to remote, and what arrives on remote goes back to the
// program. The first address to send is the program. Another address
// takes over only once the program has been silent for hopAfter, and
// until then its datagrams are dropped. mosh-server follows a client
// that moves, as mosh-client does when it changes source port after ten
// seconds without an answer, but only on datagrams that authenticate;
// the relay cannot authenticate, so without the silence rule any local
// process could divert the answers to itself with one datagram. Two
// missed 3 s mosh heartbeats is short against the 60 s mosh-client keeps
// reading its old port. Datagrams from remote before the program has
// sent are dropped. UDP returns when either side fails, as when the
// caller closes one, and closes both.
func UDP(local net.PacketConn, remote net.Conn) {
	var (
		mu    sync.Mutex
		peer  net.Addr
		heard time.Time
	)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			local.Close()
			remote.Close()
		})
	}
	defer stop()
	go func() {
		defer stop()
		b := make([]byte, 1<<16)
		for {
			n, err := remote.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			to := peer
			mu.Unlock()
			if to != nil {
				if _, err := local.WriteTo(b[:n], to); err != nil {
					return
				}
			}
		}
	}()
	b := make([]byte, 1<<16)
	for {
		n, from, err := local.ReadFrom(b)
		if err != nil {
			return
		}
		now := time.Now()
		mu.Lock()
		ok := peer == nil || sameAddr(peer, from) || now.Sub(heard) > hopAfter
		if ok {
			peer, heard = from, now
		}
		mu.Unlock()
		if !ok {
			continue
		}
		if _, err := remote.Write(b[:n]); err != nil {
			return
		}
	}
}

func sameAddr(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.AddrPort() == ub.AddrPort()
	}
	return a.String() == b.String()
}
