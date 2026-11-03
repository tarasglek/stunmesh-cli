// SPDX-License-Identifier: LGPL-3.0-or-later

package sshc

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Forward is an OpenSSH -L or -R spec, [bind_address:]port:host:hostport.
// Bind is a literal address; the zero Addr, from a spec with no bind
// address or with localhost, means loopback. Host is resolved by
// whichever side dials it.
type Forward struct {
	Bind     netip.Addr
	Port     uint16
	Host     string
	HostPort uint16
}

// ParseForward reads a forward spec. IPv6 addresses go in brackets. The
// bind address must be a literal, or localhost or * (all addresses), so
// that binding never needs a name lookup.
func ParseForward(spec string) (Forward, error) {
	fields, err := splitSpec(spec)
	if err != nil {
		return Forward{}, err
	}
	var f Forward
	switch len(fields) {
	case 3:
	case 4:
		switch b := fields[0]; b {
		case "localhost", "":
		case "*":
			f.Bind = netip.IPv4Unspecified()
		default:
			if f.Bind, err = netip.ParseAddr(b); err != nil {
				return Forward{}, fmt.Errorf("forward %q: bind address must be a literal, localhost or *", spec)
			}
		}
		fields = fields[1:]
	default:
		return Forward{}, fmt.Errorf("forward %q: want [bind_address:]port:host:hostport", spec)
	}
	if f.Port, err = parsePort(fields[0], true); err != nil {
		return Forward{}, fmt.Errorf("forward %q: %w", spec, err)
	}
	if f.Host = fields[1]; f.Host == "" {
		return Forward{}, fmt.Errorf("forward %q: no host", spec)
	}
	if f.HostPort, err = parsePort(fields[2], false); err != nil {
		return Forward{}, fmt.Errorf("forward %q: %w", spec, err)
	}
	return f, nil
}

// splitSpec splits on colons outside brackets and drops the brackets.
func splitSpec(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '[':
			depth++
		case r == ']':
			if depth--; depth < 0 {
				return nil, fmt.Errorf("forward %q: unbalanced ]", s)
			}
		case r == ':' && depth == 0:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("forward %q: unbalanced [", s)
	}
	return append(out, cur.String()), nil
}

// parsePort reads a port; zero, for a server-chosen port, only if listen.
func parsePort(s string, listen bool) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || (n == 0 && !listen) {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

var loopback4, loopback6 = netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()

// ListenAddr is where the forward listens, localhost:port for loopback.
func (f Forward) ListenAddr() string {
	if !f.Bind.IsValid() {
		return net.JoinHostPort("localhost", strconv.Itoa(int(f.Port)))
	}
	return netip.AddrPortFrom(f.Bind, f.Port).String()
}

// ListenLocal listens for -L. Loopback means both 127.0.0.1 and ::1, as
// ssh binds localhost, so a client that resolves localhost to ::1 first
// connects too; ::1 is best effort, its failure only reported to logf, as
// ssh warns and goes on. A server-chosen port (0) is IPv4 only, since the
// two would get different ports.
func ListenLocal(f Forward, logf func(format string, args ...any)) ([]net.Listener, error) {
	if f.Bind.IsValid() {
		ln, err := net.Listen("tcp", f.ListenAddr())
		if err != nil {
			return nil, err
		}
		return []net.Listener{ln}, nil
	}
	ln4, err := net.Listen("tcp", netip.AddrPortFrom(loopback4, f.Port).String())
	if err != nil {
		return nil, err
	}
	lns := []net.Listener{ln4}
	if f.Port != 0 {
		if ln6, err := net.Listen("tcp", netip.AddrPortFrom(loopback6, f.Port).String()); err == nil {
			lns = append(lns, ln6)
		} else {
			logf("-L %s: %v", f.ListenAddr(), err)
		}
	}
	return lns, nil
}

// Target is where the forward connects.
func (f Forward) Target() string { return net.JoinHostPort(f.Host, strconv.Itoa(int(f.HostPort))) }

// ListenRemote asks the server to listen for -R, on 127.0.0.1 for
// loopback, unless the spec binds elsewhere; the server's own policy may
// restrict that. ssh asks for "localhost", which OpenSSH's sshd binds on
// both families, but x/crypto sends only address literals.
func ListenRemote(c *ssh.Client, f Forward) (net.Listener, error) {
	bind := f.Bind
	if !bind.IsValid() {
		bind = loopback4
	}
	return c.ListenTCP(net.TCPAddrFromAddrPort(netip.AddrPortFrom(bind, f.Port)))
}
