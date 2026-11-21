// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// dialTimeout bounds a dial, which on a fresh node includes discovering
// the peer's endpoint and the WireGuard handshake.
const dialTimeout = 30 * time.Second

// nc connects stdin and stdout to a TCP port on a mesh host, for ssh
// -o ProxyCommand='sm nc %h %p', scp, rsync and the like. The node runs in
// this process and ends with it: with --expose, the ports are served for
// exactly as long as the ssh session is up.
func nc(args []string, p proc) int {
	if len(args) != 2 {
		fmt.Fprintf(p.err, "usage: %s [--expose PORT]... nc host port\n", self)
		return 2
	}
	host := args[0]
	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil || port == 0 {
		return fail(p, "nc", fmt.Errorf("bad port %q", args[1]))
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return fail(p, "nc", err)
	}
	// An unknown name fails here, before the key or the network.
	addr, err := cfg.Lookup(host)
	if err != nil {
		return fail(p, "nc", err)
	}
	m, err := startMesh(p, cfg, 0, addr)
	if err != nil {
		return fail(p, "nc", err)
	}
	defer m.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := m.DialTCP(ctx, host, uint16(port))
	if err != nil {
		return fail(p, "nc", fmt.Errorf("%s:%d: %w%s", host, port, err, logHint(p)))
	}
	defer c.Close()
	if err := splice(c, p.in, p.out); err != nil {
		return fail(p, "nc", err)
	}
	return 0
}

// splice copies in to c and c to out until either ends. ssh never closes
// its end of a ProxyCommand's stdin while the session lives, so EOF there
// means ssh is gone, even if it was killed and the far end is unreachable:
// returning then ends this process, its node and its exposed ports.
func splice(c net.Conn, in io.Reader, out io.Writer) error {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, in)
		done <- err
	}()
	go func() {
		_, err := io.Copy(out, c)
		done <- err
	}()
	return <-done
}

// logHint points at the node's log after a failed dial, which is where
// the reason is (STUN failed, no record for the peer, the peer is away),
// unless the user is already reading it.
func logHint(p proc) string {
	if p.getenv("STUNMESH_CLI_LOG") != "" {
		return ""
	}
	return " (STUNMESH_CLI_LOG=info shows the node's log)"
}
