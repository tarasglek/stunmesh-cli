// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/tarasglek/stunmesh-cli/mesh"
	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tarasglek/stunmesh-cli/sshc"
)

// node is the mesh as the applets use it.
type node interface {
	// DialTCP connects to port on a mesh host.
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
	// UDPRelay relays a new port on 127.0.0.1 to port on a mesh host,
	// as mesh.UDPRelay does, until stop.
	UDPRelay(host string, port uint16) (localPort uint16, stop func(), err error)
	// Listen carries connections to f.Port of the node's mesh address to
	// f's target, until stop.
	Listen(f sshc.Forward) (stop func(), err error)
	// Peers is the node's live peer state.
	Peers() ([]mesh.PeerStatus, error)
	// Close lets the node go.
	Close()
}

// openNode brings this device's node up for an applet; want, if any,
// narrows it to the peers at those addresses.
func openNode(p proc, cfg mesh.Config, verbose int, want ...netip.Addr) (node, error) {
	if len(want) > 0 {
		var err error
		if cfg, err = cfg.Narrow(want...); err != nil {
			return nil, err
		}
	}
	m, err := startMesh(p, cfg, verbose)
	if err != nil {
		return nil, err
	}
	return inProcess{m, p}, nil
}

// inProcess is a node running in this process.
type inProcess struct {
	*mesh.Mesh
	p proc
}

func (n inProcess) Listen(f sshc.Forward) (func(), error) {
	return forward(n.Mesh, n.Config(), f, func(format string, args ...any) {
		fmt.Fprintf(n.p.err, self+" listen: "+format+"\n", args...)
	})
}

func (n inProcess) Close() { n.Stop() }

// meshListener is what forward needs of a node.
type meshListener interface {
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
	ListenTCP(port uint16) (net.Listener, error)
}

// forward listens on f.Port of m's mesh address and carries each
// connection to f's target, dialed by localDialer.
func forward(m meshListener, cfg mesh.Config, f sshc.Forward, logf func(string, ...any)) (func(), error) {
	ln, err := m.ListenTCP(f.Port)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", cfg.Prefix.Addr(), f.Port, err)
	}
	go relay.Serve(ln, localDialer(m, cfg, f), logf)
	return func() { ln.Close() }, nil
}
