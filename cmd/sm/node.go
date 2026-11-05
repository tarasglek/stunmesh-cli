// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"net/netip"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// node is the mesh as the applets use it.
type node interface {
	// DialTCP connects to port on a mesh host.
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
	// Peers is the node's live peer state.
	Peers() ([]mesh.PeerStatus, error)
	// Close lets the node go.
	Close()
}

// openNode brings this device's node up for an applet, narrowed to the
// peers at want, if any.
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
	return inProcess{m}, nil
}

// inProcess is a node running in this process.
type inProcess struct{ *mesh.Mesh }

func (n inProcess) Close() { n.Stop() }
