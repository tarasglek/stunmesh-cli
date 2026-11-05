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
	// UDPRelay relays a new port on 127.0.0.1 to port on a mesh host,
	// as mesh.UDPRelay does, until stop.
	UDPRelay(host string, port uint16) (localPort uint16, stop func(), err error)
	// Peers is the node's live peer state.
	Peers() ([]mesh.PeerStatus, error)
	// Close lets the node go.
	Close()
}

// openNode is the node for an applet: sm daemon's, which it starts if
// none runs, so that the user's sm processes share one node. With
// $STUNMESH_CLI_DAEMON=off it brings one up in this process instead,
// for one-shot use, narrowed to the peers at want, if any.
func openNode(p proc, cfg mesh.Config, verbose int, want ...netip.Addr) (node, error) {
	if useDaemon(p) {
		return newDaemonClient(p, cfg)
	}
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

func useDaemon(p proc) bool { return p.getenv("STUNMESH_CLI_DAEMON") != "off" }

// inProcess is a node running in this process.
type inProcess struct{ *mesh.Mesh }

func (n inProcess) Close() { n.Stop() }
