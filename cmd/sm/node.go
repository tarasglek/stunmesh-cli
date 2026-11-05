// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import "github.com/tarasglek/stunmesh-cli/mesh"

// node is the mesh as the applets use it.
type node interface {
	// Peers is the node's live peer state.
	Peers() ([]mesh.PeerStatus, error)
	// Close lets the node go.
	Close()
}

// openNode brings this device's node up for an applet.
func openNode(p proc, cfg mesh.Config, verbose int) (node, error) {
	m, err := startMesh(p, cfg, verbose)
	if err != nil {
		return nil, err
	}
	return inProcess{m}, nil
}

// inProcess is a node running in this process.
type inProcess struct{ *mesh.Mesh }

func (n inProcess) Close() { n.Stop() }
