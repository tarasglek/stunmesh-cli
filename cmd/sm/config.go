// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tarasglek/stunmesh-cli/mesh"
	"github.com/tarasglek/stunmesh-cli/relay"
)

func nodeConfig(p proc) (mesh.Config, error) {
	b, err := p.config()
	if err != nil {
		return mesh.Config{}, err
	}
	return mesh.ParseConfig(b)
}

// startMesh brings this device's node up in this process, for one session
// with the host at peer: its only peer, so the only one that can reach
// the ports in p.expose. The node lives as long as the process; its UDP
// port keeps any other on the device from starting meanwhile
// (mesh.ErrBusy). $STUNMESH_CLI_LOG=debug, info, warn or error shows its
// log at that level and above on stderr; without it, verbose 1 shows info
// and 2 or more debug, as ssh -v and -vv.
func startMesh(p proc, cfg mesh.Config, verbose int, peer netip.Addr) (*mesh.Mesh, error) {
	cfg, err := cfg.Narrow(peer)
	if err != nil {
		return nil, err
	}
	priv, err := loadKey(p)
	if err != nil {
		return nil, err
	}
	log := logger(p, verbose)
	m, err := mesh.Start(cfg, priv, log)
	if err != nil {
		return nil, err
	}
	for _, port := range p.expose {
		ln, err := m.ListenTCP(port)
		if err != nil {
			m.Stop()
			return nil, fmt.Errorf("expose %d: %w", port, err)
		}
		go expose(ln, port, log)
	}
	return m, nil
}

// expose connects each mesh connection ln accepts to port on 127.0.0.1.
func expose(ln net.Listener, port uint16, log mesh.Logger) {
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			t, err := net.Dial("tcp", target)
			if err != nil {
				log("warn", fmt.Sprintf("expose: %s to %s: %v", c.RemoteAddr(), target, err))
				c.Close()
				return
			}
			log("info", fmt.Sprintf("expose: %s to %s", c.RemoteAddr(), target))
			relay.Pipe(c, t)
		}()
	}
}

// loadKey reads this device's private key.
func loadKey(p proc) ([32]byte, error) {
	path, err := keyPath(p.getenv)
	if err != nil {
		return [32]byte{}, err
	}
	priv, err := readKey(path)
	if errors.Is(err, fs.ErrNotExist) {
		return priv, fmt.Errorf("no key at %s; run %s keygen", path, self)
	}
	return priv, err
}

var logLevels = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}

func logger(p proc, verbose int) mesh.Logger {
	level := strings.ToLower(p.getenv("STUNMESH_CLI_LOG"))
	if level == "" && verbose > 0 {
		level = map[bool]string{true: "debug", false: "info"}[verbose > 1]
	}
	min, ok := logLevels[level]
	if !ok {
		return func(string, string) {}
	}
	return func(level, msg string) {
		if l, ok := logLevels[level]; !ok || l >= min {
			fmt.Fprintf(p.err, "%s: %s: %s\n", self, level, msg)
		}
	}
}
