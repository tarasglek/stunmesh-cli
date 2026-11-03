// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tarasglek/stunmesh-cli/sshc"
)

// parseListen reads listen's meshport:host:port specs. There is no bind
// address: the node listens on its mesh address, and only there.
func parseListen(args []string) ([]sshc.Forward, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no meshport:host:port")
	}
	var out []sshc.Forward
	for _, a := range args {
		f, err := sshc.ParseForward(a)
		if err != nil {
			return nil, err
		}
		// Counted, since ParseForward reads a localhost bind as no bind.
		if specFields(a) != 3 || f.Port == 0 {
			return nil, fmt.Errorf("%q: want meshport:host:port, the node listens on its mesh address", a)
		}
		out = append(out, f)
	}
	return out, nil
}

// specFields counts a forward spec's colon-separated fields, ignoring
// colons inside brackets.
func specFields(s string) int {
	n, depth := 1, 0
	for _, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		case ':':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}

// listen carries connections to ports of the node's mesh address to local
// or mesh targets, until interrupted: listen 22:127.0.0.1:22 lets every
// mesh peer reach this device's sshd at its mesh address. The node keeps
// all its peers, since any of them may connect.
func listen(args []string, p proc) int {
	specs, err := parseListen(args)
	if err != nil {
		fmt.Fprintf(p.err, "%s listen: %v\nusage: %s listen meshport:host:port...\n", self, err, self)
		return 2
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return fail(p, "listen", err)
	}
	m, err := startMesh(p, cfg)
	if err != nil {
		return fail(p, "listen", err)
	}
	defer m.Stop()
	logf := func(format string, args ...any) { fmt.Fprintf(p.err, self+" listen: "+format+"\n", args...) }
	for _, f := range specs {
		ln, err := m.ListenTCP(f.Port)
		if err != nil {
			return fail(p, "listen", fmt.Errorf("%s:%d: %w", cfg.Prefix.Addr(), f.Port, err))
		}
		defer ln.Close()
		go func() { relay.Serve(ln, localDialer(m, cfg, f), logf) }()
		logf("%s:%d -> %s", cfg.Prefix.Addr(), f.Port, f.Target())
	}
	waitSignal()
	return 0
}

// waitSignal blocks until SIGINT or SIGTERM.
func waitSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	<-sig
}
