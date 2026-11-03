// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"cmp"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// status prints the compiled-in hosts table, or the given hosts' rows, and
// with -w brings the node up for at most that long and adds each peer's
// live WireGuard state. It returns as soon as the given hosts, or with none
// given every peer, have a handshake.
func status(args []string, p proc) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(p.err)
	wait := fs.Duration("w", 0, "bring the node up and wait up to this long for peer handshakes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return fail(p, "status", err)
	}
	want, err := peerAddrs(cfg, fs.Args())
	if err != nil {
		return fail(p, "status", err)
	}
	var peers []mesh.PeerStatus
	if *wait > 0 {
		m, err := startMesh(p, cfg)
		if err != nil {
			return fail(p, "status", err)
		}
		defer m.Stop()
		if peers, err = waitHandshakes(m.Peers, want, *wait, p.now, p.sleep); err != nil {
			return fail(p, "status", err)
		}
	}
	writeStatus(p.out, cfg, want, peers, *wait > 0, p.now())
	return 0
}

// peerAddrs resolves the hosts status was asked about; each must be a peer.
func peerAddrs(cfg mesh.Config, hosts []string) ([]netip.Addr, error) {
	peers := make(map[netip.Addr]bool, len(cfg.Peers))
	for _, name := range cfg.Peers {
		peers[cfg.Hosts[name]] = true
	}
	var out []netip.Addr
	for _, h := range hosts {
		a, err := cfg.Lookup(h)
		if err != nil {
			return nil, err
		}
		if !peers[a] {
			return nil, fmt.Errorf("%s is not a peer of %s", h, cfg.Name)
		}
		out = append(out, a)
	}
	return out, nil
}

// waitHandshakes polls peers until those at want, or with want empty every
// peer, have a handshake, or d has passed; it returns the last poll.
func waitHandshakes(poll func() ([]mesh.PeerStatus, error), want []netip.Addr, d time.Duration, now func() time.Time, sleep func(time.Duration)) ([]mesh.PeerStatus, error) {
	deadline := now().Add(d)
	for {
		peers, err := poll()
		if err != nil || handshaken(peers, want) || !now().Before(deadline) {
			return peers, err
		}
		sleep(500 * time.Millisecond)
	}
}

// handshaken reports whether the peers at want, or all peers, have a
// handshake.
func handshaken(peers []mesh.PeerStatus, want []netip.Addr) bool {
	n := 0
	for _, pe := range peers {
		if len(want) > 0 && !slices.Contains(want, pe.Addr) {
			continue
		}
		if pe.LastHandshake.IsZero() {
			return false
		}
		n++
	}
	return n > 0 && (len(want) == 0 || n == len(want))
}

// writeStatus renders one row per host, or per host in only, by address;
// live adds the peer columns.
func writeStatus(w io.Writer, cfg mesh.Config, only []netip.Addr, peers []mesh.PeerStatus, live bool, now time.Time) {
	byName := make(map[string]mesh.PeerStatus, len(peers))
	for _, pe := range peers {
		byName[pe.Name] = pe
	}
	names := make([]string, 0, len(cfg.Hosts))
	for n, a := range cfg.Hosts {
		if len(only) == 0 || slices.Contains(only, a) {
			names = append(names, n)
		}
	}
	slices.SortFunc(names, func(a, b string) int { return cmp.Or(cfg.Hosts[a].Compare(cfg.Hosts[b]), cmp.Compare(a, b)) })

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	if !live {
		fmt.Fprintln(tw, "HOST\tADDRESS")
		for _, n := range names {
			fmt.Fprintf(tw, "%s\t%s%s\n", n, cfg.Hosts[n], thisNode(n, cfg))
		}
		return
	}
	fmt.Fprintln(tw, "HOST\tADDRESS\tENDPOINT\tHANDSHAKE\tKEEPALIVE\tBYTES")
	for _, n := range names {
		pe, ok := byName[n]
		if !ok {
			fmt.Fprintf(tw, "%s\t%s%s\n", n, cfg.Hosts[n], thisNode(n, cfg))
			continue
		}
		hs := "never"
		if !pe.LastHandshake.IsZero() {
			hs = now.Sub(pe.LastHandshake).Truncate(time.Second).String() + " ago"
		}
		ep := cmp.Or(pe.Endpoint, "-")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", n, cfg.Hosts[n], ep, hs, pe.Keepalive, pe.Bytes)
	}
}

// thisNode is a trailing cell marking the node's own row.
func thisNode(name string, cfg mesh.Config) string {
	if name == cfg.Name {
		return "\tthis node"
	}
	return ""
}
