// SPDX-License-Identifier: LGPL-3.0-or-later

// Package mesh runs one stunmesh node in userspace: WireGuard on a gVisor
// netstack inside the process, with stunmesh-go's discovery, and dials
// mesh hosts by name from a static table, never the system resolver.
package mesh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tjjh89017/stunmesh-go/userspace"
)

// Config is a node's public config as stunmesh-avahi's gen.py renders it
// for a client node: stunmesh-go's userspace config JSON without the
// private key, plus the mesh's domain and hosts table.
type Config struct {
	// Node is the document as stunmesh-go reads it, but for the private
	// key and log level Start sets.
	Node userspace.Config
	Name string
	// Prefix is the node's tunnel address and the mesh's subnet.
	Prefix netip.Prefix
	Domain string
	// Hosts and Peers hold names in lower case.
	Hosts map[string]netip.Addr
	// Peers names each peer by its WireGuard public key.
	Peers map[[32]byte]string
}

// ParseConfig reads and checks a node config. It refuses one that carries
// a private key: keys are made on the device and never travel in a config
// or a binary.
func ParseConfig(data []byte) (Config, error) {
	var doc struct {
		userspace.Config
		Domain string            `json:"domain"`
		Hosts  map[string]string `json:"hosts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("node config: %w", err)
	}
	if doc.Interface.PrivateKey != "" {
		return Config{}, errors.New("node config holds a private key; keys stay on the device")
	}
	if doc.Name == "" {
		return Config{}, errors.New("node config: no name")
	}
	if doc.Interface.ListenPort == 0 {
		return Config{}, errors.New("node config: no listen_port; the node's fixed UDP port is what keeps it to one process")
	}
	if len(doc.Interface.Addresses) != 1 {
		return Config{}, fmt.Errorf("node config: want one interface address, have %d", len(doc.Interface.Addresses))
	}
	prefix, err := netip.ParsePrefix(doc.Interface.Addresses[0])
	if err != nil {
		return Config{}, fmt.Errorf("node config: %w", err)
	}
	c := Config{
		Node:   doc.Config,
		Name:   doc.Name,
		Prefix: prefix,
		Domain: strings.Trim(doc.Domain, "."),
		Hosts:  make(map[string]netip.Addr, len(doc.Hosts)),
		Peers:  make(map[[32]byte]string, len(doc.Peers)),
	}
	for name, ip := range doc.Hosts {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return Config{}, fmt.Errorf("node config: host %s: %w", name, err)
		}
		c.Hosts[strings.ToLower(name)] = a
	}
	for _, p := range doc.Peers {
		k, err := ParseKey(p.PublicKey)
		if err != nil {
			return Config{}, fmt.Errorf("node config: peer %s: %w", p.Name, err)
		}
		c.Peers[k] = strings.ToLower(p.Name)
	}
	return c, nil
}

// Narrow returns the config with only the peer at addr, for a node that
// serves one session: discovery then does one publish and one lookup, not
// one DHT round trip per peer, and only that peer can reach the node. An
// address that is no peer's, such as this node's own, is an error, not
// the whole mesh.
func (c Config) Narrow(addr netip.Addr) (Config, error) {
	for key, name := range c.Peers {
		if c.Hosts[name] != addr {
			continue
		}
		n := c
		n.Node.Peers = slices.DeleteFunc(slices.Clone(c.Node.Peers), func(p userspace.PeerConfig) bool {
			return strings.ToLower(p.Name) != name
		})
		n.Peers = map[[32]byte]string{key: name}
		return n, nil
	}
	return c, fmt.Errorf("no peer at %s", addr)
}

// Lookup resolves a mesh host from the hosts table only: a node name, the
// same with the mesh domain, or an address literal inside the mesh subnet.
// Names match without regard to case, as DNS names do.
func (c Config) Lookup(host string) (netip.Addr, error) {
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if c.Domain != "" {
		name = strings.TrimSuffix(name, "."+strings.ToLower(c.Domain))
	}
	if a, ok := c.Hosts[name]; ok {
		return a, nil
	}
	if a, err := netip.ParseAddr(host); err == nil && c.Prefix.Masked().Contains(a) {
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("unknown host %q: not in the compiled-in hosts table", host)
}

// ParseKey decodes a WireGuard key in its base64 text form.
func ParseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, fmt.Errorf("key: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// FormatKey is a key's base64 text form, as wg and mesh.yaml write it.
func FormatKey(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }
