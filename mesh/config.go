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
	"strings"
)

// Config is a node's public config as stunmesh-avahi's gen.py renders it
// for a client node: stunmesh-go's mobile tunnel JSON without the private
// key, plus the mesh's domain and hosts table.
type Config struct {
	// Tunnel is the whole document, handed to stunmesh-go as is but for
	// the private key and log level Start sets.
	Tunnel json.RawMessage
	Name   string
	// Prefix is the node's tunnel address and the mesh's subnet.
	Prefix netip.Prefix
	MTU    int
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
		Name      string `json:"name"`
		Interface struct {
			PrivateKey string   `json:"private_key"`
			Addresses  []string `json:"addresses"`
			MTU        int      `json:"mtu"`
		} `json:"interface"`
		Peers []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
		} `json:"peers"`
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
	if len(doc.Interface.Addresses) != 1 {
		return Config{}, fmt.Errorf("node config: want one interface address, have %d", len(doc.Interface.Addresses))
	}
	prefix, err := netip.ParsePrefix(doc.Interface.Addresses[0])
	if err != nil {
		return Config{}, fmt.Errorf("node config: %w", err)
	}
	c := Config{
		Tunnel: json.RawMessage(data),
		Name:   doc.Name,
		Prefix: prefix,
		MTU:    doc.Interface.MTU,
		Domain: strings.Trim(doc.Domain, "."),
		Hosts:  make(map[string]netip.Addr, len(doc.Hosts)),
		Peers:  make(map[[32]byte]string, len(doc.Peers)),
	}
	if c.MTU == 0 {
		c.MTU = 1420 // stunmesh-go's default
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
