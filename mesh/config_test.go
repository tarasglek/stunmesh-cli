// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"net/netip"
	"strings"
	"testing"
)

const deskKey = "saKn2CjHezboUQd+DSEK2lqkx/w56TAGGRz3cY4WBAE="

// testConfig is a node.json as gen.py renders it, cut to two peers.
const testConfig = `{
  "name": "desk-cli",
  "interface": {"addresses": ["10.200.0.8/24"], "listen_port": 51820, "protocol": "ipv4"},
  "peers": [
    {"name": "desk", "public_key": "` + deskKey + `", "allowed_ips": ["10.200.0.1/32"], "plugin": "leased", "persistent_keepalive": 25},
    {"name": "Remote-01", "public_key": "7NkaedCuhiw0u6VLDY1xm4ywp+eZLYUT643Ry53LF04=", "allowed_ips": ["10.200.0.5/32"], "plugin": "leased", "persistent_keepalive": 25}
  ],
  "plugins": [{"instance": "dht", "type": "builtin", "name": "opendht", "config": {"endpoints": ["http://dhtproxy2.jami.net"]}}],
  "stun": {"addresses": ["stun.l.google.com:19302"]},
  "refresh_interval_seconds": 60,
  "domain": "mesh.internal",
  "hosts": {"desk": "10.200.0.1", "Remote-01": "10.200.0.5", "desk-cli": "10.200.0.8"}
}`

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "desk-cli" || c.Prefix != netip.MustParsePrefix("10.200.0.8/24") || c.MTU != 1420 || c.Domain != "mesh.internal" {
		t.Errorf("config = %+v", c)
	}
	k, _ := ParseKey(deskKey)
	r1, _ := ParseKey("7NkaedCuhiw0u6VLDY1xm4ywp+eZLYUT643Ry53LF04=")
	if c.Peers[k] != "desk" || c.Peers[r1] != "remote-01" || c.Hosts["remote-01"] != netip.MustParseAddr("10.200.0.5") || len(c.Peers) != 2 || len(c.Hosts) != 3 {
		t.Errorf("peers %v hosts %v", c.Peers, c.Hosts)
	}
}

func TestParseConfigRejects(t *testing.T) {
	for name, tc := range map[string]struct{ from, to, err string }{
		"private key":   {`"listen_port"`, `"private_key": "x", "listen_port"`, "private key"},
		"no name":       {`"name": "desk-cli"`, `"name": ""`, "no name"},
		"two addresses": {`["10.200.0.8/24"]`, `["10.200.0.8/24", "fd00::8/64"]`, "one interface address"},
		"bare address":  {`["10.200.0.8/24"]`, `["10.200.0.8"]`, "netip.ParsePrefix"},
		"bad host":      {`"desk": "10.200.0.1"`, `"desk": "desk.lan"`, "host desk"},
		"bad peer key":  {deskKey, "AAAA", "peer desk"},
		"not json":      {`{`, `[`, "node config"},
	} {
		_, err := ParseConfig([]byte(strings.Replace(testConfig, tc.from, tc.to, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.err)
		}
	}
}

func TestLookup(t *testing.T) {
	c, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"remote-01":                "10.200.0.5",
		"remote-01.mesh.internal":  "10.200.0.5",
		"remote-01.mesh.internal.": "10.200.0.5",
		"Remote-01.Mesh.Internal":  "10.200.0.5",
		"10.200.0.5":               "10.200.0.5",
		"10.200.0.200":             "10.200.0.200", // in the mesh, not yet named
	} {
		if a, err := c.Lookup(host); err != nil || a.String() != want {
			t.Errorf("Lookup(%q) = %v, %v; want %s", host, a, err, want)
		}
	}
	for _, host := range []string{"nosuch", "remote-01.example.com", "8.8.8.8", "localhost", ""} {
		_, err := c.Lookup(host)
		if err == nil || !strings.Contains(err.Error(), "not in the compiled-in hosts table") {
			t.Errorf("Lookup(%q) err = %v", host, err)
		}
	}
}
