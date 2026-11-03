// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tarasglek/stunmesh-avahi/wgdev"
	"github.com/tarasglek/stunmesh-cli/mesh"
)

const testConfig = `{
  "name": "desk-cli",
  "interface": {"addresses": ["10.200.0.8/24"], "listen_port": 51820},
  "peers": [{"name": "remote-01", "public_key": "7NkaedCuhiw0u6VLDY1xm4ywp+eZLYUT643Ry53LF04=", "allowed_ips": ["10.200.0.5/32"]},
            {"name": "lap1", "public_key": "WB3BdFtSnifYp3B+mU0Wy5lN4+FevBQs6C+rk7/ouD0=", "allowed_ips": ["10.200.0.2/32"]}],
  "domain": "mesh.internal",
  "hosts": {"remote-01": "10.200.0.5", "lap1": "10.200.0.2", "desk-cli": "10.200.0.8"}
}`

// Without -w, status needs neither the key nor the network: it prints the
// compiled-in table by address.
func TestStatusOffline(t *testing.T) {
	code, out, errs := runEnv(map[string]string{"config": testConfig}, "status")
	if code != 0 {
		t.Fatalf("status: %d %q", code, errs)
	}
	want := "HOST       ADDRESS\nlap1       10.200.0.2\nremote-01  10.200.0.5\ndesk-cli   10.200.0.8  this node\n"
	if out != want {
		t.Errorf("status:\n%s\nwant:\n%s", out, want)
	}
}

// A binary built without NODE has config/ with only its README.
func TestReadConfig(t *testing.T) {
	if _, err := readConfig(fstest.MapFS{"config/README.md": {}}); err == nil || !strings.Contains(err.Error(), "no node config compiled in") {
		t.Errorf("readConfig without node.json: %v", err)
	}
	b, err := readConfig(fstest.MapFS{"config/node.json": {Data: []byte(testConfig)}})
	if err != nil || string(b) != testConfig {
		t.Errorf("readConfig = %q, %v", b, err)
	}
}

func TestStatusNoKey(t *testing.T) {
	env := map[string]string{"config": testConfig, "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	code, _, errs := runEnv(env, "status", "-w", "1s")
	if code != 1 || !strings.Contains(errs, "run sm keygen") {
		t.Errorf("status -w without a key: %d %q", code, errs)
	}
}

func TestWriteStatusLive(t *testing.T) {
	cfg, err := mesh.ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	peers := testPeers(now)
	var b strings.Builder
	writeStatus(&b, cfg, nil, peers, true, now)
	for _, want := range []string{
		"lap1       10.200.0.2  -                   never      0s",
		"remote-01  10.200.0.5  203.0.113.40:51823  42s ago    25s        1234",
		"desk-cli   10.200.0.8  this node\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	writeStatus(&b, cfg, []netip.Addr{netip.MustParseAddr("10.200.0.5")}, peers, true, now)
	if strings.Contains(b.String(), "lap1") || !strings.Contains(b.String(), "remote-01") {
		t.Errorf("only remote-01:\n%s", b.String())
	}
}

func testPeers(now time.Time) []mesh.PeerStatus {
	return []mesh.PeerStatus{
		{Name: "remote-01", Addr: netip.MustParseAddr("10.200.0.5"), Peer: wgdev.Peer{Endpoint: "203.0.113.40:51823", LastHandshake: now.Add(-42 * time.Second), Keepalive: 25 * time.Second, Bytes: 1234}},
		{Name: "lap1", Addr: netip.MustParseAddr("10.200.0.2"), Peer: wgdev.Peer{}},
	}
}

func TestHandshaken(t *testing.T) {
	peers := testPeers(time.Unix(1000, 0))
	r1, lap1 := netip.MustParseAddr("10.200.0.5"), netip.MustParseAddr("10.200.0.2")
	for _, tc := range []struct {
		peers []mesh.PeerStatus
		want  []netip.Addr
		ok    bool
	}{
		{peers, nil, false},                    // lap1 has none
		{peers[:1], nil, true},                 // all peers up
		{peers, []netip.Addr{r1}, true},        // only r1 asked for
		{peers, []netip.Addr{r1, lap1}, false}, // lap1 asked for, down
		{nil, nil, false},                      // nothing to report
		{peers[1:], []netip.Addr{r1}, false},   // r1 missing from the device
	} {
		if got := handshaken(tc.peers, tc.want); got != tc.ok {
			t.Errorf("handshaken(%d peers, %v) = %v", len(tc.peers), tc.want, got)
		}
	}
}

// waitHandshakes returns on the poll that shows the handshake, or at the
// deadline; a fake clock that sleep advances keeps it instant.
func TestWaitHandshakes(t *testing.T) {
	r1 := netip.MustParseAddr("10.200.0.5")
	clock := time.Unix(1000, 0)
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { clock = clock.Add(d) }
	polls := 0
	poll := func() ([]mesh.PeerStatus, error) {
		polls++
		pe := mesh.PeerStatus{Addr: r1}
		if polls == 3 {
			pe.LastHandshake = clock
		}
		return []mesh.PeerStatus{pe}, nil
	}
	peers, err := waitHandshakes(poll, []netip.Addr{r1}, time.Minute, now, sleep)
	if err != nil || polls != 3 || peers[0].LastHandshake.IsZero() || clock != time.Unix(1001, 0) {
		t.Errorf("returned after %d polls at %v: %+v, %v", polls, clock, peers, err)
	}

	polls, clock = -100, time.Unix(1000, 0) // never handshakes in time
	if peers, err := waitHandshakes(poll, nil, 2*time.Second, now, sleep); err != nil || !peers[0].LastHandshake.IsZero() || clock != time.Unix(1002, 0) {
		t.Errorf("deadline: at %v, %+v, %v", clock, peers, err)
	}
}

func TestStatusHostArgs(t *testing.T) {
	env := map[string]string{"config": testConfig}
	code, out, _ := runEnv(env, "status", "remote-01.mesh.internal")
	if code != 0 || out != "HOST       ADDRESS\nremote-01  10.200.0.5\n" {
		t.Errorf("status remote-01: %d %q", code, out)
	}
	for host, msg := range map[string]string{"nosuch": "not in the compiled-in hosts table", "desk-cli": "not a peer"} {
		if code, _, errs := runEnv(env, "status", host); code != 1 || !strings.Contains(errs, msg) {
			t.Errorf("status %s: %d %q", host, code, errs)
		}
	}
}
