// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tarasglek/stunmesh-avahi/wgdev"
	"github.com/tarasglek/stunmesh-cli/relay"
)

// pairConfig is node i of a two-node mesh "pa"/"pb" with no plugins and
// STUN on a closed port: nothing leaves the host.
func pairConfig(t *testing.T, i int, peerPub [32]byte) Config {
	t.Helper()
	names := []string{"pa", "pb"}
	doc := map[string]any{
		"name":      names[i],
		"interface": map[string]any{"addresses": []string{fmt.Sprintf("10.99.0.%d/24", i+1)}},
		"peers": []any{map[string]any{
			"name": names[1-i], "public_key": FormatKey(peerPub),
			"allowed_ips": []string{fmt.Sprintf("10.99.0.%d/32", 2-i)},
		}},
		"stun":   map[string]any{"addresses": []string{"127.0.0.1:9"}},
		"domain": "mesh.test",
		"hosts":  map[string]string{"pa": "10.99.0.1", "pb": "10.99.0.2"},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func listenPort(t *testing.T, m *Mesh) int {
	t.Helper()
	s, err := m.node.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			p, _ := strconv.Atoi(v)
			return p
		}
	}
	t.Fatal("no listen_port")
	return 0
}

// testKey is a private key of fill bytes. Keys must differ outside the
// bits clamping clears: [32]byte{1} and {2} are the same key.
func testKey(fill byte) (k [32]byte) {
	for i := range k {
		k[i] = fill
	}
	return k
}

// startPair starts two meshes on kernel-picked loopback ports and points
// each at the other, as discovery would.
func startPair(t *testing.T) (a, b *Mesh) {
	t.Helper()
	privA, privB := testKey(1), testKey(2)
	var err error
	if a, err = Start(pairConfig(t, 0, PublicKey(privB)), privA, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Stop)
	if b, err = Start(pairConfig(t, 1, PublicKey(privA)), privB, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	if err := a.node.SetPeerEndpoint(FormatKey(PublicKey(privB)), fmt.Sprintf("127.0.0.1:%d", listenPort(t, b))); err != nil {
		t.Fatal(err)
	}
	if err := b.node.SetPeerEndpoint(FormatKey(PublicKey(privA)), fmt.Sprintf("127.0.0.1:%d", listenPort(t, a))); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// A dials B by name over TCP and UDP through both netstacks and a real
// WireGuard handshake; then Peers names B and shows the handshake.
func TestMeshDialByName(t *testing.T) {
	a, b := startPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := b.ListenTCP(22)
	if err != nil {
		t.Fatal(err)
	}
	if ln.Addr().String() != "10.99.0.2:22" {
		t.Errorf("listening on %v, want the tunnel address", ln.Addr())
	}
	if _, err := b.ListenTCP(22); err == nil {
		t.Error("second listener on one port")
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c, err := a.DialTCP(ctx, "pb.mesh.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello over the mesh")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("hello over the mesh"))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello over the mesh" {
		t.Fatalf("echo = %q, %v", got, err)
	}

	pc, err := b.net.ListenUDPAddrPort(netip.MustParseAddrPort("10.99.0.2:60001"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u, err := a.DialUDP("pb", 60001)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := pc.ReadFrom(buf); err != nil || string(buf[:n]) != "datagram" {
		t.Fatalf("udp = %q, %v", buf[:n], err)
	}

	peers, err := a.Peers()
	if err != nil || len(peers) != 1 {
		t.Fatalf("Peers = %+v, %v", peers, err)
	}
	if p := peers[0]; p.Name != "pb" || p.Addr != netip.MustParseAddr("10.99.0.2") || p.LastHandshake.IsZero() || p.Bytes == 0 {
		t.Errorf("peer = %+v", p)
	}

	if _, err := a.DialTCP(ctx, "nosuch", 22); err == nil || !strings.Contains(err.Error(), "hosts table") {
		t.Errorf("dial of an unknown host: %v", err)
	}
}

// lease finds the node through wgdev while it runs, and its keepalive
// writes reach the device; after Stop the name is free again.
func TestMeshRegistersWithWgdev(t *testing.T) {
	a, _ := startPair(t)
	d, err := wgdev.Read("pa")
	if err != nil || d.PublicKey != PublicKey(testKey(1)) || len(d.Peers) != 1 {
		t.Fatalf("wgdev.Read = %+v, %v", d, err)
	}
	if err := wgdev.SetKeepalive("pa", PublicKey(testKey(2)), 25*time.Second); err != nil {
		t.Fatal(err)
	}
	if d, _ := wgdev.Read("pa"); d.Peers[0].Keepalive != 25*time.Second {
		t.Errorf("keepalive = %v", d.Peers[0].Keepalive)
	}

	// A second node of the same name is refused and leaves the first alone.
	if _, err := Start(a.cfg, testKey(3), nil); err == nil {
		t.Error("second node with one name started")
	}
	a.Stop()
	if _, err := wgdev.Read("pa"); err == nil {
		t.Error("stopped node still answers wgdev")
	}
	again, err := Start(a.cfg, testKey(1), nil)
	if err != nil {
		t.Fatalf("restart under the same name: %v", err)
	}
	again.Stop()
}

func TestTunnelJSON(t *testing.T) {
	s, err := tunnelJSON(json.RawMessage(testConfig), [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Interface struct {
			PrivateKey string `json:"private_key"`
			ListenPort int    `json:"listen_port"`
		} `json:"interface"`
		Log   struct{ Level string } `json:"log"`
		Hosts map[string]string      `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Interface.PrivateKey != FormatKey([32]byte{7}) || doc.Interface.ListenPort != 51820 || doc.Log.Level != "silent" || len(doc.Hosts) != 3 {
		t.Errorf("tunnel = %s", s)
	}
}

// The listen applet's path: a relay serving a mesh listener carries a
// peer's connection to a local target, and ends when the listener closes,
// whose Accept then reports net.ErrClosed rather than gonet's own error.
func TestListenRelay(t *testing.T) {
	a, b := startPair(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				got, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("relayed "), got...))
			}()
		}
	}()
	ln, err := b.ListenTCP(22)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		relay.Serve(ln, func() (net.Conn, error) { return net.Dial("tcp", target.Addr().String()) }, t.Logf)
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := a.DialTCP(ctx, "pb", 22)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("in"))
	_ = c.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(got) != "relayed in" {
		t.Fatalf("through the mesh listener: %q, %v", got, err)
	}

	ln.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay still serving a closed mesh listener")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
	}
}
