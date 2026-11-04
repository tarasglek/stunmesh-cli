// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/tarasglek/stunmesh-avahi/lease" // the client's peers use lease
	"github.com/tarasglek/stunmesh-avahi/wgdev"
	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tjjh89017/stunmesh-go/mobile"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Logger receives the node's log lines; level is debug, info, warn or
// error. Nil discards them.
type Logger func(level, msg string)

// Mesh is a running node: WireGuard on a netstack in this process, its
// stunmesh discovery, and the hosts table to dial by name.
type Mesh struct {
	cfg        Config
	node       *mobile.Node
	net        *netstack.Net
	unregister func()

	mu     sync.Mutex
	relays map[net.PacketConn]struct{} // UDPRelay's open sockets
}

// Start brings the node up with the device's private key: a netstack on
// the node's tunnel address, stunmesh-go's node on it, and the device
// registered with wgdev, so lease reads and configures it as it would a
// kernel interface.
func Start(cfg Config, priv [32]byte, log Logger) (*Mesh, error) {
	if log == nil {
		log = func(string, string) {}
	}
	js, err := tunnelJSON(cfg.Tunnel, priv)
	if err != nil {
		return nil, err
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Prefix.Addr()}, nil, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	node, err := mobile.NewNodeWithTun(js, tdev, listener{log})
	if err != nil {
		tdev.Close()
		return nil, err
	}
	// Registered before Start: the controller's first cycle runs at once
	// and lease reads the device in it.
	unregister, err := wgdev.Register(cfg.Name, backend{node})
	if err != nil {
		tdev.Close()
		return nil, err
	}
	if err := node.Start(); err != nil { // closes tdev
		unregister()
		return nil, err
	}
	return &Mesh{cfg: cfg, node: node, net: tnet, unregister: unregister, relays: map[net.PacketConn]struct{}{}}, nil
}

// tunnelJSON is the config stunmesh-go gets: the node config with the
// private key put in and wireguard-go's own log silenced, since it prints
// to stdout, which is nc's data stream.
func tunnelJSON(tunnel json.RawMessage, priv [32]byte) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal(tunnel, &doc); err != nil {
		return "", fmt.Errorf("node config: %w", err)
	}
	iface, _ := doc["interface"].(map[string]any)
	if iface == nil {
		return "", errors.New("node config: no interface")
	}
	iface["private_key"] = FormatKey(priv)
	doc["log"] = map[string]any{"level": "silent"}
	b, err := json.Marshal(doc)
	return string(b), err
}

// Config is the node config the mesh runs.
func (m *Mesh) Config() Config { return m.cfg }

// DialTCP connects to port on a mesh host named as Lookup takes it.
func (m *Mesh) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	a, err := m.cfg.Lookup(host)
	if err != nil {
		return nil, err
	}
	return m.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a, port))
}

// DialUDP returns a datagram conn to port on a mesh host.
func (m *Mesh) DialUDP(host string, port uint16) (net.Conn, error) {
	a, err := m.cfg.Lookup(host)
	if err != nil {
		return nil, err
	}
	return m.net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(a, port))
}

// UDPRelay forwards datagrams between a new UDP port on 127.0.0.1 and
// port on a mesh host, for a program with its own UDP client, such as
// mosh-client: it sends to 127.0.0.1 and the returned port, and its
// datagrams leave through the node. relay.UDP says whose datagrams are
// taken. The relay runs until stop, which is idempotent, or Stop.
func (m *Mesh) UDPRelay(host string, port uint16) (localPort uint16, stop func(), err error) {
	remote, err := m.DialUDP(host, port)
	if err != nil {
		return 0, nil, err
	}
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		remote.Close()
		return 0, nil, err
	}
	m.mu.Lock()
	m.relays[local] = struct{}{}
	m.mu.Unlock()
	go relay.UDP(local, remote)
	stop = func() {
		m.mu.Lock()
		delete(m.relays, local)
		m.mu.Unlock()
		local.Close() // relay.UDP closes the mesh side
	}
	return uint16(local.LocalAddr().(*net.UDPAddr).Port), stop, nil
}

// ListenTCP listens on port of the node's tunnel address, for connections
// from mesh peers. Nothing outside the mesh can reach it: the address
// exists only inside this process's netstack.
func (m *Mesh) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := m.net.ListenTCPAddrPort(netip.AddrPortFrom(m.cfg.Prefix.Addr(), port))
	if err != nil {
		return nil, err
	}
	return &meshListener{TCPListener: ln}, nil
}

// meshListener makes a netstack listener report its own close as
// net.ErrClosed, as net.Listener's users expect: gonet's Accept after
// Close fails with an opaque "endpoint is in invalid state" instead, which
// a relay cannot tell from a transient error.
type meshListener struct {
	*gonet.TCPListener
	closed atomic.Bool
}

func (l *meshListener) Close() error {
	l.closed.Store(true)
	return l.TCPListener.Close()
}

func (l *meshListener) Accept() (net.Conn, error) {
	c, err := l.TCPListener.Accept()
	if err != nil && l.closed.Load() {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: net.ErrClosed}
	}
	return c, err
}

// PeerStatus is one peer as WireGuard sees it, named from the config.
type PeerStatus struct {
	Name string
	Addr netip.Addr
	wgdev.Peer
}

// Peers reads the device's live peer state.
func (m *Mesh) Peers() ([]PeerStatus, error) {
	d, err := backend{m.node}.Read()
	if err != nil {
		return nil, err
	}
	return peerStatus(m.cfg, d), nil
}

func peerStatus(cfg Config, d wgdev.Device) []PeerStatus {
	out := make([]PeerStatus, 0, len(d.Peers))
	for _, p := range d.Peers {
		name := cfg.Peers[p.PublicKey]
		out = append(out, PeerStatus{Name: name, Addr: cfg.Hosts[name], Peer: p})
	}
	return out
}

// Stop closes UDPRelay's relays, takes the node down, then its device out
// of wgdev. The order mirrors Start's: while the node stops, the device
// stays registered and answers "node not running", so lease falls through
// to its inner store; unregistered, the name would fall through to netlink
// and a kernel interface of the same name. Once node.Stop returns, lease is closed and
// has waited for its watches, so nothing calls wgdev for the name again.
func (m *Mesh) Stop() {
	m.mu.Lock()
	for r := range m.relays {
		r.Close() // relay.UDP closes the mesh side
	}
	clear(m.relays)
	m.mu.Unlock()
	m.node.Stop()
	m.unregister()
}

// backend answers wgdev for the node's device.
type backend struct{ node *mobile.Node }

func (b backend) Read() (wgdev.Device, error) {
	s, err := b.node.IpcGet()
	if err != nil {
		return wgdev.Device{}, err
	}
	return wgdev.ParseUAPI(s)
}

func (b backend) SetKeepalive(peer [32]byte, interval time.Duration) error {
	if interval < 0 || interval > 65535*time.Second {
		return fmt.Errorf("keepalive %v out of range", interval)
	}
	return b.node.SetPeerKeepalive(FormatKey(peer), int32(interval/time.Second))
}

// listener turns the node's events into log lines.
type listener struct{ log Logger }

func (l listener) OnStateChanged(state string)       { l.log("debug", "node "+state) }
func (l listener) OnLog(level, message string)       { l.log(level, message) }
func (l listener) OnEvent(kind, peer, detail string) { l.log("debug", kind+" "+peer+" "+detail) }
