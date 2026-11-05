// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	_ "github.com/tarasglek/stunmesh-avahi/lease" // the client's peers use lease
	"github.com/tarasglek/stunmesh-avahi/wgdev"
	"github.com/tarasglek/stunmesh-cli/relay"
	_ "github.com/tjjh89017/stunmesh-go/builtin/all" // the plugins nodes may name
	"github.com/tjjh89017/stunmesh-go/userspace"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Logger receives the node's log lines; level is debug, info, warn or
// error. Nil discards them.
type Logger func(level, msg string)

// Mesh is a running node: WireGuard on a netstack in this process, its
// stunmesh discovery, and the hosts table to dial by name.
type Mesh struct {
	cfg        Config
	node       *userspace.Node
	dev        backend
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
	// wireguard-go's own log is silenced: it prints to stdout, which is
	// nc's data stream.
	ucfg := cfg.Node
	ucfg.Interface.PrivateKey = FormatKey(priv)
	ucfg.Log.Level = "silent"
	// The node opens its tun in Start, at the config's MTU; the netstack
	// on it is what the mesh dials and listens through.
	var tnet *netstack.Net
	newTun := func(mtu int) (tun.Device, error) {
		tdev, n, err := netstack.CreateNetTUN([]netip.Addr{cfg.Prefix.Addr()}, nil, mtu)
		if err != nil {
			return nil, fmt.Errorf("netstack: %w", err)
		}
		tnet = n
		return tdev, nil
	}
	node, err := userspace.New(&ucfg, newTun, userspace.Options{Listener: listener{log}, DNSServers: dnsServers("/etc/resolv.conf")})
	if err != nil {
		return nil, err
	}
	// Registered before Start: the controller's first cycle runs at once
	// and lease reads the device in it.
	dev := backend{node, priv}
	unregister, err := wgdev.Register(cfg.Name, dev)
	if err != nil {
		return nil, err
	}
	if err := node.Start(); err != nil {
		unregister()
		return nil, err
	}
	return &Mesh{cfg: cfg, node: node, dev: dev, net: tnet, unregister: unregister, relays: map[net.PacketConn]struct{}{}}, nil
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
	return ln, nil
}

// PeerStatus is one peer as WireGuard sees it, named from the config.
type PeerStatus struct {
	Name string
	Addr netip.Addr
	wgdev.Peer
}

// Peers reads the device's live peer state.
func (m *Mesh) Peers() ([]PeerStatus, error) {
	d, err := m.dev.Read()
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

// backend answers wgdev for the node's device. The node's Status holds
// no private key; wgdev's Device does, so it comes from the config.
type backend struct {
	node *userspace.Node
	priv [32]byte
}

func (b backend) Read() (wgdev.Device, error) {
	s, err := b.node.Status()
	if err != nil {
		return wgdev.Device{}, err
	}
	d := wgdev.Device{PrivateKey: b.priv, PublicKey: PublicKey(b.priv), ListenPort: s.ListenPort}
	for _, p := range s.Peers {
		pub, err := ParseKey(p.PublicKey)
		if err != nil {
			return wgdev.Device{}, fmt.Errorf("status: %w", err)
		}
		d.Peers = append(d.Peers, wgdev.Peer{
			PublicKey: pub, Endpoint: p.Endpoint, LastHandshake: p.LastHandshake,
			Keepalive: time.Duration(p.Keepalive) * time.Second, Bytes: p.RxBytes + p.TxBytes,
		})
	}
	return d, nil
}

func (b backend) SetKeepalive(peer [32]byte, interval time.Duration) error {
	if interval < 0 || interval > 65535*time.Second {
		return fmt.Errorf("keepalive %v out of range", interval)
	}
	return b.node.SetPeerKeepalive(FormatKey(peer), int(interval/time.Second))
}

// listener turns the node's events into log lines.
type listener struct{ log Logger }

func (l listener) OnStateChanged(state string)       { l.log("debug", "node "+state) }
func (l listener) OnLog(level, message string)       { l.log(level, message) }
func (l listener) OnEvent(kind, peer, detail string) { l.log("debug", kind+" "+peer+" "+detail) }

// fallbackDNS is what STUN and plugin lookups use where the system has no
// resolver config: public resolvers reachable from most networks, as
// stunmesh-go's mobile wrapper defaults to.
var fallbackDNS = []string{"8.8.8.8:53", "1.1.1.1:53", "[2001:4860:4860::8888]:53"}

// dnsServers is the node's nameserver list: none, so the system's, when
// resolvConf exists, else fallbackDNS. Android has no /etc/resolv.conf,
// and Go's resolver then asks [::1]:53, where nothing answers: discovery
// fails and the node never publishes its endpoint.
func dnsServers(resolvConf string) func() []string {
	if _, err := os.Stat(resolvConf); err == nil {
		return nil
	}
	return func() []string { return fallbackDNS }
}
