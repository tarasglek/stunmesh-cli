// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
)

// startTimeout bounds waiting for a daemon to stop.
const startTimeout = 10 * time.Second

// daemonClient is the node of sm daemon, reached on its socket. Each
// request has a connection of its own, which for a dial becomes the
// stream and for a relay says by being open that the client still
// wants it.
type daemonClient struct {
	cfg  mesh.Config
	sock string
	id   string // Sm-Node
}

// connect connects to the daemon.
func (d *daemonClient) connect(ctx context.Context) (*net.UnixConn, error) {
	var dl net.Dialer
	c, err := dl.DialUnix(ctx, "unix", nil, &net.UnixAddr{Name: d.sock, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("sm daemon: %w", err)
	}
	return c, nil
}

// lockFree reports whether no daemon holds the lock at path.
func lockFree(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close() // releases it
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

// do sends req on a connection of its own. A response other than 2xx or
// 101 is returned as an error with its text. A connection that breaks
// before the answer is tried once more: a daemon that stops for idle
// drops connections it has not taken yet, and none of these requests has
// a body or leaves anything behind unanswered.
func (d *daemonClient) do(req *http.Request) (*http.Response, *http.ClientConn, net.Conn, error) {
	res, cc, conn, err := d.try(req)
	if errors.Is(err, errBroken) && req.Context().Err() == nil {
		res, cc, conn, err = d.try(req)
	}
	return res, cc, conn, err
}

// errBroken marks a request whose connection broke before its answer.
var errBroken = errors.New("connection broken")

func (d *daemonClient) try(req *http.Request) (*http.Response, *http.ClientConn, net.Conn, error) {
	var conn net.Conn
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := d.connect(ctx)
		if err != nil {
			return nil, err
		}
		conn = c
		return c, nil
	}}
	cc, err := t.NewClientConn(req.Context(), "http", "sm:80")
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Sm-Node", d.id)
	res, err := cc.RoundTrip(req)
	if err != nil {
		cc.Close()
		return nil, nil, nil, fmt.Errorf("sm daemon: %w: %w", errBroken, err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols && res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		res.Body.Close()
		cc.Close()
		return nil, nil, nil, errors.New(strings.TrimSpace(string(b)))
	}
	return res, cc, conn, nil
}

func (d *daemonClient) request(ctx context.Context, method, path string, h http.Header) (*http.Response, *http.ClientConn, net.Conn, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://sm"+path, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header = h
	return d.do(req)
}

func (d *daemonClient) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	res, _, conn, err := d.request(ctx, "POST", "/v0/dial", http.Header{
		"Connection": {"Upgrade"}, "Upgrade": {"sm-dial"},
		"Dial-Host": {host}, "Dial-Port": {strconv.Itoa(int(port))},
	})
	if err != nil {
		return nil, err
	}
	body, ok := res.Body.(io.ReadWriteCloser)
	if res.StatusCode != http.StatusSwitchingProtocols || !ok {
		res.Body.Close()
		return nil, fmt.Errorf("sm daemon: dial answered %s", res.Status)
	}
	s := &stream{Conn: conn, body: body, local: &net.TCPAddr{IP: d.cfg.Prefix.Addr().AsSlice()}}
	if a, err := d.cfg.Lookup(host); err == nil {
		s.remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, port))
	}
	return s, nil
}

// stream is a connection dialed through the daemon. Reads and writes go
// through the 101 response's body, which holds whatever was read past
// the response, then the socket; deadlines are the socket's. Its
// addresses are the mesh connection's, as known_hosts needs, the local
// port aside, which only the daemon knows.
type stream struct {
	net.Conn
	body          io.ReadWriteCloser
	local, remote net.Addr
}

func (s *stream) LocalAddr() net.Addr  { return s.local }
func (s *stream) RemoteAddr() net.Addr { return s.remote }

func (s *stream) Read(b []byte) (int, error)  { return s.body.Read(b) }
func (s *stream) Write(b []byte) (int, error) { return s.body.Write(b) }
func (s *stream) Close() error                { return s.body.Close() }

func (s *stream) CloseWrite() error {
	return s.body.(interface{ CloseWrite() error }).CloseWrite()
}

// hold makes a request whose open connection keeps something in the
// daemon, and returns its response and the function that lets it go.
func (d *daemonClient) hold(path string, h http.Header) (*http.Response, func(), error) {
	res, cc, _, err := d.request(context.Background(), "POST", path, h)
	if err != nil {
		return nil, nil, err
	}
	return res, func() { res.Body.Close(); cc.Close() }, nil
}

// UDPRelay has the daemon run the relay. stop ends it at once; were this
// process to die instead, the daemon keeps it while the program it relays
// for still has its port.
func (d *daemonClient) UDPRelay(host string, port uint16) (uint16, func(), error) {
	res, release, err := d.hold("/v0/udp", http.Header{"Dial-Host": {host}, "Dial-Port": {strconv.Itoa(int(port))}})
	if err != nil {
		return 0, nil, err
	}
	n, err := strconv.ParseUint(res.Header.Get("Relay-Port"), 10, 16)
	if err != nil || n == 0 {
		release()
		return 0, nil, errors.New("sm daemon: no Relay-Port")
	}
	return uint16(n), func() {
		if r, cc, _, err := d.request(context.Background(), "DELETE", "/v0/udp/"+strconv.Itoa(int(n)), http.Header{}); err == nil {
			r.Body.Close()
			cc.Close()
		}
		release()
	}, nil
}

func (d *daemonClient) Peers() ([]mesh.PeerStatus, error) {
	res, cc, _, err := d.request(context.Background(), "GET", "/v0/status", http.Header{})
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	defer res.Body.Close()
	var peers []mesh.PeerStatus
	if err := json.NewDecoder(res.Body).Decode(&peers); err != nil {
		return nil, fmt.Errorf("sm daemon: status: %w", err)
	}
	return peers, nil
}

// Close leaves the daemon running for the next applet.
func (d *daemonClient) Close() {}

// down stops the daemon, if one runs.
func (d *daemonClient) down() error {
	res, cc, _, err := d.request(context.Background(), "POST", "/v0/down", http.Header{})
	if err != nil {
		return err
	}
	res.Body.Close()
	cc.Close()
	return nil
}

// downApplet stops the daemon and waits until it has, so a next one can
// start at once.
func downApplet(args []string, p proc) int {
	if len(args) != 0 {
		fmt.Fprintf(p.err, "usage: %s down\n", self)
		return 2
	}
	sock, lock, _, err := daemonPaths(p.getenv)
	if err != nil {
		return fail(p, "down", err)
	}
	d := &daemonClient{sock: sock}
	if err := d.down(); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return 0 // none runs
		}
		return fail(p, "down", err)
	}
	for deadline := time.Now().Add(startTimeout); !lockFree(lock); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			return fail(p, "down", errors.New("the daemon did not stop"))
		}
	}
	return 0
}
