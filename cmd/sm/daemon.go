// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tarasglek/stunmesh-cli/sshc"
)

// sm daemon runs this device's node once for all of the user's sm
// processes: one WireGuard key can only be one node, and a node that is
// already up needs no join. The others reach it over HTTP/1.1 on a unix
// socket, in the shape of Tailscale's LocalAPI:
//
//	POST   /v0/dial           Upgrade: sm-dial, Dial-Host, Dial-Port: 101, then the TCP stream
//	POST   /v0/udp            Dial-Host, Dial-Port: Relay-Port, a UDP relay's 127.0.0.1 port, held open
//	DELETE /v0/udp/{port}     closes that relay
//	POST   /v0/listen         Listen-Port, Dial-Host, Dial-Port: held open while the node listens
//	GET    /v0/status         the peers, as JSON
//	POST   /v0/down           stops the daemon
//
// Hosts are names from the hosts table, as everywhere in sm, never DNS.
// Every request names the node it was meant for in Sm-Node, so a client
// with another config or key is refused instead of served by the wrong
// node. Only the daemon's own user may connect, not even root: sudo sm
// down is refused, as on Android, where there is no other user.

// daemonPaths is where the daemon's socket, lock and log live:
// $XDG_RUNTIME_DIR, private to the user, else the key's directory.
func daemonPaths(getenv func(string) string) (sock, lock, log string, err error) {
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		key, err := keyPath(getenv)
		if err != nil {
			return "", "", "", err
		}
		dir = filepath.Dir(key)
	}
	return filepath.Join(dir, "sm.sock"), filepath.Join(dir, "sm.lock"), filepath.Join(dir, "sm.log"), nil
}

// nodeID names the node a config and key make, for Sm-Node: the key's
// bytes, so that a key made anew under a running daemon is noticed.
func nodeID(config, key []byte) string {
	h := sha256.New()
	h.Write(config)
	h.Write([]byte{0})
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// daemonNode is what the daemon serves of a node; *mesh.Mesh in sm.
type daemonNode interface {
	meshListener
	DialUDP(host string, port uint16) (net.Conn, error)
	Peers() ([]mesh.PeerStatus, error)
}

// server answers the daemon's requests.
type server struct {
	m    daemonNode
	cfg  mesh.Config
	id   string
	logf func(format string, args ...any)
	down func() // POST /v0/down; set by serve

	mu     sync.Mutex
	relays map[uint16]*udpRelay
}

func newServer(m daemonNode, cfg mesh.Config, id string, logf func(string, ...any)) *server {
	return &server{m: m, cfg: cfg, id: id, logf: logf, relays: map[uint16]*udpRelay{}}
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0/dial", s.dial)
	mux.HandleFunc("POST /v0/udp", s.udp)
	mux.HandleFunc("DELETE /v0/udp/{port}", s.udpDelete)
	mux.HandleFunc("POST /v0/listen", s.listen)
	mux.HandleFunc("GET /v0/status", s.status)
	mux.HandleFunc("POST /v0/down", s.stop)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// sm down must reach a daemon of any node, to replace it.
		if r.Header.Get("Sm-Node") != s.id && r.URL.Path != "/v0/down" {
			http.Error(w, "sm daemon runs another node config or key; sm down stops it", http.StatusConflict)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// dialTarget reads a request's Dial-Host and Dial-Port.
func dialTarget(h http.Header) (string, uint16, error) {
	host := h.Get("Dial-Host")
	port, err := strconv.ParseUint(h.Get("Dial-Port"), 10, 16)
	if host == "" || err != nil || port == 0 {
		return "", 0, errors.New("want Dial-Host and Dial-Port")
	}
	return host, uint16(port), nil
}

// dial connects to a mesh host and, once connected, switches the request's
// connection to a plain stream to it, as Tailscale's /localapi/v0/dial.
func (s *server) dial(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "sm-dial" {
		http.Error(w, "want Upgrade: sm-dial", http.StatusBadRequest)
		return
	}
	host, port, err := dialTarget(r.Header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	c, err := s.m.DialTCP(ctx, host, port)
	cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		c.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The client sends nothing before the 101; bytes read past the
	// request would be lost, so they end the stream instead.
	if brw.Reader.Buffered() > 0 {
		conn.Close()
		c.Close()
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: sm-dial\r\n\r\n"); err != nil {
		conn.Close()
		c.Close()
		return
	}
	relay.Pipe(conn, c)
}

// udpRelay is a UDP relay the daemon runs for a client: mesh.UDPRelay's,
// with what the daemon needs to know when to end it.
type udpRelay struct {
	local  net.PacketConn
	sender atomic.Pointer[net.UDPAddr] // the program's address, nil until it sends
	done   chan struct{}               // closed when the relay ends
	orphan bool                        // its request has closed; under server.mu
}

// udp starts a relay to a mesh host and answers with its port, then holds
// the request for as long as the client wants the relay. A client that
// goes away without DELETE may leave the program it relayed for running,
// as when sm mosh is killed and mosh-client is not: the relay outlives
// the request while the program still has its port, which reap checks.
func (s *server) udp(w http.ResponseWriter, r *http.Request) {
	host, port, err := dialTarget(r.Header)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	remote, err := s.m.DialUDP(host, port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		remote.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lport := uint16(local.LocalAddr().(*net.UDPAddr).Port)
	u := &udpRelay{local: local, done: make(chan struct{})}
	s.mu.Lock()
	s.relays[lport] = u
	s.mu.Unlock()
	go func() {
		relay.UDP(local, remote, func(a net.Addr) {
			if ua, ok := a.(*net.UDPAddr); ok {
				u.sender.Store(ua)
			}
		})
		s.mu.Lock()
		if s.relays[lport] == u {
			delete(s.relays, lport)
		}
		s.mu.Unlock()
		close(u.done)
	}()
	w.Header().Set("Relay-Port", strconv.Itoa(int(lport)))
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	select {
	case <-u.done:
		return
	case <-r.Context().Done():
	}
	s.mu.Lock()
	u.orphan = true
	s.mu.Unlock()
	s.reap()
}

func (s *server) udpDelete(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.ParseUint(r.PathValue("port"), 10, 16)
	s.mu.Lock()
	u := s.relays[uint16(port)]
	s.mu.Unlock()
	if u == nil {
		http.Error(w, "no such relay", http.StatusNotFound)
		return
	}
	u.local.Close()
	<-u.done
}

// reap ends the relays whose request has closed and whose program no
// longer has the port it last sent from, and reports whether any relay is
// left. Another program that takes the freed port keeps the relay too,
// until it exits: the relay never knew its program, only a port, and any
// local sender may take it over after hopAfter, as before the daemon.
func (s *server) reap() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := false
	for _, u := range s.relays {
		if a := u.sender.Load(); u.orphan && (a == nil || !bound(a)) {
			u.local.Close()
		} else {
			live = true
		}
	}
	return live
}

// bound reports whether some socket has the UDP address a, by binding it:
// without SO_REUSEADDR the bind fails with EADDRINUSE if one does. It
// needs no /proc/net or sock_diag, which Android keeps from apps, and
// sends the program nothing. Any other failure counts as bound, the safe
// answer for a relay.
func bound(a *net.UDPAddr) bool {
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return !errors.Is(err, syscall.EADDRNOTAVAIL)
	}
	c.Close()
	return false
}

// listen listens on a port of the node's mesh address and carries each
// connection to the target while the request is held.
func (s *server) listen(w http.ResponseWriter, r *http.Request) {
	lport, err := strconv.ParseUint(r.Header.Get("Listen-Port"), 10, 16)
	host, port, terr := dialTarget(r.Header)
	if err != nil || lport == 0 || terr != nil {
		http.Error(w, "want Listen-Port, Dial-Host and Dial-Port", http.StatusBadRequest)
		return
	}
	stop, err := forward(s.m, s.cfg, sshc.Forward{Port: uint16(lport), Host: host, HostPort: port}, s.logf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer stop()
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	<-r.Context().Done()
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	peers, err := s.m.Peers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peers)
}

func (s *server) stop(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	go s.down()
}

// closeAll ends every relay, for the daemon's exit; listeners end with
// their requests.
func (s *server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.relays {
		u.local.Close()
	}
}

// activity keeps the daemon up while any client is connected and stops
// it once none has been for idle, unless busy, asked then, says something
// still needs it; then it waits another idle. One timer, armed when the
// last client goes; a firing that finds the deadline moved does nothing.
type activity struct {
	idle time.Duration // 0: never stop
	busy func() bool
	stop func()

	mu       sync.Mutex
	n        int
	closing  bool
	deadline time.Time
	timer    *time.Timer
}

// add counts a new client, unless the daemon is stopping.
func (a *activity) add() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return false
	}
	a.n++
	return true
}

// done counts a client gone.
func (a *activity) done() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.n--; a.n == 0 {
		a.arm()
	}
}

// arm starts the idle wait; a.mu is held.
func (a *activity) arm() {
	if a.idle <= 0 || a.closing {
		return
	}
	a.deadline = time.Now().Add(a.idle)
	if a.timer == nil {
		a.timer = time.AfterFunc(a.idle, a.fire)
	} else {
		a.timer.Reset(a.idle)
	}
}

func (a *activity) fire() {
	a.mu.Lock()
	if a.n > 0 || a.closing || time.Now().Before(a.deadline) {
		a.mu.Unlock()
		return
	}
	if a.busy != nil && a.busy() {
		a.arm()
		a.mu.Unlock()
		return
	}
	a.closing = true
	a.mu.Unlock()
	a.stop()
}

// close takes no more clients.
func (a *activity) close() {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
}

// clientListener admits connections from this user only, and counts each
// in act while it is open.
type clientListener struct {
	*net.UnixListener
	act *activity
}

func (l clientListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if uid, err := peerUID(c); err != nil || uid != os.Getuid() {
			c.Close()
			continue
		}
		if !l.act.add() {
			c.Close()
			return nil, net.ErrClosed
		}
		return &clientConn{UnixConn: c, done: l.act.done}, nil
	}
}

// peerUID is the user of the process at the other end of c.
func peerUID(c *net.UnixConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return int(cred.Uid), nil
}

// clientConn is an admitted connection; its first Close counts it gone.
// The *net.UnixConn is embedded so that a hijacked stream keeps
// CloseWrite.
type clientConn struct {
	*net.UnixConn
	once sync.Once
	done func()
}

func (c *clientConn) Close() error {
	err := c.UnixConn.Close()
	c.once.Do(c.done)
	return err
}

// daemonApplet runs the node for the user's other sm processes until sm
// down, a signal, or idle with no clients. With -bg, as other applets
// start it, it reports on fd 3 once it serves ("ok"), or why it cannot,
// and logs to the log file next to its socket.
func daemonApplet(args []string, p proc) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(p.err)
	idle := fs.Duration("idle", 5*time.Minute, "exit after this long with no clients; 0 never")
	bg := fs.Bool("bg", false, "started by an applet: report on fd 3, log to a file")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	var once sync.Once
	report := func(string) {}
	if *bg {
		// Not for the daemon's children, such as stunmesh-go's exec and
		// shell plugins, which would hold the applet's wait open.
		syscall.CloseOnExec(3)
		f := os.NewFile(3, "report")
		report = func(msg string) { once.Do(func() { fmt.Fprintln(f, msg); f.Close() }) }
	}
	if err := serveDaemon(p, *idle, *bg, report); err != nil {
		report(err.Error())
		return fail(p, "daemon", err)
	}
	return 0
}

// errBusy is the report of a daemon that finds another holding the lock.
var errBusy = errors.New("busy")

func serveDaemon(p proc, idle time.Duration, bg bool, report func(string)) error {
	b, err := p.config()
	if err != nil {
		return err
	}
	cfg, err := mesh.ParseConfig(b)
	if err != nil {
		return err
	}
	key, err := keyPath(p.getenv)
	if err != nil {
		return err
	}
	keyBytes, _ := os.ReadFile(key) // startMesh reports a missing key
	sock, lockPath, logPath, err := daemonPaths(p.getenv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return err
	}
	// The lock, held until exit, makes this the only daemon of the
	// socket; whoever holds it may remove a socket left by a dead one.
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			report(errBusy.Error())
			return fmt.Errorf("one runs already on %s", sock)
		}
		return err
	}
	if bg {
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		p.err = f
	}
	m, err := startMesh(p, cfg, 1)
	if err != nil {
		return err
	}
	defer m.Stop()
	if err := os.Remove(sock); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logf := func(format string, args ...any) { fmt.Fprintf(p.err, self+" daemon: "+format+"\n", args...) }
	logf("serving %s on %s", cfg.Name, sock)
	err = serve(ctx, ln, newServer(m, cfg, nodeID(b, keyBytes), logf), idle, func() { report("ok") })
	logf("stopped")
	return err
}

// serve answers s's requests on ln until ctx is done, POST /v0/down, or
// idle with no clients, then closes ln, which removes its socket. ready is
// called once ln is served.
func serve(ctx context.Context, ln *net.UnixListener, s *server, idle time.Duration, ready func()) error {
	var once sync.Once
	act := &activity{idle: idle, busy: s.reap}
	stop := func() {
		once.Do(func() {
			act.close()
			ln.Close()
		})
	}
	act.stop, s.down = stop, stop
	act.mu.Lock()
	act.arm()
	act.mu.Unlock()
	defer context.AfterFunc(ctx, stop)()
	srv := &http.Server{Handler: s.handler()}
	ready()
	err := srv.Serve(clientListener{ln, act})
	stop()
	srv.Close()
	s.closeAll()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}
