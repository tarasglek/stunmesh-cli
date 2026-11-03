// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tarasglek/stunmesh-cli/mesh"
	"github.com/tarasglek/stunmesh-cli/relay"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const sshUsage = "usage: %s ssh [-v] [-N] [-i identity]... [-L [bind:]port:host:hostport]... [-R [bind:]port:host:hostport]... [-p port] [-l user] [user@]host [command...]\n"

type sshArgs struct {
	identities []string
	local      []sshc.Forward
	remote     []sshc.Forward
	port       uint16
	user, host string
	command    string   // the command words joined, as ssh sends them
	args       []string // the command words, for mosh-server to exec
	noCommand  bool     // -N
	verbose    int      // -v, -vv
}

// parseSSHArgs reads the OpenSSH options the applet supports, as
// "-L spec" or "-Lspec". As in ssh, options may come before or after the
// destination, and "--" or the first word after the destination starts
// the command, joined with spaces as ssh joins it.
func parseSSHArgs(args []string, defaultUser string) (sshArgs, error) {
	a := sshArgs{port: 22, user: defaultUser}
	userSet, dest := false, ""
	for len(args) > 0 {
		opt := args[0]
		if opt == "--" {
			args = args[1:]
			if dest == "" && len(args) > 0 {
				dest, args = args[0], args[1:]
			}
			break
		}
		if !strings.HasPrefix(opt, "-") || opt == "-" {
			if dest != "" {
				break
			}
			dest, args = opt, args[1:]
			continue
		}
		args = args[1:]
		if opt == "-N" {
			a.noCommand = true
			continue
		}
		if strings.Trim(opt[1:], "v") == "" {
			a.verbose += len(opt) - 1
			continue
		}
		if len(opt) < 2 || !strings.Contains("iLRpl", opt[1:2]) {
			return a, fmt.Errorf("unsupported option %s", opt)
		}
		val := opt[2:]
		if val == "" {
			if len(args) == 0 {
				return a, fmt.Errorf("option %s needs a value", opt)
			}
			val, args = args[0], args[1:]
		}
		var err error
		switch opt[1] {
		case 'i':
			a.identities = append(a.identities, val)
		case 'L', 'R':
			var f sshc.Forward
			if f, err = sshc.ParseForward(val); err != nil {
				return a, err
			}
			if opt[1] == 'L' {
				a.local = append(a.local, f)
			} else {
				a.remote = append(a.remote, f)
			}
		case 'p':
			n, perr := strconv.ParseUint(val, 10, 16)
			if perr != nil || n == 0 {
				return a, fmt.Errorf("bad port %q", val)
			}
			a.port = uint16(n)
		case 'l':
			a.user, userSet = val, true
		}
	}
	if dest == "" {
		return a, errors.New("no destination")
	}
	a.host = dest
	if u, h, ok := strings.Cut(dest, "@"); ok {
		if !userSet {
			a.user = u
		}
		a.host = h
	}
	if a.host == "" || a.user == "" {
		return a, errors.New("no host or user")
	}
	if len(args) > 0 {
		a.args = args
	}
	a.command = strings.Join(args, " ")
	if a.noCommand && a.command != "" {
		return a, errors.New("-N takes no command")
	}
	return a, nil
}

// sshApplet logs in to a mesh host over the userspace node: a shell, a
// command, or with -N only the forwards.
func sshApplet(args []string, p proc) int {
	a, err := parseSSHArgs(args, p.getenv("USER"))
	if err != nil {
		fmt.Fprintf(p.err, "%s ssh: %v\n"+sshUsage, self, err, self)
		return 255
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return failSSH(p, err)
	}
	addr, err := cfg.Lookup(a.host)
	if err != nil {
		return failSSH(p, err)
	}
	// The forwards' local targets may be mesh hosts too: keep their peers.
	want := []netip.Addr{addr}
	for _, f := range a.remote {
		if fa, err := cfg.Lookup(f.Host); err == nil {
			want = append(want, fa)
		}
	}
	if cfg, err = cfg.Narrow(want...); err != nil {
		return failSSH(p, err)
	}
	dbg := debugf(p, "ssh", a.verbose)
	dbg("%s is %s in the hosts table; node narrowed to %d peer(s)", a.host, addr, len(cfg.Peers))
	clientCfg, closeAuth, err := sshClientConfig(p, a, cfg, addr, dbg)
	if err != nil {
		return failSSH(p, err)
	}
	defer closeAuth()

	m, err := startMesh(p, cfg, a.verbose)
	if err != nil {
		return failSSH(p, err)
	}
	defer m.Stop()
	c, err := dialSSH(p, m, a, clientCfg, dialTimeout, dbg)
	if err != nil {
		return failSSH(p, err)
	}
	defer c.Close()

	logf := func(format string, args ...any) { fmt.Fprintf(p.err, self+" ssh: "+format+"\n", args...) }
	for _, f := range a.local {
		lns, err := sshc.ListenLocal(f, logf)
		if err != nil {
			return failSSH(p, fmt.Errorf("-L %s: %w", f.ListenAddr(), err))
		}
		for _, ln := range lns {
			defer ln.Close()
			go func() { relay.Serve(ln, func() (net.Conn, error) { return c.Dial("tcp", f.Target()) }, logf) }()
		}
	}
	for _, f := range a.remote {
		ln, err := sshc.ListenRemote(c, f)
		if err != nil {
			return failSSH(p, fmt.Errorf("-R %s: %w", f.ListenAddr(), err))
		}
		defer ln.Close()
		go func() { relay.Serve(ln, localDialer(m, cfg, f), logf) }()
	}
	if a.noCommand {
		return waitClient(c)
	}
	code, err := runSession(c, a.command, p)
	if err != nil {
		return failSSH(p, err)
	}
	return code
}

// localDialer dials an -R target from this side: a mesh host through the
// node, anything else, such as localhost, directly.
func localDialer(m *mesh.Mesh, cfg mesh.Config, f sshc.Forward) func() (net.Conn, error) {
	if _, err := cfg.Lookup(f.Host); err == nil {
		return func() (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			defer cancel()
			return m.DialTCP(ctx, f.Host, f.HostPort)
		}
	}
	return func() (net.Conn, error) { return net.Dial("tcp", f.Target()) }
}

// waitClient holds -N's forwards until the connection ends or the user
// interrupts.
func waitClient(c *ssh.Client) int {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
		return 255
	case <-sig:
		return 0
	}
}

// failSSH reports an error with ssh's exit status for one, 255.
func failSSH(p proc, err error) int {
	fail(p, "ssh", err)
	return 255
}

// hostAliases is the other names known_hosts may know a mesh host by: its
// short name and its name in the mesh domain, whichever was not typed.
func hostAliases(cfg mesh.Config, host string, port uint16) []string {
	short := strings.ToLower(strings.TrimSuffix(host, "."))
	if cfg.Domain != "" {
		short = strings.TrimSuffix(short, "."+strings.ToLower(cfg.Domain))
	}
	if _, ok := cfg.Hosts[short]; !ok {
		return nil // an address literal
	}
	names := []string{short}
	if cfg.Domain != "" {
		names = append(names, short+"."+cfg.Domain)
	}
	var out []string
	for _, n := range names {
		if n != host {
			out = append(out, net.JoinHostPort(n, strconv.Itoa(int(port))))
		}
	}
	return out
}

// sshClientConfig is OpenSSH's defaults from ~/.ssh, as the user named
// the host in a: the agent, -i identities, then the default ones, and
// known_hosts, asking on the terminal, with the host key types known_hosts
// has for the host at addr, under any of its mesh names, preferred.
func sshClientConfig(p proc, a sshArgs, cfg mesh.Config, addr netip.Addr, dbg func(string, ...any)) (*ssh.ClientConfig, func(), error) {
	hostport := net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
	remote := net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, a.port))
	aliases := hostAliases(cfg, a.host, a.port)
	home := p.getenv("HOME")
	if home == "" {
		return nil, nil, errors.New("no HOME for ~/.ssh")
	}
	dir := filepath.Join(home, ".ssh")
	var defaults []string
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		defaults = append(defaults, filepath.Join(dir, n))
	}
	methods, closeAuth, err := sshc.Auth{AgentSock: p.getenv("SSH_AUTH_SOCK"), Identities: a.identities, Defaults: defaults, Prompt: p.prompt, Logf: dbg}.Methods()
	if err != nil {
		return nil, nil, err
	}
	var confirm func(string, ssh.PublicKey) bool
	if p.prompt != nil {
		confirm = func(host string, key ssh.PublicKey) bool {
			ans, err := p.prompt(fmt.Sprintf("The authenticity of host '%s' can't be established.\n%s key fingerprint is %s.\nAre you sure you want to continue connecting (yes/no)? ",
				host, key.Type(), ssh.FingerprintSHA256(key)), true)
			if err != nil {
				fmt.Fprintf(p.err, "%s: cannot ask about the host key: %v\n", self, err)
			}
			return err == nil && strings.TrimSpace(ans) == "yes"
		}
	}
	known := []string{filepath.Join(dir, "known_hosts")}
	hk, err := sshc.HostKeys(known, confirm, aliases...)
	if err != nil {
		closeAuth()
		return nil, nil, err
	}
	algos, err := sshc.KnownAlgorithms(known, hostport, remote, aliases...)
	if err != nil {
		closeAuth()
		return nil, nil, err
	}
	checked := func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := hk(host, remote, key)
		dbg("server host key %s %s for %s: %s", key.Type(), ssh.FingerprintSHA256(key), host, map[bool]string{true: "known", false: fmt.Sprint(err)}[err == nil])
		return err
	}
	if len(algos) > 0 {
		dbg("host key types known for %s: %s first", hostport, algos[0])
	}
	return &ssh.ClientConfig{User: a.user, Auth: methods, HostKeyCallback: checked, HostKeyAlgorithms: algos}, closeAuth, nil
}

// dialSSH connects to the host in a through the node and logs in, within
// timeout, tracing each step to dbg.
func dialSSH(p proc, m *mesh.Mesh, a sshArgs, cfg *ssh.ClientConfig, timeout time.Duration, dbg func(string, ...any)) (*ssh.Client, error) {
	hostport := net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := p.now()
	dbg("connecting to %s through the mesh", hostport)
	conn, err := m.DialTCP(ctx, a.host, a.port)
	if err != nil {
		return nil, fmt.Errorf("%s: %w%s", hostport, err, logHint(p))
	}
	dbg("connected in %v", p.now().Sub(start).Round(time.Millisecond))
	c, err := sshc.Client(ctx, conn, hostport, cfg)
	if err != nil {
		return nil, err
	}
	dbg("authenticated as %s in %v", a.user, p.now().Sub(start).Round(time.Millisecond))
	return c, nil
}

// debugf is the applet's -v trace, ssh's debug1 lines; a no-op without -v.
func debugf(p proc, applet string, verbose int) func(string, ...any) {
	if verbose == 0 {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		fmt.Fprintf(p.err, "%s %s: debug1: %s\n", self, applet, fmt.Sprintf(format, args...))
	}
}

// runSession runs command, or a shell when it is empty, and returns its
// exit status. A shell on a terminal gets a pty, raw mode and resizes.
// Stdin is fed from a goroutine of ours, not Session.Stdin, whose copy
// Wait would wait for: a shell that exits would hang until a key press.
func runSession(c *ssh.Client, command string, p proc) (int, error) {
	sess, err := c.NewSession()
	if err != nil {
		return 255, err
	}
	defer sess.Close()
	sess.Stdout, sess.Stderr = p.out, p.err
	stdin, err := sess.StdinPipe()
	if err != nil {
		return 255, err
	}
	in, isFile := p.in.(*os.File)
	if command == "" && isFile && term.IsTerminal(int(in.Fd())) {
		restore, err := startTerminal(sess, in, p.getenv("TERM"))
		if err != nil {
			return 255, err
		}
		defer restore()
	}
	go func() {
		_, _ = io.Copy(stdin, p.in)
		stdin.Close()
	}()
	if command == "" {
		err = sess.Shell()
	} else {
		err = sess.Start(command)
	}
	if err != nil {
		return 255, err
	}
	return exitStatus(sess.Wait())
}

// exitStatus maps Session.Wait's result to ssh's exit status: the remote
// one, or 255 with an error of ours.
func exitStatus(err error) (int, error) {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitStatus(), nil
	case errors.As(err, &missing):
		return 255, errors.New("remote command exited without status")
	}
	return 255, err
}

// requestPty asks for a pty of termName, xterm-256color by default.
func requestPty(sess *ssh.Session, termName string, cols, rows int) error {
	if termName == "" {
		termName = "xterm-256color"
	}
	return sess.RequestPty(termName, rows, cols, ssh.TerminalModes{})
}

// startTerminal asks for a pty the size of in's terminal, puts it in raw
// mode, and passes on resizes; restore undoes it. It sends no terminal
// modes, where ssh sends the local tty's: servers' defaults are sane, but
// remote programs expecting this tty's settings may differ.
func startTerminal(sess *ssh.Session, in *os.File, termName string) (func(), error) {
	fd := int(in.Fd())
	cols, rows, err := term.GetSize(fd)
	if err != nil {
		cols, rows = 80, 24
	}
	if err := requestPty(sess, termName, cols, rows); err != nil {
		return nil, err
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			if c, r, err := term.GetSize(fd); err == nil {
				_ = sess.WindowChange(r, c)
			}
		}
	}()
	return func() {
		signal.Stop(winch)
		close(winch)
		_ = term.Restore(fd, state)
	}, nil
}
