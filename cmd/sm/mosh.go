// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/tarasglek/stunmesh-cli/moshc"
	"golang.org/x/term"
)

const moshUsage = "usage: %s mosh [--client=PATH (first)] [-v] [-i identity]... [-p port] [-l user] [user@]host [command...]\n"

// moshApplet runs a Mosh session to a mesh host through the userspace
// node: mosh-server is started over SSH, then mosh's own mosh-client
// talks to it through a UDP relay on 127.0.0.1 whose other end is in the
// node, as ssh talks through nc. --client names the mosh-client to run,
// as for mosh. The node lives as long as mosh-client does.
func moshApplet(args []string, p proc) int {
	client := "mosh-client"
	if len(args) > 0 {
		if v, ok := strings.CutPrefix(args[0], "--client="); ok {
			client, args = v, args[1:]
		}
	}
	a, err := parseSSHArgs(args, defaultUser(p))
	if err == nil && (len(a.local) > 0 || len(a.remote) > 0 || a.noCommand) {
		err = errors.New("mosh takes no -L, -R or -N")
	}
	if err != nil {
		fmt.Fprintf(p.err, "%s mosh: %v\n"+moshUsage, self, err, self)
		return 2
	}
	in, isFile := p.in.(*os.File)
	if !isFile || !term.IsTerminal(int(in.Fd())) {
		return fail(p, "mosh", errors.New("stdin is not a terminal"))
	}
	if client, err = exec.LookPath(client); err != nil {
		return fail(p, "mosh", err)
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return fail(p, "mosh", err)
	}
	addr, err := cfg.Lookup(a.host)
	if err != nil {
		return fail(p, "mosh", err)
	}
	if cfg, err = cfg.Narrow(addr); err != nil {
		return fail(p, "mosh", err)
	}
	dbg := debugf(p, "mosh", a.verbose)
	dbg("%s is %s in the hosts table; node narrowed to %d peer(s)", a.host, addr, len(cfg.Peers))
	dbg("user %s from %s", a.user, a.userFrom)
	clientCfg, closeAuth, err := sshClientConfig(p, a, cfg, addr, dbg)
	if err != nil {
		return fail(p, "mosh", err)
	}
	defer closeAuth()
	m, err := startMesh(p, cfg, a.verbose)
	if err != nil {
		return fail(p, "mosh", err)
	}
	defer m.Stop()

	cols, rows, err := term.GetSize(int(in.Fd()))
	if err != nil {
		cols, rows = 80, 24
	}
	c, err := dialSSH(p, m, a, clientCfg, dialTimeout, dbg)
	if err != nil {
		return fail(p, "mosh", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), moshc.BootstrapTimeout)
	port, key, err := moshc.Bootstrap(ctx, c, moshc.Server{Term: p.getenv("TERM"), Columns: cols, Rows: rows, Command: a.args})
	c.Close() // the session needs no SSH from here on
	cancel()
	if err != nil {
		return fail(p, "mosh", err)
	}
	local, stop, err := m.UDPRelay(a.host, port)
	if err != nil {
		return fail(p, "mosh", err)
	}
	defer stop()
	dbg("mosh-server is up on port %d; %s talks to it through 127.0.0.1:%d", port, client, local)
	code, err := runMoshClient(client, local, key, in, p.out, p.err)
	if err != nil {
		return fail(p, "mosh", err)
	}
	return code
}

// runMoshClient runs mosh-client on the terminal against 127.0.0.1:port
// with the session key in MOSH_KEY, as the mosh script does, and returns
// its exit status. Ctrl-^ . and the terminal are mosh-client's. Signals
// that would end this process are passed on instead, so the relay
// outlives the client that uses it.
func runMoshClient(client string, port uint16, key string, in *os.File, out, errw io.Writer) (int, error) {
	cmd := exec.Command(client, "127.0.0.1", strconv.Itoa(int(port)))
	cmd.Env = append(os.Environ(), "MOSH_KEY="+key)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
