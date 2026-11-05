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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tarasglek/stunmesh-cli/moshc"
	"golang.org/x/term"
)

const moshUsage = "usage: %s mosh [--client=PATH (first)] [-v] [user@]host [--] [command...]\n"

// moshApplet runs a Mosh session to a mesh host through the node:
// mosh-server is started over the system's ssh, as the mosh script does,
// whose ssh_config sends it through sm nc; then mosh's own mosh-client
// talks to it through a UDP relay on 127.0.0.1 whose other end is in the
// node. --client names the mosh-client to run, as for mosh; user, port,
// keys and the rest are ssh_config's. The relay lives as long as
// mosh-client does.
func moshApplet(args []string, p proc) int {
	client := "mosh-client"
	if len(args) > 0 {
		if v, ok := strings.CutPrefix(args[0], "--client="); ok {
			client, args = v, args[1:]
		}
	}
	verbose := 0
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "v") == "" {
		verbose += len(args[0]) - 1
		args = args[1:]
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		msg := "no destination"
		if len(args) > 0 {
			msg = "unsupported option " + args[0] + "; ssh_config has the rest"
		}
		fmt.Fprintf(p.err, "%s mosh: %s\n"+moshUsage, self, msg, self)
		return 2
	}
	dest, command := args[0], args[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	host := dest[strings.LastIndex(dest, "@")+1:]
	in, isFile := p.in.(*os.File)
	if !isFile || !term.IsTerminal(int(in.Fd())) {
		return fail(p, "mosh", errors.New("stdin is not a terminal"))
	}
	client, err := exec.LookPath(client)
	if err != nil {
		return fail(p, "mosh", err)
	}
	cfg, err := nodeConfig(p)
	if err != nil {
		return fail(p, "mosh", err)
	}
	addr, err := cfg.Lookup(host)
	if err != nil {
		return fail(p, "mosh", err)
	}
	dbg := debugf(p, "mosh", verbose)
	dbg("%s is %s in the hosts table", host, addr)

	// First, so that this node is up only after ssh's sm nc has let the
	// peer go: two nodes with one key would reset each other's sessions.
	ctx, cancel := context.WithTimeout(context.Background(), moshc.BootstrapTimeout)
	port, key, err := bootstrap(ctx, "ssh", moshSSHArgs(dest, command, verbose), bootstrapEnv(p), p.err)
	cancel()
	if err != nil {
		return fail(p, "mosh", err)
	}
	n, err := openNode(p, cfg, verbose, addr)
	if err != nil {
		return fail(p, "mosh", err)
	}
	defer n.Close()
	local, stop, err := n.UDPRelay(host, port)
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

// moshSSHArgs is the ssh command line that starts mosh-server, as the mosh
// script runs it: -n, so the keys typed meanwhile stay for mosh-client,
// and -tt, since mosh-server wants a terminal.
func moshSSHArgs(dest string, command []string, verbose int) []string {
	args := []string{"-n", "-tt"}
	for range verbose {
		args = append(args, "-v")
	}
	return append(args, dest, "--", moshc.ServerCommand(command))
}

// bootstrapEnv is ssh's environment: this one, plus the node config file
// sm was given, if any, so that ssh's sm nc runs the same node config as
// this sm.
func bootstrapEnv(p proc) []string {
	env := os.Environ()
	if p.configFile != "" {
		if abs, err := filepath.Abs(p.configFile); err == nil {
			env = append(env, "STUNMESH_CLI_CONFIG="+abs)
		}
	}
	return env
}

// bootstrap runs ssh with args and env and returns the port and key from
// mosh-server's MOSH CONNECT line. ssh's prompts go to the terminal and
// its errors to errw; ctx bounds it all.
func bootstrap(ctx context.Context, ssh string, args, env []string, errw io.Writer) (uint16, string, error) {
	cmd := exec.CommandContext(ctx, ssh, args...)
	cmd.Env, cmd.Stderr = env, errw
	cmd.WaitDelay = time.Second // a killed ssh's children may hold its stdout
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return 0, "", fmt.Errorf("starting mosh-server: %w", ctx.Err())
	}
	port, key, perr := moshc.ParseConnect(string(out))
	if perr != nil && err != nil {
		return 0, "", fmt.Errorf("starting mosh-server: ssh: %w", err)
	}
	return port, key, perr
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

// debugf is the applet's -v trace, in ssh's debug1 style; a no-op
// without -v.
func debugf(p proc, applet string, verbose int) func(string, ...any) {
	if verbose == 0 {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		fmt.Fprintf(p.err, "%s %s: debug1: %s\n", self, applet, fmt.Sprintf(format, args...))
	}
}
