// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jpillora/sshd-lite/mosh"
	"github.com/tarasglek/stunmesh-cli/moshc"
	"golang.org/x/term"
)

const moshUsage = "usage: %s mosh [-v] [-i identity]... [-p port] [-l user] [user@]host [command...]\n"

// moshApplet runs a Mosh session to a mesh host through the userspace
// node: mosh-server is started over SSH, then the session runs over UDP
// through the node, surviving network changes as mosh does. Ctrl-^ . quits.
func moshApplet(args []string, p proc) int {
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
	termName := p.getenv("TERM")
	c, err := dialSSH(p, m, a, clientCfg, dialTimeout, dbg)
	if err != nil {
		return fail(p, "mosh", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), moshc.BootstrapTimeout)
	port, key, err := moshc.Bootstrap(ctx, c, moshc.Server{Term: termName, Columns: cols, Rows: rows, Command: a.args})
	c.Close() // the session needs no SSH from here on
	cancel()
	if err != nil {
		return fail(p, "mosh", err)
	}
	dbg("mosh-server is up on port %d; session over UDP through the mesh", port)
	udp, err := m.DialUDP(a.host, port)
	if err != nil {
		return fail(p, "mosh", err)
	}
	code, err := runMosh(udp, key, in, p.out, termName, cols, rows)
	if err != nil {
		return fail(p, "mosh", err)
	}
	return code
}

// terminalModeReset undoes modes a remote program may have left set:
// cursor keys, attributes, reverse video, cursor visibility, mouse
// reporting and bracketed paste, as sshd-lite's mosh client resets them.
const terminalModeReset = "\x1b[?1l\x1b[0m\x1b[?5l\x1b[?25h\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?2004l"

// runMosh runs the session on udp with in as the keyboard in raw mode and
// out as the screen, until the remote shell exits or the user types
// Ctrl-^ ., which shuts the server down too. Cursor keys are put in
// application mode, as standard Mosh expects, and every mode is reset on
// the way out.
func runMosh(udp net.Conn, key string, in *os.File, out io.Writer, termName string, cols, rows int) (int, error) {
	state, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		udp.Close()
		return 1, err
	}
	defer term.Restore(int(in.Fd()), state)
	screen := &screenTracker{w: out}
	defer io.WriteString(out, terminalModeReset)
	defer screen.restore()
	if _, err := io.WriteString(out, "\x1b[?1h"); err != nil {
		udp.Close()
		return 1, err
	}
	if termName == "" {
		termName = "xterm-256color"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := mosh.Connect(ctx, udp, key, mosh.ClientConfig{Term: termName, Columns: cols, Rows: rows, Output: screen})
	if err != nil {
		return 1, err
	}
	defer s.Close()

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer func() {
		signal.Stop(winch)
		close(winch)
	}()
	go func() {
		for range winch {
			if c, r, err := term.GetSize(int(in.Fd())); err == nil {
				_ = s.Resize(c, r)
			}
		}
	}()
	quit := make(chan struct{})
	go func() {
		var esc moshc.Escape
		b := make([]byte, 4096)
		for {
			n, err := in.Read(b)
			keys, q := esc.Feed(b[:n])
			if len(keys) > 0 {
				if _, werr := s.Write(keys); werr != nil {
					return
				}
			}
			if q {
				close(quit)
				cancel() // the session sends mosh-server its shutdown
				return
			}
			if err != nil {
				return
			}
		}
	}()
	code, err := s.Wait()
	select {
	case <-quit:
		return 0, nil
	default:
	}
	return code, err
}

// screenTracker passes the session's screen output on and remembers
// whether it left the terminal on the alternate screen, so restore can
// go back to the primary one; the switch may be split across writes.
type screenTracker struct {
	w         io.Writer
	tail      string
	alternate bool
}

const altEnter, altLeave = "\x1b[?1049h", "\x1b[?1049l"

func (t *screenTracker) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	data := t.tail + string(p[:n])
	enter, leave := strings.LastIndex(data, altEnter), strings.LastIndex(data, altLeave)
	if enter >= 0 || leave >= 0 {
		t.alternate = enter > leave
	}
	if keep := len(altEnter) - 1; len(data) > keep {
		data = data[len(data)-keep:]
	}
	t.tail = data
	return n, err
}

func (t *screenTracker) restore() {
	if t.alternate {
		_, _ = io.WriteString(t.w, altLeave)
		t.alternate = false
	}
}
