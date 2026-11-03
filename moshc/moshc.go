// SPDX-License-Identifier: LGPL-3.0-or-later

// Package moshc starts Mosh sessions over the userspace mesh: mosh-server
// is bootstrapped over an SSH client of the caller's, and the session's
// datagrams go to sshd-lite's mosh.Connect on a conn the caller dials,
// through the mesh rather than the host's network.
package moshc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server is where and how to start mosh-server.
type Server struct {
	// Path is the remote executable, mosh-server by default.
	Path string
	// Command is the argv to run in the session; empty for the login shell.
	Command []string
	Term    string
	// Columns and Rows are the terminal size mosh-server starts with.
	Columns, Rows int
}

// ServerCommand is the remote command line that starts mosh-server as the
// mosh script does: bound to the address the SSH connection arrived on
// (-s), so its datagrams come back through the mesh, 256 colors, and a
// UTF-8 locale. Every word is shell-quoted.
func ServerCommand(s Server) string {
	path := s.Path
	if path == "" {
		path = "mosh-server"
	}
	cmd := shellQuote(path) + " new -s -c 256 -l LANG=C.UTF-8"
	if len(s.Command) > 0 {
		cmd += " --"
		for _, a := range s.Command {
			cmd += " " + shellQuote(a)
		}
	}
	return cmd
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ParseConnect finds mosh-server's MOSH CONNECT <port> <key> line in its
// output, which may also hold banners and motd. The key must be the
// 22-character unpadded base64 of 16 bytes that mosh-server prints.
func ParseConnect(out string) (port uint16, key string, err error) {
	found := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "MOSH CONNECT ") {
			continue
		}
		if found {
			return 0, "", errors.New("mosh-server printed MOSH CONNECT twice")
		}
		f := strings.Fields(line)
		if len(f) != 4 {
			return 0, "", fmt.Errorf("malformed %q", line)
		}
		n, perr := strconv.ParseUint(f[2], 10, 16)
		if perr != nil || n == 0 {
			return 0, "", fmt.Errorf("bad port in %q", line)
		}
		if raw, kerr := base64.RawStdEncoding.DecodeString(f[3]); kerr != nil || len(f[3]) != 22 || len(raw) != 16 {
			return 0, "", errors.New("bad session key in MOSH CONNECT")
		}
		port, key, found = uint16(n), f[3], true
	}
	if !found {
		return 0, "", fmt.Errorf("mosh-server did not print MOSH CONNECT: %s", strings.TrimSpace(out))
	}
	return port, key, nil
}

// Bootstrap runs mosh-server on c, on a pty of the given size, as the
// mosh script does with ssh -tt, and returns the port and key it prints.
// ctx bounds the whole exchange; cancelling it closes c.
func Bootstrap(ctx context.Context, c *ssh.Client, s Server) (uint16, string, error) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	sess, err := c.NewSession()
	if err != nil {
		return 0, "", err
	}
	defer sess.Close()
	term := s.Term
	if term == "" {
		term = "xterm-256color"
	}
	if err := sess.RequestPty(term, max(s.Rows, 1), max(s.Columns, 1), ssh.TerminalModes{}); err != nil {
		return 0, "", err
	}
	var out bounded
	sess.Stdout, sess.Stderr = &out, &out
	err = sess.Run(ServerCommand(s))
	if ctx.Err() != nil {
		return 0, "", ctx.Err()
	}
	if out.over {
		return 0, "", errors.New("mosh-server output over 64 KiB")
	}
	port, key, perr := ParseConnect(out.String())
	if perr != nil && err != nil {
		return 0, "", fmt.Errorf("mosh-server: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return port, key, perr
}

// bounded keeps at most 64 KiB of output; stdout and stderr write to it
// concurrently.
type bounded struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	over bool
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := 64<<10 - b.buf.Len(); len(p) > room {
		b.over = true
		b.buf.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *bounded) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// BootstrapTimeout bounds Bootstrap in the applet, as mosh's own does.
const BootstrapTimeout = 20 * time.Second
