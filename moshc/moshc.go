// SPDX-License-Identifier: LGPL-3.0-or-later

// Package moshc is what starting a Mosh session over the mesh needs of
// mosh: the command that starts mosh-server over SSH, and the port and
// key a mosh client gets from its answer. Running SSH is the caller's.
package moshc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ServerCommand is the remote command line that starts mosh-server as the
// mosh script does: bound to the address the SSH connection arrived on
// (-s), so its datagrams come back through the mesh, 256 colors, and a
// UTF-8 locale, running command, or the login shell when it is empty.
// Every word of command is shell-quoted.
func ServerCommand(command []string) string {
	cmd := "mosh-server new -s -c 256 -l LANG=C.UTF-8"
	if len(command) > 0 {
		cmd += " --"
		for _, a := range command {
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

// BootstrapTimeout bounds starting mosh-server, as mosh's own does.
const BootstrapTimeout = 20 * time.Second
