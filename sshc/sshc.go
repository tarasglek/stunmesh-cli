// SPDX-License-Identifier: LGPL-3.0-or-later

// Package sshc is the SSH client of stunmesh-cli: x/crypto/ssh over a
// connection the caller dialed, here through the userspace mesh, with
// OpenSSH's key, agent and known_hosts conventions.
package sshc

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

// Client runs the SSH handshake over conn, an already connected stream to
// addr, the host:port the user named, which host keys are checked
// against. Cancelling ctx during the handshake closes conn. On error conn
// is closed; on success the client owns it.
func Client(ctx context.Context, conn net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !stop() || err != nil {
		conn.Close()
		if err == nil {
			c.Close()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}
