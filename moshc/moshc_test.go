// SPDX-License-Identifier: LGPL-3.0-or-later

package moshc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jpillora/sshd-lite/mosh"
	"github.com/jpillora/sshd-lite/sshd"
	"github.com/tarasglek/stunmesh-cli/sshc"
	"golang.org/x/crypto/ssh"
)

func TestServerCommand(t *testing.T) {
	if got := ServerCommand(Server{}); got != "'mosh-server' new -s -c 256 -l LANG=C.UTF-8" {
		t.Errorf("default = %q", got)
	}
	got := ServerCommand(Server{Path: "/opt/mosh server", Command: []string{"tmux", "new", "-s", "it's"}})
	if want := `'/opt/mosh server' new -s -c 256 -l LANG=C.UTF-8 -- 'tmux' 'new' '-s' 'it'\''s'`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseConnect(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAA"
	port, k, err := ParseConnect("Welcome to remote-02\r\n\r\nMOSH CONNECT 60001 " + key + "\r\n\nmosh-server (mosh 1.3.2)\n")
	if err != nil || port != 60001 || k != key {
		t.Errorf("ParseConnect = %d %q %v", port, k, err)
	}
	for name, out := range map[string]string{
		"none":       "mosh-server: command not found\n",
		"twice":      "MOSH CONNECT 1 " + key + "\nMOSH CONNECT 2 " + key + "\n",
		"short key":  "MOSH CONNECT 60001 AAAA\n",
		"padded key": "MOSH CONNECT 60001 " + key + "==\n",
		"bad port":   "MOSH CONNECT 0 " + key + "\n",
		"big port":   "MOSH CONNECT 70000 " + key + "\n",
		"extra":      "MOSH CONNECT 60001 " + key + " x\n",
	} {
		if _, _, err := ParseConnect(out); err == nil {
			t.Errorf("%s: accepted %q", name, out)
		}
	}
	if _, _, err := ParseConnect("bash: mosh-server: command not found"); err == nil || !strings.Contains(err.Error(), "command not found") {
		t.Errorf("error should carry the output: %v", err)
	}
}

// Bootstrap against sshd-lite's mosh server: over an SSH client, it starts
// the server and returns a port where it answers and a well-formed key.
func TestBootstrap(t *testing.T) {
	key := func() (ed25519.PrivateKey, ssh.Signer) {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(k)
		return k, s
	}
	hk, hs := key()
	_, us := key()
	b, _ := ssh.MarshalPrivateKey(hk, "")
	srv, err := sshd.NewServer(sshd.Config{Attach: mosh.Attach, KeyBytes: pem.EncodeToMemory(b), AuthKeys: []ssh.PublicKey{us.PublicKey()},
		Shell: "/bin/sh", WorkDir: t.TempDir(), NoInheritEnv: true, NoGlobalEnv: true, LogQuiet: true})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.StartWithContext(sctx, ln) }()
	defer func() { scancel(); <-done }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := sshc.Client(ctx, conn, "h:22", &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(us)}, HostKeyCallback: ssh.FixedHostKey(hs.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	port, mkey, err := Bootstrap(ctx, c, Server{Columns: 80, Rows: 24})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if port == 0 || len(mkey) != 22 {
		t.Errorf("Bootstrap = %d, %q", port, mkey)
	}
}
