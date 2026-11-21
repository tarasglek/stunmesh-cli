// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// splice ends when either side does: the far end closing, or stdin's EOF
// even with the far end silent, as when ssh is killed and the peer is
// away, so the process and its exposed ports end with ssh.
func TestSpliceEndsOnEitherSide(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conns := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// stdin ends; the far end stays open and silent.
	c := dial()
	defer c.Close()
	far := <-conns
	defer far.Close()
	done := make(chan error, 1)
	go func() { done <- splice(c, strings.NewReader("ping"), io.Discard) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("splice did not return at stdin's EOF")
	}

	// The far end answers and closes; stdin never ends.
	c2 := dial()
	defer c2.Close()
	far2 := <-conns
	far2.Write([]byte("pong"))
	far2.Close()
	pr, pw := io.Pipe()
	defer pw.Close()
	var out bytes.Buffer
	if err := splice(c2, pr, &out); err != nil || out.String() != "pong" {
		t.Errorf("splice = %q, %v", out.String(), err)
	}
}

// Bad arguments and unknown hosts fail before the key or the network:
// this test has neither.
func TestNcRejects(t *testing.T) {
	env := map[string]string{"config": testConfig, "STUNMESH_CLI_KEY": t.TempDir() + "/key"}
	for _, tc := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"nc", "remote-01"}, 2, "usage"},
		{[]string{"nc", "remote-01", "ssh"}, 1, `bad port "ssh"`},
		{[]string{"nc", "remote-01", "0"}, 1, "bad port"},
		{[]string{"nc", "nosuch", "22"}, 1, `unknown host "nosuch": not in the compiled-in hosts table`},
		{[]string{"nc", "remote-01", "22"}, 1, "run sm keygen"},
	} {
		code, _, errs := runEnv(env, append([]string{"sm"}, tc.args...)...)
		if code != tc.code || !strings.Contains(errs, tc.err) {
			t.Errorf("%v: %d %q, want %d and %q", tc.args, code, errs, tc.code, tc.err)
		}
	}
}

func TestLogHint(t *testing.T) {
	var b bytes.Buffer
	if h := logHint(testProc(nil, &b, &b)); !strings.Contains(h, "STUNMESH_CLI_LOG=info") {
		t.Errorf("hint = %q", h)
	}
	if h := logHint(testProc(map[string]string{"STUNMESH_CLI_LOG": "debug"}, &b, &b)); h != "" {
		t.Errorf("hint with the log on = %q", h)
	}
}
