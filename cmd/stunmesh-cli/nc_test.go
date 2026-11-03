// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

// The far end reads to EOF before answering, so the answer arrives only
// if splice half-closes after stdin ends.
func TestSpliceHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got "), b...))
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out bytes.Buffer
	if err := splice(c, strings.NewReader("ping"), &out); err != nil || out.String() != "got ping" {
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
		{[]string{"nc", "remote-01", "22"}, 1, "run stunmesh-cli keygen"},
	} {
		code, _, errs := runEnv(env, append([]string{"stunmesh-cli"}, tc.args...)...)
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
