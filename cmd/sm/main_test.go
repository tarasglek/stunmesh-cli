// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestPick(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		name string
		args []string
	}{
		{[]string{"/x/build/bin/mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"sm", "mosh", "desk"}, "mosh", []string{"desk"}},
		{[]string{"./build/sm", "nc", "desk", "22"}, "nc", []string{"desk", "22"}},
		{[]string{"build/sm-desk-cli-amd64", "status"}, "status", nil},
		{[]string{"sm"}, "", nil},
		{[]string{"/usr/bin/stunmesh-cli", "nc"}, "stunmesh-cli", []string{"nc"}}, // any other name is an applet's
		{[]string{"smash", "x"}, "smash", []string{"x"}},                          // a prefix of sm- only
		{nil, "", nil},
	} {
		name, args := pick(tc.argv)
		if name != tc.name || !slices.Equal(args, tc.args) {
			t.Errorf("pick(%q) = %q %q, want %q %q", tc.argv, name, args, tc.name, tc.args)
		}
	}
}

// testProc is a process with environment env and no stdin.
func testProc(env map[string]string, out, errb *bytes.Buffer) proc {
	return proc{
		in: strings.NewReader(""), out: out, err: errb,
		getenv: func(k string) string { return env[k] },
	}
}

func runEnv(env map[string]string, argv ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(argv, testProc(env, &out, &errb))
	return code, out.String(), errb.String()
}

func runCapture(argv ...string) (int, string, string) { return runEnv(nil, argv...) }

func TestRun(t *testing.T) {
	if code, out, _ := runCapture("sm", "--list"); code != 0 || out != "" {
		t.Errorf("--list: %d %q", code, out)
	}
	if code, out, _ := runCapture("sm", "--version"); code != 0 || !strings.HasPrefix(out, "sm ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, errs := runCapture("sm", "nosuch"); code != 127 || !strings.Contains(errs, `unknown applet "nosuch"`) {
		t.Errorf("unknown applet: %d %q", code, errs)
	}
	if code, _, errs := runCapture("sm"); code != 127 || !strings.Contains(errs, "usage:") {
		t.Errorf("no applet: %d %q", code, errs)
	}
}
