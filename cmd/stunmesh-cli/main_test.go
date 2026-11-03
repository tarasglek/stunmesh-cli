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
		{[]string{"/x/build/bin/ssh", "desk"}, "ssh", []string{"desk"}},
		{[]string{"stunmesh-cli", "ssh", "desk"}, "ssh", []string{"desk"}},
		{[]string{"./build/stunmesh-cli", "nc", "desk", "22"}, "nc", []string{"desk", "22"}},
		{[]string{"build/stunmesh-cli-desk-cli-amd64", "status"}, "status", nil},
		{[]string{"stunmesh-cli"}, "", nil},
		{nil, "", nil},
	} {
		name, args := pick(tc.argv)
		if name != tc.name || !slices.Equal(args, tc.args) {
			t.Errorf("pick(%q) = %q %q, want %q %q", tc.argv, name, args, tc.name, tc.args)
		}
	}
}

func runCapture(argv ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(argv, stdio{strings.NewReader(""), &out, &errb})
	return code, out.String(), errb.String()
}

func TestRun(t *testing.T) {
	if code, out, _ := runCapture("stunmesh-cli", "--list"); code != 0 || out != "" {
		t.Errorf("--list with no applets: %d %q", code, out)
	}
	if code, out, _ := runCapture("stunmesh-cli", "--version"); code != 0 || !strings.HasPrefix(out, "stunmesh-cli ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, errs := runCapture("stunmesh-cli", "nosuch"); code != 127 || !strings.Contains(errs, `unknown applet "nosuch"`) {
		t.Errorf("unknown applet: %d %q", code, errs)
	}
	if code, _, errs := runCapture("stunmesh-cli"); code != 127 || !strings.Contains(errs, "usage:") {
		t.Errorf("no applet: %d %q", code, errs)
	}
}
