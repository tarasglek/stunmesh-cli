// SPDX-License-Identifier: LGPL-3.0-or-later

// Command stunmesh-cli is a multi-call binary, like busybox: the applet is
// the basename it runs as (a symlink named ssh runs the ssh applet), else
// its first argument when run as stunmesh-cli or stunmesh-cli-*.
package main

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// version is stamped by the Makefile.
var version = "dev"

const self = "stunmesh-cli"

// stdio is what an applet may touch of the process, so tests can run one
// without it.
type stdio struct {
	in       io.Reader
	out, err io.Writer
}

type applet func(args []string, std stdio) int

var applets = map[string]applet{}

// pick splits argv into the applet name and its arguments.
func pick(argv []string) (string, []string) {
	if len(argv) == 0 {
		return "", nil
	}
	// Build artifacts are named stunmesh-cli-<node>-<arch>; they are still
	// the binary itself, not an applet.
	if name := filepath.Base(argv[0]); name != self && !strings.HasPrefix(name, self+"-") {
		return name, argv[1:]
	}
	if len(argv) == 1 {
		return "", nil
	}
	return argv[1], argv[2:]
}

func run(argv []string, std stdio) int {
	name, args := pick(argv)
	if name == "--version" {
		fmt.Fprintln(std.out, self, version)
		return 0
	}
	if name == "--list" {
		for _, n := range slices.Sorted(maps.Keys(applets)) {
			fmt.Fprintln(std.out, n)
		}
		return 0
	}
	a, ok := applets[name]
	if !ok { // 127, as busybox and the shell exit for a missing command
		if name != "" {
			fmt.Fprintf(std.err, "%s: unknown applet %q\n", self, name)
		}
		fmt.Fprintf(std.err, "usage: %s <applet> [args...]; %s --list shows applets\n", self, self)
		return 127
	}
	return a(args, std)
}

func main() {
	os.Exit(run(os.Args, stdio{os.Stdin, os.Stdout, os.Stderr}))
}
