// SPDX-License-Identifier: LGPL-3.0-or-later

// Command sm is stunmesh-cli's multi-call binary, like busybox: the applet
// is the basename it runs as (a symlink named mosh runs the mosh applet),
// else its first argument when run as sm or sm-*: sm nc, sm mosh.
package main

import (
	"crypto/rand"
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

const self = "sm"

// proc is what an applet may touch of the process, so tests can run one
// without it.
type proc struct {
	in       io.Reader
	out, err io.Writer
	getenv   func(string) string
	rand     io.Reader
	// config is the node config compiled in, or read from a file.
	config func() ([]byte, error)
	// sshConfig is the ssh_config that came with the node config.
	sshConfig func() ([]byte, error)
}

type applet func(args []string, p proc) int

var applets = map[string]applet{
	"config": configApplet,
	"keygen": keygen,
	"nc":     nc,
	"status": status,
}

// fail reports an applet's error the way every applet does.
func fail(p proc, applet string, err error) int {
	fmt.Fprintf(p.err, "%s %s: %v\n", self, applet, err)
	return 1
}

// pick splits argv into the applet name and its arguments.
func pick(argv []string) (string, []string) {
	if len(argv) == 0 {
		return "", nil
	}
	// Build artifacts are named sm-<node>-<arch>; they are still the
	// binary itself, not an applet.
	if name := filepath.Base(argv[0]); name != self && !strings.HasPrefix(name, self+"-") {
		return name, argv[1:]
	}
	if len(argv) == 1 {
		return "", nil
	}
	return argv[1], argv[2:]
}

func run(argv []string, p proc) int {
	name, args := pick(argv)
	if name == "--config" { // sm --config FILE <applet> ...
		if len(args) < 2 {
			fmt.Fprintf(p.err, "usage: %s --config FILE <applet> [args...]\n", self)
			return 2
		}
		p.config = configSource(args[0], attachedName, nil)
		p.sshConfig = configSource(args[0], sshName, nil)
		name, args = args[1], args[2:]
	}
	if name == "--version" {
		fmt.Fprintln(p.out, self, version)
		return 0
	}
	if name == "--list" {
		for _, n := range slices.Sorted(maps.Keys(applets)) {
			fmt.Fprintln(p.out, n)
		}
		return 0
	}
	a, ok := applets[name]
	if !ok { // 127, as busybox and the shell exit for a missing command
		if name != "" {
			fmt.Fprintf(p.err, "%s: unknown applet %q\n", self, name)
		}
		fmt.Fprintf(p.err, "usage: %s <applet> [args...]; %s --list shows applets\n", self, self)
		return 127
	}
	return a(args, p)
}

func main() { os.Exit(run(os.Args, osProc())) }

// osProc is this process.
func osProc() proc {
	file := os.Getenv("STUNMESH_CLI_CONFIG")
	return proc{
		in: os.Stdin, out: os.Stdout, err: os.Stderr,
		getenv: os.Getenv, rand: rand.Reader, config: configSource(file, attachedName, os.Executable),
		sshConfig: configSource(file, sshName, os.Executable),
	}
}
