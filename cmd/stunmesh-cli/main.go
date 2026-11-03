// SPDX-License-Identifier: LGPL-3.0-or-later

// Command stunmesh-cli is a multi-call binary, like busybox: the applet is
// the basename it runs as (a symlink named ssh runs the ssh applet), else
// its first argument when run as stunmesh-cli or stunmesh-cli-*.
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
	"time"

	"github.com/tarasglek/stunmesh-cli/sshc"
)

// version is stamped by the Makefile.
var version = "dev"

const self = "stunmesh-cli"

// proc is what an applet may touch of the process, so tests can run one
// without it.
type proc struct {
	in       io.Reader
	out, err io.Writer
	getenv   func(string) string
	rand     io.Reader
	// config is the node config compiled in.
	config func() ([]byte, error)
	now    func() time.Time
	sleep  func(time.Duration)
	// prompt asks the user on the terminal; nil when there is none.
	prompt sshc.Prompt
}

type applet func(args []string, p proc) int

var applets = map[string]applet{
	"keygen": keygen,
	"listen": listen,
	"mosh":   moshApplet,
	"nc":     nc,
	"ssh":    sshApplet,
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

func run(argv []string, p proc) int {
	name, args := pick(argv)
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

func main() {
	os.Exit(run(os.Args, proc{
		in: os.Stdin, out: os.Stdout, err: os.Stderr,
		getenv: os.Getenv, rand: rand.Reader, config: embeddedConfig,
		now: time.Now, sleep: time.Sleep, prompt: ttyPrompt,
	}))
}
