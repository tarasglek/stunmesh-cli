// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ttyPrompt asks on the controlling terminal, as ssh does, so prompts work
// while stdin and stdout carry a session or a pipe.
var ttyPrompt = terminalPrompt(func() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }, os.Stdin, os.Stderr)

// terminalPrompt asks on the terminal open returns or, failing that, on
// in and out when in is a terminal, as OpenSSH's readpassphrase does: a
// process can have a terminal on stdin and no controlling terminal, as
// under su on Android, where /dev/tty is "no such device or address".
func terminalPrompt(open func() (*os.File, error), in, out *os.File) func(string, bool) (string, error) {
	return func(prompt string, echo bool) (string, error) {
		r, w := in, out
		tty, err := open()
		if err == nil {
			defer tty.Close()
			r, w = tty, tty
		} else if !term.IsTerminal(int(in.Fd())) {
			return "", fmt.Errorf("no terminal to ask %q on: %w", strings.TrimSpace(prompt), err)
		}
		fmt.Fprint(w, prompt)
		if !echo {
			b, err := term.ReadPassword(int(r.Fd()))
			fmt.Fprintln(w)
			return string(b), err
		}
		return readLine(r)
	}
}

// readLine reads up to a newline a byte at a time, so nothing typed after
// it is taken from a stdin the session reads next.
func readLine(r *os.File) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return string(line), err
		}
	}
}
