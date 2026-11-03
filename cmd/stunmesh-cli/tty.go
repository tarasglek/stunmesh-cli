// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ttyPrompt asks on the controlling terminal, as ssh does, so prompts work
// while stdin and stdout carry a session or a pipe.
func ttyPrompt(prompt string, echo bool) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal to ask %q on: %w", strings.TrimSpace(prompt), err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	if !echo {
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
