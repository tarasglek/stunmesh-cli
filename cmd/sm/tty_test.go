// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// With no controlling terminal, the prompt goes to stdin when stdin is a
// terminal, and reads no further than the answer's line.
func TestTerminalPromptFallback(t *testing.T) {
	keyboard, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer keyboard.Close()
	defer tty.Close()
	noTTY := func() (*os.File, error) { return nil, errors.New("no such device or address") }
	ask := terminalPrompt(noTTY, tty, tty)
	if _, err := keyboard.Write([]byte("yes\nnext\n")); err != nil {
		t.Fatal(err)
	}
	ans, err := ask("Continue? ", true)
	if err != nil || ans != "yes" {
		t.Fatalf("answer = %q, %v", ans, err)
	}
	if rest, _ := readLine(tty); rest != "next" {
		t.Errorf("prompt took input past its line; next line = %q", rest)
	}
	shown := make([]byte, 256)
	n, _ := keyboard.Read(shown)
	if !strings.Contains(string(shown[:n]), "Continue? ") {
		t.Errorf("prompt not shown on the terminal: %q", shown[:n])
	}

	// Stdin not a terminal either: an error that says so.
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if _, err := terminalPrompt(noTTY, r, w)("Continue? ", true); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("no terminal anywhere: %v", err)
	}
}
