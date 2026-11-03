// SPDX-License-Identifier: LGPL-3.0-or-later

package moshc

// EscapeKey is Ctrl-^, mosh's escape key.
const EscapeKey = 0x1e

// Escape is mosh's escape sequence filter on keyboard input: Ctrl-^ .
// quits, Ctrl-^ ^ and Ctrl-^ Ctrl-^ send a literal Ctrl-^, and Ctrl-^
// followed by anything else sends both, as mosh's client does. It holds
// one byte of state across reads.
type Escape struct{ pending bool }

// Feed filters in and returns the bytes to send, and whether the user
// asked to quit; bytes after the quit are dropped.
func (e *Escape) Feed(in []byte) (out []byte, quit bool) {
	out = make([]byte, 0, len(in))
	for _, b := range in {
		if e.pending {
			e.pending = false
			switch b {
			case '.':
				return out, true
			case '^', EscapeKey:
				out = append(out, EscapeKey)
			default:
				out = append(out, EscapeKey, b)
			}
			continue
		}
		if b == EscapeKey {
			e.pending = true
			continue
		}
		out = append(out, b)
	}
	return out, false
}
