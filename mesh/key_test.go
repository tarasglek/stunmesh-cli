// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"bytes"
	"testing"
)

// The key wg genkey would make from the same bytes, and the public key
// wg pubkey prints for it.
func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0xff}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if k[0] != 0xf8 || k[31] != 0x7f || k[1] != 0xff {
		t.Errorf("not clamped: %x", k)
	}
	if _, err := GenerateKey(bytes.NewReader(make([]byte, 31))); err == nil {
		t.Error("short random source accepted")
	}
	// printf AQEB...AQE= | wg pubkey, for a key of 0x01 bytes.
	priv, _ := ParseKey("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	if got := FormatKey(PublicKey(priv)); got != "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=" {
		t.Errorf("PublicKey = %s", got)
	}
}
