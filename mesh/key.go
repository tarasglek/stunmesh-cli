// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

// GenerateKey makes a WireGuard private key from r, clamped as wg genkey
// clamps it.
func GenerateKey(r io.Reader) ([32]byte, error) {
	var k [32]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return k, nil
}

// PublicKey is the public key of private key priv.
func PublicKey(priv [32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub
}
