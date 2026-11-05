// SPDX-License-Identifier: LGPL-3.0-or-later

package mesh

import (
	"crypto/ecdh"
	"io"
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
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		panic(err) // any 32 bytes are an X25519 key
	}
	return [32]byte(k.PublicKey().Bytes())
}
