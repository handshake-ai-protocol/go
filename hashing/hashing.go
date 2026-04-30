// Package hashing wraps SHA-256 — the digest required by
// _common.json#/$defs/hashAlgorithm. Wrapping (vs. callers depending on
// crypto/sha256 directly) lets us add SHA3-256 later without a breaking
// API change.
package hashing

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256 returns the 32-byte SHA-256 digest of input.
func SHA256(input []byte) [32]byte {
	return sha256.Sum256(input)
}

// SHA256Hex returns the lowercase-hex SHA-256 digest of input — the encoding
// used in hashValue.value per the spec's `hex` definition.
func SHA256Hex(input []byte) string {
	d := sha256.Sum256(input)
	return hex.EncodeToString(d[:])
}
