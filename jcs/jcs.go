// Package jcs implements RFC 8785 — JSON Canonicalization Scheme — by
// delegating to github.com/gowebpki/jcs. That package is a direct port of
// the reference implementation by Anders Rundgren (the RFC editor), so it
// matches the Rust serde_jcs output byte-for-byte on every fixture in
// tests/conformance/fixtures/jcs.json — including the IEEE-754 number
// edge cases that ECMAScript 6.1.6.1 prescribes.
package jcs

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize returns the RFC 8785 canonical UTF-8 byte representation of
// value. value may be any json.Unmarshal-compatible Go type, or already-
// serialized JSON wrapped in json.RawMessage.
func Canonicalize(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("jcs: serialize value: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("jcs: canonicalize: %w", err)
	}
	return out, nil
}

// CanonicalizeBytes canonicalizes already-serialized JSON. Useful when the
// caller has the JSON in raw form and wants to avoid an extra unmarshal.
func CanonicalizeBytes(jsonBytes []byte) ([]byte, error) {
	out, err := jcs.Transform(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("jcs: canonicalize: %w", err)
	}
	return out, nil
}
