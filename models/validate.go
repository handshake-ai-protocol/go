// Schema-native validation for the v0.2.3 message types using
// github.com/go-playground/validator/v10. Required by the FFI architecture
// (ADR-0006 §"schema-native models in every language") and exercised by the
// conformance suite below.
package models

import "github.com/go-playground/validator/v10"

// validate is a process-wide validator. It is safe for concurrent use per the
// validator/v10 docs and caches struct introspection across calls.
var validate = validator.New(validator.WithRequiredStructEnabled())

// Validate checks the DelegationToken against its `validate` struct tags and
// returns the first violation found, or nil if the token is well-formed.
// It does NOT verify the cryptographic signature; that lives in the signing
// package and Phase 2 chain walker.
func (d *DelegationToken) Validate() error {
	return validate.Struct(d)
}

// Validate checks the HandshakeRequest against its `validate` struct tags.
// See DelegationToken.Validate for what this does and does not cover.
func (r *HandshakeRequest) Validate() error {
	return validate.Struct(r)
}

// Validate checks the Receipt against its `validate` struct tags.
func (r *Receipt) Validate() error {
	return validate.Struct(r)
}
