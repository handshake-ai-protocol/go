// SPDX-License-Identifier: MIT
// Package handshake is the parallel native Go implementation of the Handshake
// protocol. It is intentionally byte-equal with the canonical Rust core
// (packages/handshake-rs) on every conformance vector — see
// tests/conformance/ for the corpus.
//
// Why a parallel implementation rather than a Go FFI shim over Rust:
// downstream consumers (Go services, Kubernetes operators, OpenTelemetry
// extensions) often forbid cgo. Having a pure-Go core keeps Handshake
// adoptable in those environments without compromising on the wire-format
// guarantees enforced by the conformance suite.
//
// See packages/handshake-rs/src/lib.rs for the authoritative API; the Go
// surface mirrors it function-for-function.
package handshake

// SpecVersion is the schema revision this package implements. Pinned so
// callers can detect mismatch against packages/handshake-spec/schemas/.
const SpecVersion = "0.2.3"
