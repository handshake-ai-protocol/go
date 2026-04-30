# handshake-go

Pure-Go implementation of the Handshake protocol. **Cgo-free** — adoptable in
environments that forbid cgo (Kubernetes operators, OpenTelemetry extensions).

The Rust crate (`packages/handshake-rs`) is the canonical reference; this
package is the parallel Go implementation. They are tested for **byte-exact
output equality** on every fixture in `tests/conformance/fixtures/jcs.json`,
including:

- RFC 8785 JCS — object key ordering, string escaping, and the IEEE-754 number
  edge cases prescribed by ECMAScript 6.1.6.1
- SHA-256 digests
- Ed25519 signatures (RFC 8032, the official KAT vector)
- ML-DSA-65 deterministic signatures (FIPS 204 §5.5)

## Surface

| Package | Purpose |
| --- | --- |
| `jcs` | RFC 8785 JCS canonicalization (delegates to `gowebpki/jcs`) |
| `hashing` | SHA-256 helpers |
| `signing` | Ed25519 (`crypto/ed25519`) and ML-DSA-65 (`cloudflare/circl/sign/mldsa/mldsa65`) |
| `models` | Go structs mirroring the v0.2.3 JSON Schemas, with `validator/v10` tags |

## Why a parallel implementation, not FFI?

The Python (`packages/handshake-py`) and TypeScript (`packages/handshake-ts`)
SDKs ship as FFI shims over the Rust core, so they cannot drift. Go is
different: we deliberately maintain a parallel implementation because the
target environments most often forbid cgo. The conformance suite is the
contract that prevents drift.
