// Package signing implements both signature algorithms enumerated by the
// spec (_common.json#/$defs/signatureAlgorithm):
//
//   - Ed25519 (RFC 8032), via crypto/ed25519
//   - ML-DSA-65 (FIPS 204), via github.com/cloudflare/circl/sign/mldsa/mldsa65
//
// ML-DSA-65 is shipped in Phase 1 alongside Ed25519 so the post-quantum
// migration path is exercised by the conformance suite from day one. Both
// algorithms are tested for byte-exact interop with packages/handshake-rs in
// tests/conformance/.
//
// Wire format mirrors the Rust crate: signatures emitted as
// base64url-without-padding (_common.json#/$defs/base64url) when serialized
// into protocol messages.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// b64url is the spec's required base64url-without-padding encoding.
var b64url = base64.RawURLEncoding

// ============================== Ed25519 =====================================

// Ed25519Keypair holds an Ed25519 private+public pair.
type Ed25519Keypair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateEd25519 returns a fresh Ed25519 keypair from the OS CSPRNG.
func GenerateEd25519() (*Ed25519Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return &Ed25519Keypair{Private: priv, Public: pub}, nil
}

// Ed25519FromSeed deterministically derives a keypair from a 32-byte seed
// (RFC 8032 §5.1.5).
func Ed25519FromSeed(seed []byte) (*Ed25519Keypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Keypair{Private: priv, Public: pub}, nil
}

// SignEd25519 signs message with priv and returns the 64-byte raw signature.
func SignEd25519(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// SignEd25519B64 signs and base64url-encodes (no padding).
func SignEd25519B64(priv ed25519.PrivateKey, message []byte) string {
	return b64url.EncodeToString(SignEd25519(priv, message))
}

// VerifyEd25519 verifies a 64-byte raw signature.
func VerifyEd25519(pub ed25519.PublicKey, signature, message []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("ed25519 signature must be %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("ed25519 signature did not verify")
	}
	return nil
}

// VerifyEd25519B64 verifies a base64url-without-padding-encoded signature.
func VerifyEd25519B64(pub ed25519.PublicKey, signatureB64 string, message []byte) error {
	sig, err := b64url.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("ed25519 signature base64url decode: %w", err)
	}
	return VerifyEd25519(pub, sig, message)
}

// ============================ ML-DSA-65 =====================================

// FIPS 204 ML-DSA-65 wire-format constants. Re-exported so callers have a
// single import for sizes when allocating buffers.
const (
	MLDSA65PublicKeySize  = mldsa65.PublicKeySize
	MLDSA65PrivateKeySize = mldsa65.PrivateKeySize
	MLDSA65SignatureSize  = mldsa65.SignatureSize
	MLDSA65SeedSize       = mldsa65.SeedSize
)

// MLDSA65Keypair holds an ML-DSA-65 private+public pair.
type MLDSA65Keypair struct {
	Private *mldsa65.PrivateKey
	Public  *mldsa65.PublicKey
}

// GenerateMLDSA65 returns a fresh ML-DSA-65 keypair from the OS CSPRNG.
func GenerateMLDSA65() (*MLDSA65Keypair, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 keygen: %w", err)
	}
	return &MLDSA65Keypair{Private: priv, Public: pub}, nil
}

// MLDSA65FromSeed deterministically derives a keypair from a 32-byte seed
// (FIPS 204 ξ).
func MLDSA65FromSeed(seed []byte) (*MLDSA65Keypair, error) {
	if len(seed) != MLDSA65SeedSize {
		return nil, fmt.Errorf("ml-dsa-65 seed must be %d bytes, got %d", MLDSA65SeedSize, len(seed))
	}
	var s [32]byte
	copy(s[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&s)
	return &MLDSA65Keypair{Private: priv, Public: pub}, nil
}

// MarshalMLDSA65PublicKey returns the canonical 1952-byte public-key bytes.
func MarshalMLDSA65PublicKey(pub *mldsa65.PublicKey) ([]byte, error) {
	out, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 public key marshal: %w", err)
	}
	if len(out) != MLDSA65PublicKeySize {
		return nil, fmt.Errorf("ml-dsa-65 public key marshal: expected %d bytes, got %d", MLDSA65PublicKeySize, len(out))
	}
	return out, nil
}

// MarshalMLDSA65PrivateKey returns the canonical 4032-byte private-key bytes.
func MarshalMLDSA65PrivateKey(priv *mldsa65.PrivateKey) ([]byte, error) {
	out, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ml-dsa-65 private key marshal: %w", err)
	}
	if len(out) != MLDSA65PrivateKeySize {
		return nil, fmt.Errorf("ml-dsa-65 private key marshal: expected %d bytes, got %d", MLDSA65PrivateKeySize, len(out))
	}
	return out, nil
}

// SignMLDSA65 signs message DETERMINISTICALLY with priv, with empty context.
// FIPS 204 §5.5 deterministic variant — required for byte-equal interop with
// the Rust core's sign_deterministic call.
func SignMLDSA65(priv *mldsa65.PrivateKey, message []byte) ([]byte, error) {
	sig := make([]byte, MLDSA65SignatureSize)
	if err := mldsa65.SignTo(priv, message, nil, false, sig); err != nil {
		return nil, fmt.Errorf("ml-dsa-65 sign: %w", err)
	}
	return sig, nil
}

// SignMLDSA65B64 signs deterministically and base64url-encodes (no padding).
func SignMLDSA65B64(priv *mldsa65.PrivateKey, message []byte) (string, error) {
	sig, err := SignMLDSA65(priv, message)
	if err != nil {
		return "", err
	}
	return b64url.EncodeToString(sig), nil
}

// VerifyMLDSA65 verifies a raw 3309-byte signature.
func VerifyMLDSA65(pub *mldsa65.PublicKey, signature, message []byte) error {
	if len(signature) != MLDSA65SignatureSize {
		return fmt.Errorf("ml-dsa-65 signature must be %d bytes, got %d", MLDSA65SignatureSize, len(signature))
	}
	if !mldsa65.Verify(pub, message, nil, signature) {
		return errors.New("ml-dsa-65 signature did not verify")
	}
	return nil
}

// VerifyMLDSA65B64 verifies a base64url-without-padding-encoded signature.
func VerifyMLDSA65B64(pub *mldsa65.PublicKey, signatureB64 string, message []byte) error {
	sig, err := b64url.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("ml-dsa-65 signature base64url decode: %w", err)
	}
	return VerifyMLDSA65(pub, sig, message)
}

// UnmarshalMLDSA65PublicKey parses a 1952-byte public key from raw bytes.
func UnmarshalMLDSA65PublicKey(data []byte) (*mldsa65.PublicKey, error) {
	if len(data) != MLDSA65PublicKeySize {
		return nil, fmt.Errorf("ml-dsa-65 public key must be %d bytes, got %d", MLDSA65PublicKeySize, len(data))
	}
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("ml-dsa-65 public key unmarshal: %w", err)
	}
	return pk, nil
}
