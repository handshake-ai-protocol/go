// Package models contains Go structs mirroring the v0.2.3 JSON Schemas under
// packages/handshake-spec/schemas/v0.2.3/. Each struct carries `validate`
// tags consumed by github.com/go-playground/validator/v10 so callers can
// reject malformed payloads without round-tripping through a JSON Schema
// validator.
//
// The field names use json tags matching the schema property names exactly,
// so encoding/json will round-trip a raw payload through these structs and
// then through the jcs package to produce identical canonical bytes.
//
// CI consistency: the planned Phase 2 conformance step compares the JSON
// Schema export of these structs against the on-disk schema files. Any drift
// (e.g. a new field added to the schema but not the struct) fails the build.
package models

import "encoding/json"

// SignatureAlgorithm — _common.json#/$defs/signatureAlgorithm
type SignatureAlgorithm string

const (
	AlgEdDSA              SignatureAlgorithm = "EdDSA"
	AlgMLDSA65            SignatureAlgorithm = "ML-DSA-65"
	AlgHybridEdDSAMLDSA65 SignatureAlgorithm = "Hybrid-EdDSA-MLDSA65"
)

// HashAlgorithm — _common.json#/$defs/hashAlgorithm
type HashAlgorithm string

const (
	HashSHA256  HashAlgorithm = "sha-256"
	HashSHA3256 HashAlgorithm = "sha3-256"
)

// HashValue — _common.json#/$defs/hashValue
type HashValue struct {
	Alg   HashAlgorithm `json:"alg" validate:"required,oneof=sha-256 sha3-256"`
	Value string        `json:"value" validate:"required"`
}

// Capability — _common.json#/$defs/capability
type Capability struct {
	Name        string          `json:"name" validate:"required"`
	Constraints json.RawMessage `json:"constraints,omitempty"`
	Delegable   *bool           `json:"delegable,omitempty"`
}

// DelegationToken — delegation-token.json
type DelegationToken struct {
	Version                       string             `json:"version" validate:"required"`
	Kind                          string             `json:"kind" validate:"required,eq=DelegationToken"`
	ID                            string             `json:"id" validate:"required"`
	Iss                           string             `json:"iss" validate:"required"`
	Sub                           string             `json:"sub" validate:"required"`
	Aud                           string             `json:"aud" validate:"required"`
	Iat                           string             `json:"iat" validate:"required"`
	Nbf                           string             `json:"nbf" validate:"required"`
	Exp                           string             `json:"exp" validate:"required"`
	Capabilities                  []Capability       `json:"capabilities" validate:"required,min=1,dive"`
	SubDelegationDepthRemaining   uint32             `json:"sub_delegation_depth_remaining"`
	ParentDelegationID            string             `json:"parent_delegation_id,omitempty"`
	Alg                           SignatureAlgorithm `json:"alg" validate:"required,oneof=EdDSA ML-DSA-65 Hybrid-EdDSA-MLDSA65"`
	Signature                     string             `json:"signature,omitempty"`
}

// HandshakeRequest — handshake-request.json
type HandshakeRequest struct {
	Version          string             `json:"version" validate:"required"`
	Kind             string             `json:"kind" validate:"required,eq=HandshakeRequest"`
	ID               string             `json:"id" validate:"required"`
	Iss              string             `json:"iss" validate:"required"`
	Aud              string             `json:"aud" validate:"required"`
	Iat              string             `json:"iat" validate:"required"`
	Nonce            string             `json:"nonce" validate:"required"`
	AgentAttestation json.RawMessage    `json:"agent_attestation" validate:"required"`
	Capability       Capability         `json:"capability" validate:"required"`
	DelegationChain  []DelegationToken  `json:"delegation_chain" validate:"required,dive"`
	Alg              SignatureAlgorithm `json:"alg" validate:"required,oneof=EdDSA ML-DSA-65 Hybrid-EdDSA-MLDSA65"`
	Signature        string             `json:"signature,omitempty"`
}

// ReceiptResult — receipt.json#/properties/result
type ReceiptResult string

const (
	ReceiptOk      ReceiptResult = "ok"
	ReceiptError   ReceiptResult = "error"
	ReceiptPartial ReceiptResult = "partial"
)

// Receipt — receipt.json
type Receipt struct {
	Version          string             `json:"version" validate:"required"`
	Kind             string             `json:"kind" validate:"required,eq=Receipt"`
	ID               string             `json:"id" validate:"required"`
	HandshakeID      string             `json:"handshake_id" validate:"required"`
	Iss              string             `json:"iss" validate:"required"`
	Sub              string             `json:"sub" validate:"required"`
	Action           string             `json:"action" validate:"required"`
	ExecutedAt       string             `json:"executed_at" validate:"required"`
	Result           ReceiptResult      `json:"result" validate:"required,oneof=ok error partial"`
	ResultHash       HashValue          `json:"result_hash" validate:"required"`
	ResultSummary    json.RawMessage    `json:"result_summary,omitempty"`
	UpstreamReceipts []string           `json:"upstream_receipts,omitempty"`
	RegistryAnchor   json.RawMessage    `json:"registry_anchor,omitempty"`
	Alg              SignatureAlgorithm `json:"alg" validate:"required,oneof=EdDSA ML-DSA-65 Hybrid-EdDSA-MLDSA65"`
	Signature        string             `json:"signature,omitempty"`
}
