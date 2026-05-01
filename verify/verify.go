// Package verify implements the Phase 2 chain-walk verifier in pure Go.
//
// This is a parallel native implementation of
// `packages/handshake-rs/src/verify.rs` — the Go core does NOT FFI into
// Rust (per ADR-0006: only Python and TypeScript do). The two
// implementations are byte-tested for agreement on:
//   - errorCode (one of the 12 values from `_common.json`),
//   - rejectedAtStep (where the rejection occurred in the spec ordering),
//   - effective_constraints (when the verifier accepts).
//
// Step ordering matches the Rust core (handoff §7 Phase 2 + Implementation
// Guide §3.1):
//
//  1. Schema/version sanity (kind + protocol version).
//  2. Outer signature on the HandshakeRequest.
//  3. Audience check — request.aud must equal receiver DID.
//  4. Freshness window — |now − iat| ≤ 60s (spec §11 ±60s clock skew).
//  5. Nonce uniqueness inside the TTL window (replay rejection).
//  6. Chain leaf-issuer match — first delegation's sub == request.iss.
//  7. Per-link checks (oldest first):
//     a. Signature.
//     b. nbf ≤ now ≤ exp (with ±60s skew).
//     c. Revocation lookup.
//     d. Issuer-chain integrity.
//     e. delegable + sub_delegation_depth_remaining for non-final links.
//  8. Capability intersection — request's capability ⊆ chain-intersected scope.
package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/intersect"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
)

// DefaultSkewSecs mirrors the Rust core; spec §11 ±60s.
const DefaultSkewSecs = 60

// ErrorCode is one of the 12 values from `_common.json#/$defs/errorCode`.
type ErrorCode string

const (
	SignatureInvalid           ErrorCode = "signature_invalid"
	ChainBroken                ErrorCode = "chain_broken"
	ScopeExceeded              ErrorCode = "scope_exceeded"
	CredentialRevoked          ErrorCode = "credential_revoked"
	Expired                    ErrorCode = "expired"
	NotYetValid                ErrorCode = "not_yet_valid"
	ReplayDetected             ErrorCode = "replay_detected"
	AudMismatch                ErrorCode = "aud_mismatch"
	PolicyDenied               ErrorCode = "policy_denied"
	ServiceUnavailable         ErrorCode = "service_unavailable"
	RateLimited                ErrorCode = "rate_limited"
	ProtocolVersionUnsupported ErrorCode = "protocol_version_unsupported"
)

// RejectStep names exactly which step in the verifier emitted a rejection.
type RejectStep string

const (
	StepSchemaValidation      RejectStep = "schema_validation"
	StepSignatureVerification RejectStep = "signature_verification"
	StepAudienceCheck         RejectStep = "audience_check"
	StepFreshnessWindow       RejectStep = "freshness_window"
	StepNonceCheck            RejectStep = "nonce_check"
	StepDelegationChainWalk   RejectStep = "delegation_chain_walk"
	StepScopeIntersection     RejectStep = "scope_intersection"
	StepPolicyHook            RejectStep = "policy_hook"
)

// SpecVersion is the version string this implementation accepts.
const SpecVersion = "0.2.3"

// KeyResolver looks up the raw 32-byte Ed25519 public key for a DID.
// Returns (nil, false) when the DID is unknown.
type KeyResolver interface {
	Resolve(did string) ([]byte, bool)
}

// StaticKeyResolver is the default in-memory backend.
type StaticKeyResolver struct {
	keys map[string][]byte
}

// NewStaticKeyResolver returns an empty resolver.
func NewStaticKeyResolver() *StaticKeyResolver {
	return &StaticKeyResolver{keys: make(map[string][]byte)}
}

// Insert registers a DID → public-key binding.
func (s *StaticKeyResolver) Insert(did string, publicKey []byte) {
	s.keys[did] = publicKey
}

// Resolve satisfies KeyResolver.
func (s *StaticKeyResolver) Resolve(did string) ([]byte, bool) {
	pk, ok := s.keys[did]
	return pk, ok
}

// NonceStore tracks consumed nonces inside a TTL window. The default is
// in-memory; production deployments swap in a Postgres-backed store
// (deferred to ADR-0007).
type NonceStore interface {
	CheckAndRecord(nonce string, seenAt time.Time) bool
}

// InMemoryNonceStore is the default backend. TTL-bounded so the map does
// not grow unbounded under sustained traffic. The store is goroutine-safe
// — server middleware shares one instance across concurrent requests.
type InMemoryNonceStore struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	TTLSecs int
}

// NewInMemoryNonceStore constructs an in-memory store with a TTL window
// (spec §11 recommends ≥120s — twice the freshness skew window).
func NewInMemoryNonceStore(ttlSecs int) *InMemoryNonceStore {
	return &InMemoryNonceStore{seen: make(map[string]time.Time), TTLSecs: ttlSecs}
}

// CheckAndRecord returns true if `nonce` was already consumed (replay).
// Safe to call from many goroutines simultaneously.
func (n *InMemoryNonceStore) CheckAndRecord(nonce string, seenAt time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := seenAt.Add(-time.Duration(n.TTLSecs) * time.Second)
	for k, t := range n.seen {
		if t.Before(cutoff) {
			delete(n.seen, k)
		}
	}
	if _, ok := n.seen[nonce]; ok {
		return true
	}
	n.seen[nonce] = seenAt
	return false
}

// RevocationResolver returns true when a principal or delegation has been
// revoked at or before `asOf`.
type RevocationResolver interface {
	IsPrincipalRevoked(principalDID string, asOf time.Time) bool
	IsDelegationRevoked(delegationID string, asOf time.Time) bool
}

// StaticRevocationResolver is the default in-memory backend.
type StaticRevocationResolver struct {
	RevokedPrincipals  []string
	RevokedDelegations []string
}

// IsPrincipalRevoked satisfies RevocationResolver.
func (s *StaticRevocationResolver) IsPrincipalRevoked(did string, _ time.Time) bool {
	for _, d := range s.RevokedPrincipals {
		if d == did {
			return true
		}
	}
	return false
}

// IsDelegationRevoked satisfies RevocationResolver.
func (s *StaticRevocationResolver) IsDelegationRevoked(id string, _ time.Time) bool {
	for _, d := range s.RevokedDelegations {
		if d == id {
			return true
		}
	}
	return false
}

// Context carries per-call verification inputs. Mirrors `VerifyContext` in
// the Rust core.
type Context struct {
	ReceiverDID string
	Now         time.Time
	SkewSecs    int
	Keys        KeyResolver
	Nonces      NonceStore
	Revocations RevocationResolver
}

// Acceptance is the success outcome — the chain-intersected effective scope.
type Acceptance struct {
	Capability           string
	EffectiveConstraints map[string]any
}

// Refusal is the structured rejection. Mirrors `RefusalReason` in the
// Rust core.
type Refusal struct {
	ErrorCode            ErrorCode
	RejectedAtStep       RejectStep
	Detail               string
	RejectedDelegationID string // empty for outer-request rejections
}

// Error satisfies the `error` interface so callers can `errors.As(err, &Refusal{})`.
func (r *Refusal) Error() string {
	if r.RejectedDelegationID != "" {
		return fmt.Sprintf("[%s @ %s in %s] %s", r.ErrorCode, r.RejectedAtStep, r.RejectedDelegationID, r.Detail)
	}
	return fmt.Sprintf("[%s @ %s] %s", r.ErrorCode, r.RejectedAtStep, r.Detail)
}

// Result is the verifier's typed return.
type Result struct {
	Acceptance *Acceptance
	Refusal    *Refusal
}

// Accepted reports whether the verifier accepted the request.
func (r *Result) Accepted() bool { return r.Acceptance != nil }

// VerifyHandshakeRequest runs the full chain-walk verifier over `req` using
// the inputs in `ctx`. See package docs for the step ordering.
func VerifyHandshakeRequest(req *models.HandshakeRequest, ctx *Context) *Result {
	skew := time.Duration(ctx.SkewSecs) * time.Second

	// --- Step 1: schema/version ----------------------------------------
	if req.Kind != "HandshakeRequest" {
		return refusalOuter(SignatureInvalid, StepSchemaValidation, fmt.Sprintf("expected kind=HandshakeRequest, got %s", req.Kind))
	}
	if req.Version != SpecVersion {
		return refusalOuter(ProtocolVersionUnsupported, StepSchemaValidation, fmt.Sprintf("expected version=%s, got %s", SpecVersion, req.Version))
	}
	if len(req.DelegationChain) == 0 {
		return refusalOuter(ChainBroken, StepSchemaValidation, "delegation_chain must contain at least one DelegationToken")
	}

	// --- Step 2: outer signature ---------------------------------------
	if rej := verifySignedPayload(req, req.Alg, req.Signature, req.Iss, ctx, StepSignatureVerification, ""); rej != nil {
		return &Result{Refusal: rej}
	}

	// --- Step 3: audience ----------------------------------------------
	if req.Aud != ctx.ReceiverDID {
		return refusalOuter(AudMismatch, StepAudienceCheck, fmt.Sprintf("request aud=%s does not match receiver %s", req.Aud, ctx.ReceiverDID))
	}

	// --- Step 4: freshness window --------------------------------------
	iat, err := time.Parse(time.RFC3339, req.Iat)
	if err != nil {
		return refusalOuter(SignatureInvalid, StepFreshnessWindow, fmt.Sprintf("request.iat unparseable: %v", err))
	}
	if iat.After(ctx.Now.Add(skew)) {
		return refusalOuter(NotYetValid, StepFreshnessWindow, fmt.Sprintf("request.iat %s is more than %ds ahead of now %s", req.Iat, ctx.SkewSecs, ctx.Now.Format(time.RFC3339)))
	}
	if iat.Before(ctx.Now.Add(-skew)) {
		return refusalOuter(Expired, StepFreshnessWindow, fmt.Sprintf("request.iat %s is more than %ds behind now %s", req.Iat, ctx.SkewSecs, ctx.Now.Format(time.RFC3339)))
	}

	// --- Step 5: nonce uniqueness --------------------------------------
	if ctx.Nonces.CheckAndRecord(req.Nonce, ctx.Now) {
		return refusalOuter(ReplayDetected, StepNonceCheck, fmt.Sprintf("nonce %s already consumed", req.Nonce))
	}

	// --- Step 6: leaf-issuer match -------------------------------------
	leaf := req.DelegationChain[len(req.DelegationChain)-1]
	if leaf.Sub != req.Iss {
		return refusalLink(ChainBroken, StepDelegationChainWalk, leaf.ID,
			fmt.Sprintf("leaf delegation sub=%s does not match request iss=%s", leaf.Sub, req.Iss))
	}

	// --- Step 7: per-link walk -----------------------------------------
	type cumulative struct {
		name        string
		constraints map[string]any
	}
	var cum *cumulative

	for idx, link := range req.DelegationChain {
		if rej := verifyLink(&link, idx, len(req.DelegationChain), req.Capability.Name, ctx); rej != nil {
			return &Result{Refusal: rej}
		}

		// Issuer-chain integrity: each non-root link's iss must equal the
		// previous link's sub.
		if idx > 0 {
			prev := req.DelegationChain[idx-1]
			if link.Iss != prev.Sub {
				return refusalLink(ChainBroken, StepDelegationChainWalk, link.ID,
					fmt.Sprintf("link iss=%s does not match prior link sub=%s", link.Iss, prev.Sub))
			}
		}

		// Find the capability inside this link that matches the request.
		var matched *models.Capability
		for i := range link.Capabilities {
			if link.Capabilities[i].Name == req.Capability.Name {
				matched = &link.Capabilities[i]
				break
			}
		}
		if matched == nil {
			return refusalLink(ChainBroken, StepDelegationChainWalk, link.ID,
				fmt.Sprintf("delegation does not grant capability %s; chain cannot satisfy request", req.Capability.Name))
		}

		linkConstraints := decodeConstraints(matched.Constraints)
		if cum == nil {
			cum = &cumulative{name: matched.Name, constraints: linkConstraints}
		} else {
			merged, err := intersect.Intersect(cum.constraints, linkConstraints)
			if err != nil {
				return refusalLink(ScopeExceeded, StepDelegationChainWalk, link.ID, err.Error())
			}
			cum = &cumulative{name: matched.Name, constraints: merged}
		}
	}

	// --- Step 8: scope intersection vs. request ------------------------
	reqConstraints := decodeConstraints(req.Capability.Constraints)
	effective, err := intersect.Intersect(cum.constraints, reqConstraints)
	if err != nil {
		return &Result{Refusal: &Refusal{
			ErrorCode:      ScopeExceeded,
			RejectedAtStep: StepScopeIntersection,
			Detail:         err.Error(),
		}}
	}

	return &Result{Acceptance: &Acceptance{Capability: cum.name, EffectiveConstraints: effective}}
}

func verifyLink(link *models.DelegationToken, idx, chainLen int, requestedCapabilityName string, ctx *Context) *Refusal {
	if link.Kind != "DelegationToken" {
		return &Refusal{ErrorCode: SignatureInvalid, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("expected kind=DelegationToken, got %s", link.Kind)}
	}

	// 7a: link signature
	if rej := verifySignedPayload(link, link.Alg, link.Signature, link.Iss, ctx, StepDelegationChainWalk, link.ID); rej != nil {
		return rej
	}

	// 7b: nbf ≤ now ≤ exp with ±skew
	skew := time.Duration(ctx.SkewSecs) * time.Second
	nbf, err := time.Parse(time.RFC3339, link.Nbf)
	if err != nil {
		return &Refusal{ErrorCode: SignatureInvalid, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("nbf unparseable: %v", err)}
	}
	exp, err := time.Parse(time.RFC3339, link.Exp)
	if err != nil {
		return &Refusal{ErrorCode: SignatureInvalid, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("exp unparseable: %v", err)}
	}
	if ctx.Now.Add(skew).Before(nbf) {
		return &Refusal{ErrorCode: NotYetValid, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("delegation nbf=%s is in the future relative to now=%s (±%ds)", link.Nbf, ctx.Now.Format(time.RFC3339), ctx.SkewSecs)}
	}
	if ctx.Now.Add(-skew).After(exp) {
		return &Refusal{ErrorCode: Expired, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("delegation exp=%s is in the past relative to now=%s (±%ds)", link.Exp, ctx.Now.Format(time.RFC3339), ctx.SkewSecs)}
	}

	// 7c: revocation
	if ctx.Revocations.IsDelegationRevoked(link.ID, ctx.Now) {
		return &Refusal{ErrorCode: CredentialRevoked, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("delegation %s is revoked", link.ID)}
	}
	if ctx.Revocations.IsPrincipalRevoked(link.Iss, ctx.Now) {
		return &Refusal{ErrorCode: CredentialRevoked, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
			Detail: fmt.Sprintf("issuer principal %s is revoked", link.Iss)}
	}

	// 7e: delegable + sub_delegation_depth_remaining for non-final links.
	// The *specific capability* the request is asking for must be
	// delegable=true on this link — checking "any cap on the link is
	// delegable" would let an attacker chain a non-delegable capability
	// A by co-mingling it with an unrelated delegable capability B.
	// (See architect review of T007 wrap-up; ADR-0007.)
	if idx+1 < chainLen {
		for i := range link.Capabilities {
			c := &link.Capabilities[i]
			if c.Name != requestedCapabilityName {
				continue
			}
			if c.Delegable == nil || !*c.Delegable {
				return &Refusal{ErrorCode: ChainBroken, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
					Detail: fmt.Sprintf("intermediate delegation: capability %s is not delegable on this link", requestedCapabilityName)}
			}
			break
		}
		// If the requested capability isn't on this link at all, the
		// caller's matched-capability lookup (right after this function
		// returns) emits the canonical ChainBroken at the same step.
		if link.SubDelegationDepthRemaining == 0 {
			return &Refusal{ErrorCode: ChainBroken, RejectedAtStep: StepDelegationChainWalk, RejectedDelegationID: link.ID,
				Detail: "sub_delegation_depth_remaining is 0 but chain extends further"}
		}
	}
	return nil
}

// verifySignedPayload checks the signature on a HandshakeRequest or
// DelegationToken. The bytes-to-sign are the JCS canonicalization of the
// payload with the `signature` field stripped.
func verifySignedPayload(payload any, alg models.SignatureAlgorithm, signatureB64 string, issuerDID string, ctx *Context, step RejectStep, delegationID string) *Refusal {
	if signatureB64 == "" {
		return makeRefusal(SignatureInvalid, step, delegationID, "envelope is missing `signature` field")
	}
	if alg != models.AlgEdDSA {
		// Phase 2 supports EdDSA only; ML-DSA-65 lands in v0.3 per ADR-0006.
		return makeRefusal(ProtocolVersionUnsupported, step, delegationID,
			fmt.Sprintf("alg %s not supported by Phase 2 verifier (EdDSA only); ML-DSA-65 + Hybrid land in v0.3", alg))
	}
	pk, ok := ctx.Keys.Resolve(issuerDID)
	if !ok {
		return makeRefusal(SignatureInvalid, step, delegationID,
			fmt.Sprintf("no public key registered for issuer %s", issuerDID))
	}
	msg, err := bytesToSign(payload)
	if err != nil {
		return makeRefusal(SignatureInvalid, step, delegationID, fmt.Sprintf("canonicalization failed: %v", err))
	}
	if err := signing.VerifyEd25519B64(ed25519.PublicKey(pk), signatureB64, msg); err != nil {
		return makeRefusal(SignatureInvalid, step, delegationID, fmt.Sprintf("signature did not verify: %v", err))
	}
	return nil
}

// bytesToSign computes the canonicalized signing payload — same shape as
// the Rust core's `bytes_to_sign`.
func bytesToSign(payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return nil, fmt.Errorf("re-decode: %w", err)
	}
	delete(asMap, "signature")
	canonical, err := jcs.Canonicalize(asMap)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return canonical, nil
}

func decodeConstraints(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}
	return m
}

func refusalOuter(code ErrorCode, step RejectStep, detail string) *Result {
	return &Result{Refusal: &Refusal{ErrorCode: code, RejectedAtStep: step, Detail: detail}}
}

func refusalLink(code ErrorCode, step RejectStep, delegationID, detail string) *Result {
	return &Result{Refusal: &Refusal{ErrorCode: code, RejectedAtStep: step, RejectedDelegationID: delegationID, Detail: detail}}
}

func makeRefusal(code ErrorCode, step RejectStep, delegationID, detail string) *Refusal {
	return &Refusal{ErrorCode: code, RejectedAtStep: step, RejectedDelegationID: delegationID, Detail: detail}
}

// SortedKeys returns the keys of m in sorted order — exposed for tests
// that want to compare effective_constraints byte-for-byte across runs.
func SortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsRefusalCode reports whether `result.Refusal.ErrorCode` matches any of
// the supplied codes. Convenience helper for tests.
func (r *Result) IsRefusalCode(codes ...ErrorCode) bool {
	if r.Refusal == nil {
		return false
	}
	for _, c := range codes {
		if r.Refusal.ErrorCode == c {
			return true
		}
	}
	return false
}

// FormatDetail surfaces the `detail` field for substring assertions in the
// conformance harness.
func (r *Result) FormatDetail() string {
	if r.Refusal == nil {
		return ""
	}
	return strings.TrimSpace(r.Refusal.Detail)
}
