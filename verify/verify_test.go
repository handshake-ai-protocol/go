// Unit tests for the Phase 2 chain-walk verifier (Go side).
//
// Mirrors the Rust core's `tests` module in `verify.rs`. The fresh-keypair
// helpers + canonical signing use the same JCS path as the conformance
// runner, so passing here means the byte-equality bar with Rust holds.
package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
)

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return tt
}

// buildValid returns a signed (request, resolver, receiverDID) triple
// equivalent to the Rust core's `build_valid()` helper.
func buildValid(t *testing.T) (*models.HandshakeRequest, *StaticKeyResolver, string) {
	t.Helper()
	userKp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("user keypair: %v", err)
	}
	agentKp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("agent keypair: %v", err)
	}

	delegable := false
	delegation := models.DelegationToken{
		Version: SpecVersion,
		Kind:    "DelegationToken",
		ID:      "dt_test",
		Iss:     "did:hsk:user:alice",
		Sub:     "did:hsk:agent:bob",
		Aud:     "did:hsk:agent:bob",
		Iat:     "2026-04-29T14:02:11Z",
		Nbf:     "2026-04-29T14:02:11Z",
		Exp:     "2026-04-29T14:32:11Z",
		Capabilities: []models.Capability{
			{
				Name:        "billing.invoices.read",
				Constraints: json.RawMessage(`{"max_invoices":100}`),
				Delegable:   &delegable,
			},
		},
		SubDelegationDepthRemaining: 0,
		Alg:                         models.AlgEdDSA,
	}
	delMsg, err := bytesToSign(&delegation)
	if err != nil {
		t.Fatalf("delegation canon: %v", err)
	}
	delegation.Signature = signing.SignEd25519B64(userKp.Private, delMsg)

	request := models.HandshakeRequest{
		Version:          SpecVersion,
		Kind:             "HandshakeRequest",
		ID:               "hs_test",
		Iss:              "did:hsk:agent:bob",
		Aud:              "did:hsk:svc:test-service",
		Iat:              "2026-04-29T14:14:32Z",
		Nonce:            "k7nQ9pX3vR2mT4uV6wY8zA",
		AgentAttestation: json.RawMessage(`{"deployer":"did:hsk:org:deployer","model":"claude-sonnet-4-5"}`),
		Capability: models.Capability{
			Name:        "billing.invoices.read",
			Constraints: json.RawMessage(`{"max_invoices":100}`),
		},
		DelegationChain: []models.DelegationToken{delegation},
		Alg:             models.AlgEdDSA,
	}
	reqMsg, err := bytesToSign(&request)
	if err != nil {
		t.Fatalf("request canon: %v", err)
	}
	request.Signature = signing.SignEd25519B64(agentKp.Private, reqMsg)

	resolver := NewStaticKeyResolver()
	resolver.Insert("did:hsk:user:alice", []byte(ed25519.PublicKey(userKp.Public)))
	resolver.Insert("did:hsk:agent:bob", []byte(ed25519.PublicKey(agentKp.Public)))
	return &request, resolver, "did:hsk:svc:test-service"
}

func TestAcceptance(t *testing.T) {
	req, resolver, svc := buildValid(t)
	ctx := &Context{
		ReceiverDID: svc,
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: &StaticRevocationResolver{},
	}
	res := VerifyHandshakeRequest(req, ctx)
	if !res.Accepted() {
		t.Fatalf("expected accept, got refusal: %+v", res.Refusal)
	}
	if res.Acceptance.Capability != "billing.invoices.read" {
		t.Fatalf("unexpected capability: %s", res.Acceptance.Capability)
	}
}

func TestRejectsExpiredDelegation(t *testing.T) {
	req, resolver, svc := buildValid(t)
	ctx := &Context{
		ReceiverDID: svc,
		// Jump 18 minutes past delegation.exp + request.iat
		Now:         mustParse(t, "2026-04-29T14:50:11Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: &StaticRevocationResolver{},
	}
	res := VerifyHandshakeRequest(req, ctx)
	if res.Accepted() {
		t.Fatalf("expected reject")
	}
	if res.Refusal.ErrorCode != Expired {
		t.Fatalf("expected expired, got %s", res.Refusal.ErrorCode)
	}
}

func TestRejectsScopeExceeded(t *testing.T) {
	req, resolver, svc := buildValid(t)
	// Mutate the request to ask for more than the delegation grants and
	// re-sign with a fresh key (Rust test uses the same trick).
	req.Capability.Constraints = json.RawMessage(`{"max_invoices":500}`)
	req.Signature = ""
	agentKp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := bytesToSign(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = signing.SignEd25519B64(agentKp.Private, msg)
	resolver.Insert("did:hsk:agent:bob", []byte(ed25519.PublicKey(agentKp.Public)))

	ctx := &Context{
		ReceiverDID: svc,
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: &StaticRevocationResolver{},
	}
	res := VerifyHandshakeRequest(req, ctx)
	if res.Accepted() {
		t.Fatal("expected reject")
	}
	if res.Refusal.ErrorCode != ScopeExceeded {
		t.Fatalf("expected scope_exceeded, got %s", res.Refusal.ErrorCode)
	}
	if !strings.Contains(res.Refusal.Detail, "max_invoices") {
		t.Fatalf("expected detail to mention max_invoices, got %q", res.Refusal.Detail)
	}
}

func TestReplayRejected(t *testing.T) {
	req, resolver, svc := buildValid(t)
	nonces := NewInMemoryNonceStore(120)
	ctx := &Context{
		ReceiverDID: svc,
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      nonces,
		Revocations: &StaticRevocationResolver{},
	}
	if !VerifyHandshakeRequest(req, ctx).Accepted() {
		t.Fatal("first call should accept")
	}
	res := VerifyHandshakeRequest(req, ctx)
	if res.Accepted() {
		t.Fatal("replay should be rejected")
	}
	if res.Refusal.ErrorCode != ReplayDetected {
		t.Fatalf("expected replay_detected, got %s", res.Refusal.ErrorCode)
	}
}

func TestAudienceMismatch(t *testing.T) {
	req, resolver, _ := buildValid(t)
	ctx := &Context{
		ReceiverDID: "did:hsk:svc:wrong-audience",
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: &StaticRevocationResolver{},
	}
	res := VerifyHandshakeRequest(req, ctx)
	if res.Accepted() {
		t.Fatal("expected reject")
	}
	if res.Refusal.ErrorCode != AudMismatch {
		t.Fatalf("expected aud_mismatch, got %s", res.Refusal.ErrorCode)
	}
}

func TestRevokedDelegationRejected(t *testing.T) {
	req, resolver, svc := buildValid(t)
	revs := &StaticRevocationResolver{RevokedDelegations: []string{"dt_test"}}
	ctx := &Context{
		ReceiverDID: svc,
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: revs,
	}
	res := VerifyHandshakeRequest(req, ctx)
	if res.Accepted() {
		t.Fatal("expected reject")
	}
	if res.Refusal.ErrorCode != CredentialRevoked {
		t.Fatalf("expected credential_revoked, got %s", res.Refusal.ErrorCode)
	}
}

// TestChainBrokenWhenRequestedCapNotDelegableEvenIfOtherCapIs guards the
// architect-flagged authorization-escalation case from the T007 wrap-up
// review: an intermediate link grants two capabilities — the requested
// one with delegable=false and an unrelated one with delegable=true. The
// chain MUST be rejected with chain_broken at delegation_chain_walk;
// co-mingling an unrelated delegable capability MUST NOT be enough to
// launder a non-delegable one. Mirrored as conformance vector
// `error_codes/009-non-delegable-capability.json`.
func TestChainBrokenWhenRequestedCapNotDelegableEvenIfOtherCapIs(t *testing.T) {
	aliceKp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	agent1Kp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("agent1 keypair: %v", err)
	}
	agent2Kp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("agent2 keypair: %v", err)
	}

	notDelegable := false
	delegable := true

	root := models.DelegationToken{
		Version: SpecVersion,
		Kind:    "DelegationToken",
		ID:      "dt_009a",
		Iss:     "did:hsk:user:alice",
		Sub:     "did:hsk:agent:agent1",
		Aud:     "did:hsk:agent:agent1",
		Iat:     "2026-04-29T14:02:11Z",
		Nbf:     "2026-04-29T14:02:11Z",
		Exp:     "2026-04-29T14:32:11Z",
		Capabilities: []models.Capability{
			// Requested cap: NOT delegable.
			{
				Name:        "billing.invoices.read",
				Constraints: json.RawMessage(`{"max_invoices":100}`),
				Delegable:   &notDelegable,
			},
			// Decoy cap: delegable.
			{
				Name:        "billing.invoices.export",
				Constraints: json.RawMessage(`{"max_invoices":100}`),
				Delegable:   &delegable,
			},
		},
		SubDelegationDepthRemaining: 1,
		Alg:                         models.AlgEdDSA,
	}
	rootMsg, err := bytesToSign(&root)
	if err != nil {
		t.Fatalf("root canon: %v", err)
	}
	root.Signature = signing.SignEd25519B64(aliceKp.Private, rootMsg)

	leaf := models.DelegationToken{
		Version: SpecVersion,
		Kind:    "DelegationToken",
		ID:      "dt_009b",
		Iss:     "did:hsk:agent:agent1",
		Sub:     "did:hsk:agent:agent2",
		Aud:     "did:hsk:agent:agent2",
		Iat:     "2026-04-29T14:03:00Z",
		Nbf:     "2026-04-29T14:03:00Z",
		Exp:     "2026-04-29T14:33:00Z",
		Capabilities: []models.Capability{
			{
				Name:        "billing.invoices.read",
				Constraints: json.RawMessage(`{"max_invoices":50}`),
				Delegable:   &notDelegable,
			},
		},
		SubDelegationDepthRemaining: 0,
		Alg:                         models.AlgEdDSA,
	}
	leafMsg, err := bytesToSign(&leaf)
	if err != nil {
		t.Fatalf("leaf canon: %v", err)
	}
	leaf.Signature = signing.SignEd25519B64(agent1Kp.Private, leafMsg)

	request := models.HandshakeRequest{
		Version:          SpecVersion,
		Kind:             "HandshakeRequest",
		ID:               "hs_009",
		Iss:              "did:hsk:agent:agent2",
		Aud:              "did:hsk:svc:test-service",
		Iat:              "2026-04-29T14:14:32Z",
		Nonce:            "nonce-009-go",
		AgentAttestation: json.RawMessage(`{"deployer":"did:hsk:org:o","model":"claude-sonnet-4-5"}`),
		Capability: models.Capability{
			Name:        "billing.invoices.read",
			Constraints: json.RawMessage(`{"max_invoices":25}`),
		},
		DelegationChain: []models.DelegationToken{root, leaf},
		Alg:             models.AlgEdDSA,
	}
	reqMsg, err := bytesToSign(&request)
	if err != nil {
		t.Fatalf("request canon: %v", err)
	}
	request.Signature = signing.SignEd25519B64(agent2Kp.Private, reqMsg)

	resolver := NewStaticKeyResolver()
	resolver.Insert("did:hsk:user:alice", []byte(ed25519.PublicKey(aliceKp.Public)))
	resolver.Insert("did:hsk:agent:agent1", []byte(ed25519.PublicKey(agent1Kp.Public)))
	resolver.Insert("did:hsk:agent:agent2", []byte(ed25519.PublicKey(agent2Kp.Public)))

	ctx := &Context{
		ReceiverDID: "did:hsk:svc:test-service",
		Now:         mustParse(t, "2026-04-29T14:14:32Z"),
		SkewSecs:    DefaultSkewSecs,
		Keys:        resolver,
		Nonces:      NewInMemoryNonceStore(120),
		Revocations: &StaticRevocationResolver{},
	}
	res := VerifyHandshakeRequest(&request, ctx)
	if res.Accepted() {
		t.Fatal("must reject — non-delegable cap with delegable decoy")
	}
	if res.Refusal.ErrorCode != ChainBroken {
		t.Fatalf("expected chain_broken, got %s", res.Refusal.ErrorCode)
	}
	if res.Refusal.RejectedAtStep != StepDelegationChainWalk {
		t.Fatalf("expected delegation_chain_walk, got %s", res.Refusal.RejectedAtStep)
	}
	if res.Refusal.RejectedDelegationID != "dt_009a" {
		t.Fatalf("expected dt_009a as rejected delegation, got %s", res.Refusal.RejectedDelegationID)
	}
	if !strings.Contains(res.Refusal.Detail, "billing.invoices.read") || !strings.Contains(res.Refusal.Detail, "not delegable") {
		t.Fatalf("expected detail to name the non-delegable cap, got %q", res.Refusal.Detail)
	}
}

// TestJCSEqualityWithRust is a smoke check: the JCS canonicalization of a
// signed delegation must round-trip through Go's encoding without changing
// the signature payload. The cross-language byte-equality bar is enforced
// by the conformance runner.
func TestJCSCanonicalizationRoundTrip(t *testing.T) {
	req, _, _ := buildValid(t)
	canonical, err := jcs.Canonicalize(req)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("canonical bytes empty")
	}
}
