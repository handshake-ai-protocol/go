package models

import (
	"encoding/json"
	"strings"
	"testing"
)

// validDelegation returns a fully-populated DelegationToken whose `validate`
// tags should all pass. Tests then mutate copies of it to exercise individual
// rules; this keeps the assertions focused.
func validDelegation() DelegationToken {
	delegable := true
	return DelegationToken{
		Version:                     "0.2.3",
		Kind:                        "DelegationToken",
		ID:                          "del_01HXXXXXXXXXXXXXXX",
		Iss:                         "did:web:user.example",
		Sub:                         "did:web:agent.example",
		Aud:                         "did:web:service.example",
		Iat:                         "2026-04-30T12:00:00Z",
		Nbf:                         "2026-04-30T12:00:00Z",
		Exp:                         "2026-04-30T12:10:00Z",
		Capabilities:                []Capability{{Name: "invoices.read", Constraints: json.RawMessage(`{"max":100}`), Delegable: &delegable}},
		SubDelegationDepthRemaining: 1,
		Alg:                         AlgEdDSA,
	}
}

func TestDelegationToken_Valid(t *testing.T) {
	d := validDelegation()
	if err := d.Validate(); err != nil {
		t.Fatalf("expected valid delegation, got %v", err)
	}
}

func TestDelegationToken_RejectsWrongKind(t *testing.T) {
	d := validDelegation()
	d.Kind = "NotDelegationToken"
	err := d.Validate()
	if err == nil {
		t.Fatal("expected validation error for wrong Kind")
	}
	if !strings.Contains(err.Error(), "Kind") {
		t.Fatalf("expected error to mention Kind, got %v", err)
	}
}

func TestDelegationToken_RejectsUnknownAlgorithm(t *testing.T) {
	d := validDelegation()
	d.Alg = "RSA-PSS"
	if err := d.Validate(); err == nil {
		t.Fatal("expected validation error for unknown signature algorithm")
	}
}

func TestDelegationToken_RequiresAtLeastOneCapability(t *testing.T) {
	d := validDelegation()
	d.Capabilities = nil
	if err := d.Validate(); err == nil {
		t.Fatal("expected validation error for empty capabilities list")
	}
}

func TestDelegationToken_AcceptsAllSpecAlgorithms(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{AlgEdDSA, AlgMLDSA65, AlgHybridEdDSAMLDSA65} {
		d := validDelegation()
		d.Alg = alg
		if err := d.Validate(); err != nil {
			t.Errorf("alg %s: expected valid, got %v", alg, err)
		}
	}
}

func TestHandshakeRequest_RoundTripsThroughJSON(t *testing.T) {
	d := validDelegation()
	d.Signature = "stub"
	req := HandshakeRequest{
		Version:          "0.2.3",
		Kind:             "HandshakeRequest",
		ID:               "req_01HXXXXXXXXXXXXXXX",
		Iss:              "did:web:agent.example",
		Aud:              "did:web:service.example",
		Iat:              "2026-04-30T12:01:00Z",
		Nonce:            "n_01HXXXXXXXXXXXXXXX",
		AgentAttestation: json.RawMessage(`{"runtime":"replit"}`),
		Capability:       Capability{Name: "invoices.read"},
		DelegationChain:  []DelegationToken{d},
		Alg:              AlgEdDSA,
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("expected valid request, got %v", err)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round HandshakeRequest
	if err := json.Unmarshal(payload, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := round.Validate(); err != nil {
		t.Fatalf("round-tripped request failed validation: %v", err)
	}
}

func TestReceipt_RejectsUnknownResult(t *testing.T) {
	r := Receipt{
		Version:     "0.2.3",
		Kind:        "Receipt",
		ID:          "rec_01HXXXXXXXXXXXXXXX",
		HandshakeID: "req_01HXXXXXXXXXXXXXXX",
		Iss:         "did:web:service.example",
		Sub:         "did:web:agent.example",
		Action:      "invoices.read",
		ExecutedAt:  "2026-04-30T12:01:05Z",
		Result:      "weird",
		ResultHash:  HashValue{Alg: HashSHA256, Value: "deadbeef"},
		Alg:         AlgEdDSA,
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected validation error for unknown Result value")
	}
}
