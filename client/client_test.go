package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/client"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
)

func newClient(t *testing.T) (*client.Client, *signing.Ed25519Keypair) {
	t.Helper()
	kp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	c, err := client.New(client.Config{
		RegistryURL: "http://example.invalid",
		DID:         "did:hsk:test.go.client",
		Signer:      client.NewSoftwareSigner(kp.Private),
		Offline:     true,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, kp
}

// TestDelegateSignsCanonical verifies the DelegationToken's signature is over
// the canonical JCS bytes of the envelope minus its `signature` field — i.e.
// matches the wire-format contract enforced by the conformance suite.
func TestDelegateSignsCanonical(t *testing.T) {
	c, kp := newClient(t)
	tok, err := c.Delegate(client.DelegateInput{
		Sub:        c.DID(),
		Aud:        "did:hsk:tool.test",
		Capability: "fs.read",
	})
	if err != nil {
		t.Fatalf("Delegate: %v", err)
	}
	if tok.Signature == "" {
		t.Fatalf("delegation token unsigned")
	}

	// Reconstruct the canonical bytes: marshal a copy with signature blanked,
	// then JCS — and verify the original signature against those bytes. Using
	// a copy avoids mutating the struct under test.
	signed := tok.Signature
	clone := *tok
	clone.Signature = ""
	raw, err := json.Marshal(clone)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	canon, err := jcs.CanonicalizeBytes(raw)
	if err != nil {
		t.Fatalf("jcs: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(kp.Public, canon, sig) {
		t.Fatalf("delegation signature did not verify against canonical bytes")
	}
}

// TestRecordReceiptOfflineMergesParents ensures the DAG provenance contract
// holds: receipts merge HandshakeContext.ParentReceiptIDs with the per-call
// UpstreamReceipts list, dedup-ing by id.
func TestRecordReceiptOfflineMergesParents(t *testing.T) {
	c, _ := newClient(t)
	tok, err := c.Delegate(client.DelegateInput{
		Sub: c.DID(), Aud: "did:hsk:tool", Capability: "fs.read",
	})
	if err != nil {
		t.Fatalf("Delegate: %v", err)
	}
	hsCtx, err := c.Handshake(client.HandshakeInput{
		Aud: "did:hsk:tool", Capability: "fs.read",
		Chain: []models.DelegationToken{*tok},
	})
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	hsCtx.AddParent("rc_parent_a")
	hsCtx.AddParent("rc_parent_a") // duplicate is dropped

	out, err := c.RecordReceipt(context.Background(), hsCtx, client.RecordInput{
		Action:           "fs.read",
		UpstreamReceipts: []string{"rc_parent_a", "rc_parent_b"}, // first dup vs ctx
	})
	if err != nil {
		t.Fatalf("RecordReceipt: %v", err)
	}
	if got := out.Receipt.UpstreamReceipts; len(got) != 2 || got[0] != "rc_parent_a" || got[1] != "rc_parent_b" {
		t.Fatalf("merged upstream want [rc_parent_a rc_parent_b], got %v", got)
	}
	if !strings.HasPrefix(out.Receipt.ID, "rc_") {
		t.Fatalf("receipt id should be rc-prefixed, got %s", out.Receipt.ID)
	}
}

// TestRecordReceiptPostsToRegistry verifies that in non-offline mode the
// SDK posts the canonical receipt JSON to /v1/receipts with HTTP 202 as the
// success code. Uses an httptest stand-in for the Phase-3 Registry so the
// test stays hermetic.
func TestRecordReceiptPostsToRegistry(t *testing.T) {
	var seen []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/receipts" || r.Method != http.MethodPost {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		seen = body
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"leaf_hash":"deadbeef"}`))
	}))
	defer srv.Close()

	kp, _ := signing.GenerateEd25519()
	c, err := client.New(client.Config{
		RegistryURL: srv.URL,
		DID:         "did:hsk:test.go.live",
		Signer:      client.NewSoftwareSigner(kp.Private),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	tok, _ := c.Delegate(client.DelegateInput{Sub: c.DID(), Aud: "did:hsk:tool", Capability: "fs.read"})
	hsCtx, _ := c.Handshake(client.HandshakeInput{Aud: "did:hsk:tool", Capability: "fs.read", Chain: []models.DelegationToken{*tok}})
	out, err := c.RecordReceipt(context.Background(), hsCtx, client.RecordInput{Action: "fs.read"})
	if err != nil {
		t.Fatalf("RecordReceipt: %v", err)
	}
	if out.LeafHash != "deadbeef" {
		t.Fatalf("leaf hash mismatch: %s", out.LeafHash)
	}
	if len(seen) == 0 {
		t.Fatalf("no body received")
	}
	var parsed map[string]any
	if err := json.Unmarshal(seen, &parsed); err != nil {
		t.Fatalf("registry got non-JSON body: %v", err)
	}
	if parsed["kind"] != "Receipt" || parsed["id"] != out.Receipt.ID {
		t.Fatalf("registry payload mismatch: %+v", parsed)
	}
}

// Quiet the unused-import linter without bringing in extra deps.
var _ = rand.Reader
