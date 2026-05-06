// SPDX-License-Identifier: MIT
// phase4-smoke is the live end-to-end check for the Go SDK against a
// running Phase-3 Registry. It bootstraps a tenant + producer DID, posts a
// Receipt via client.Client, and waits for the anchor.
//
// Used by `make phase4-go` and the wider `make phase4` target.

package main

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/handshake-ai-protocol/go/client"
	"github.com/handshake-ai-protocol/go/signing"
)

func main() {
	registry := envOr("HANDSHAKE_REGISTRY", "http://localhost:8080")
	tok := adminToken()
	if tok == "" {
		log.Fatalf("HANDSHAKE_ADMIN_TOKEN environment variable is required")
	}

	suffix := hex.EncodeToString(randBytes(4))
	slug := fmt.Sprintf("go-phase4-%d-%s", time.Now().Unix(), suffix)
	controllerDID := fmt.Sprintf("did:hsk:go-phase4-controller-%s", suffix)
	producerDID := fmt.Sprintf("did:hsk:go-phase4-%s", suffix)

	mustAdminPost(registry, tok, "/v1/admin/tenants", map[string]any{
		"slug":           slug,
		"display_name":   "Go Phase 4 smoke",
		"region":         "us-east",
		"controller_did": controllerDID,
	})

	kp, err := signing.GenerateEd25519()
	if err != nil {
		log.Fatalf("ed25519 keygen: %v", err)
	}
	mustAdminPost(registry, tok, "/v1/admin/dids", map[string]any{
		"tenant_slug":                 slug,
		"did":                         producerDID,
		"role":                        "service",
		"did_document":                map[string]any{"@context": []string{"https://www.w3.org/ns/did/v1"}, "id": producerDID},
		"primary_ed25519_pubkey_b64u": base64.RawURLEncoding.EncodeToString(kp.Public),
	})

	// Mirror examples/_phase4_common.py:116 — pass AdminToken so the
	// SDK's FetchReceipt / WaitForAnchor calls send Authorization: Bearer
	// against a Registry that enforces auth on GET /v1/receipts/{id}.
	c, err := client.New(client.Config{
		RegistryURL: registry,
		DID:         producerDID,
		Signer:      client.NewSoftwareSigner(kp.Private),
		AdminToken:  tok,
	})
	if err != nil {
		log.Fatalf("client.New: %v", err)
	}

	delegation, err := c.Delegate(client.DelegateInput{
		Sub: producerDID, Aud: "did:hsk:tool.go.smoke", Capability: "fs.read",
	})
	if err != nil {
		log.Fatalf("Delegate: %v", err)
	}
	hsCtx, err := c.Handshake(client.HandshakeInput{
		Aud: "did:hsk:tool.go.smoke", Capability: "fs.read",
		Chain: chainOf(*delegation),
	})
	if err != nil {
		log.Fatalf("Handshake: %v", err)
	}
	out, err := c.RecordReceipt(context.Background(), hsCtx, client.RecordInput{
		Action:        "fs.read",
		ResultPayload: map[string]any{"file": "smoke.txt", "bytes": 12},
	})
	if err != nil {
		log.Fatalf("RecordReceipt: %v", err)
	}
	fmt.Printf("→ go phase4 receipt %s posted\n", out.ReceiptID)
	if _, err := c.WaitForAnchor(context.Background(), out.ReceiptID, 15*time.Second, 400*time.Millisecond); err != nil {
		log.Fatalf("WaitForAnchor: %v", err)
	}
	fmt.Printf("OK go phase4 smoke green: %s anchored\n", out.ReceiptID)
}

func envOr(k, v string) string {
	if got := os.Getenv(k); got != "" {
		return got
	}
	return v
}

func adminToken() string {
	return os.Getenv("HANDSHAKE_ADMIN_TOKEN")
}

func mustAdminPost(registry, token, path string, body map[string]any) {
	raw, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("marshal %s: %v", path, err)
	}
	req, err := http.NewRequest(http.MethodPost, registry+path, bytes.NewReader(raw))
	if err != nil {
		log.Fatalf("build %s: %v", path, err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		log.Fatalf("%s → %d %s", path, resp.StatusCode, string(respBody))
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rngReader{}, b); err != nil {
		log.Fatalf("randBytes: %v", err)
	}
	return b
}

// rngReader is a thin wrapper around crypto/rand.Reader so we can avoid the
// import-cycle awkwardness in test mains. Defined here to keep the smoke
// binary self-contained.
type rngReader struct{}

func (rngReader) Read(p []byte) (int, error) {
	// Local import to avoid leaking crypto/rand into the package’s public
	// surface from the binary; cheap because go imports are transitive.
	return cryptoRandRead(p)
}

func cryptoRandRead(p []byte) (int, error) {
	return cryptoRand.Read(p)
}

// chainOf returns a single-token slice. Helper for readability; gofmt
// otherwise wants this inline at the call site and the test reads worse.
func chainOf[T any](v T) []T { return []T{v} }
