// SPDX-License-Identifier: MIT
// Package client is the Phase 4 Handshake SDK surface for Go services.
//
// One Client per producer DID per process. The Client owns a private key
// (typically wrapping handshake/signing) and the Registry base URL; it
// produces signed DelegationTokens, HandshakeRequests, and Receipts whose
// canonical bytes are byte-equal to the Python and TypeScript SDKs because
// all three share the JCS+Ed25519 contract enforced by the conformance
// suite.
//
// The minimum viable producer flow:
//
//	c, _ := client.New(client.Config{
//	    RegistryURL: "http://localhost:8080",
//	    DID:         "did:hsk:my.svc",
//	    Signer:      signing.NewSoftwareSigner(kp.Private),
//	})
//	tok, _ := c.Delegate(client.DelegateInput{Sub: c.DID(), Aud: "did:hsk:tool", Capability: "fs.read"})
//	ctx, _ := c.Handshake(client.HandshakeInput{Aud: "did:hsk:tool", Capability: "fs.read", Chain: []models.DelegationToken{*tok}})
//	out, _ := c.RecordReceipt(context.Background(), ctx, client.RecordInput{Action: "fs.read"})
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/jcs"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
)

// Signer is the narrow interface every KMS backend must satisfy so the
// Client never holds raw private bytes itself. handshake/signing's
// SoftwareSigner is the in-process default; HSM backends may implement this
// directly.
type Signer interface {
	Algorithm() models.SignatureAlgorithm
	PublicKey() []byte
	Sign(message []byte) ([]byte, error)
}

// SoftwareSigner is the default in-process Ed25519 signer.
type SoftwareSigner struct {
	priv ed25519.PrivateKey
}

// NewSoftwareSigner wraps an Ed25519 private key.
func NewSoftwareSigner(priv ed25519.PrivateKey) *SoftwareSigner { return &SoftwareSigner{priv: priv} }

// Algorithm returns the wire-format algorithm name.
func (s *SoftwareSigner) Algorithm() models.SignatureAlgorithm { return models.AlgEdDSA }

// PublicKey returns the 32-byte raw public key.
func (s *SoftwareSigner) PublicKey() []byte {
	return s.priv.Public().(ed25519.PublicKey)
}

// Sign produces a 64-byte raw Ed25519 signature.
func (s *SoftwareSigner) Sign(message []byte) ([]byte, error) {
	return signing.SignEd25519(s.priv, message), nil
}

// Config configures a Client.
type Config struct {
	// RegistryURL is the Phase-3 Registry base URL. Trailing slash is OK.
	RegistryURL string
	// DID is the producer DID (this signer's `iss`).
	DID string
	// Signer holds the private key. Required.
	Signer Signer
	// HTTPClient is optional. Defaults to a 10s-timeout client.
	HTTPClient *http.Client
	// Offline, if true, signs envelopes but never POSTs to the Registry.
	// Useful for unit tests that just want the canonical bytes.
	Offline bool
}

// Client is the Handshake SDK entry point.
type Client struct {
	cfg     Config
	http    *http.Client
	baseURL string
}

// New constructs a Client and validates the config.
func New(cfg Config) (*Client, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("handshake/client: Signer is required")
	}
	if cfg.DID == "" {
		return nil, fmt.Errorf("handshake/client: DID is required")
	}
	if cfg.RegistryURL == "" && !cfg.Offline {
		return nil, fmt.Errorf("handshake/client: RegistryURL is required unless Offline=true")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		cfg:     cfg,
		http:    httpClient,
		baseURL: strings.TrimRight(cfg.RegistryURL, "/"),
	}, nil
}

// DID returns the producer DID this client signs as.
func (c *Client) DID() string { return c.cfg.DID }

// Signer returns the configured Signer. Useful for callers (notably tests
// and the HTTP middleware adapter) that need to publish the producer's
// public key under a KeyResolver.
func (c *Client) Signer() Signer { return c.cfg.Signer }

// DelegateInput parametrises Delegate.
type DelegateInput struct {
	Sub                         string
	Aud                         string
	Capability                  string
	Constraints                 json.RawMessage
	DurationSeconds             int
	SubDelegationDepthRemaining uint32
	ParentDelegationID          string
}

// Delegate mints and signs a DelegationToken.
func (c *Client) Delegate(in DelegateInput) (*models.DelegationToken, error) {
	now := time.Now().UTC()
	dur := time.Duration(in.DurationSeconds) * time.Second
	if dur == 0 {
		dur = time.Hour
	}
	tok := &models.DelegationToken{
		Version:                     handshake.SpecVersion,
		Kind:                        "DelegationToken",
		ID:                          mustULID("dt"),
		Iss:                         c.cfg.DID,
		Sub:                         in.Sub,
		Aud:                         in.Aud,
		Iat:                         iso(now),
		Nbf:                         iso(now),
		Exp:                         iso(now.Add(dur)),
		Capabilities:                []models.Capability{{Name: in.Capability, Constraints: in.Constraints}},
		SubDelegationDepthRemaining: in.SubDelegationDepthRemaining,
		ParentDelegationID:          in.ParentDelegationID,
		Alg:                         c.cfg.Signer.Algorithm(),
	}
	if err := c.signEnvelope(tok, &tok.Signature); err != nil {
		return nil, err
	}
	return tok, nil
}

// HandshakeInput parametrises Handshake.
type HandshakeInput struct {
	Aud              string
	Capability       string
	Constraints      json.RawMessage
	Chain            []models.DelegationToken
	Nonce            string
	AgentAttestation json.RawMessage
}

// HandshakeContext is the in-process bag carried between Handshake and
// RecordReceipt. It tracks DAG provenance via ParentReceiptIDs.
type HandshakeContext struct {
	Request          models.HandshakeRequest
	HandshakeID      string
	Iss              string
	Sub              string
	Capability       models.Capability
	ParentReceiptIDs []string
}

// AddParent appends a receipt id to the upstream DAG (idempotent).
func (h *HandshakeContext) AddParent(receiptID string) {
	if receiptID == "" {
		return
	}
	for _, existing := range h.ParentReceiptIDs {
		if existing == receiptID {
			return
		}
	}
	h.ParentReceiptIDs = append(h.ParentReceiptIDs, receiptID)
}

// Handshake mints and signs a HandshakeRequest and returns a context.
func (c *Client) Handshake(in HandshakeInput) (*HandshakeContext, error) {
	if in.AgentAttestation == nil {
		in.AgentAttestation = json.RawMessage(fmt.Sprintf(
			`{"runtime":"handshake-go","version":%q}`, handshake.SpecVersion,
		))
	}
	if in.Nonce == "" {
		in.Nonce = randB64u(24)
	}
	cap := models.Capability{Name: in.Capability, Constraints: in.Constraints}
	req := models.HandshakeRequest{
		Version:          handshake.SpecVersion,
		Kind:             "HandshakeRequest",
		ID:               mustULID("hs"),
		Iss:              c.cfg.DID,
		Aud:              in.Aud,
		Iat:              iso(time.Now().UTC()),
		Nonce:            in.Nonce,
		AgentAttestation: in.AgentAttestation,
		Capability:       cap,
		DelegationChain:  append([]models.DelegationToken(nil), in.Chain...),
		Alg:              c.cfg.Signer.Algorithm(),
	}
	if err := c.signEnvelope(&req, &req.Signature); err != nil {
		return nil, err
	}
	return &HandshakeContext{
		Request:     req,
		HandshakeID: req.ID,
		Iss:         c.cfg.DID,
		Sub:         in.Aud,
		Capability:  cap,
	}, nil
}

// RecordInput parametrises RecordReceipt.
type RecordInput struct {
	Action           string
	Result           models.ReceiptResult
	ResultPayload    any
	ResultSummary    json.RawMessage
	UpstreamReceipts []string
}

// RecordOutcome bundles the fully-signed Receipt with the Registry's reply.
type RecordOutcome struct {
	ReceiptID string
	Receipt   models.Receipt
	LeafHash  string
}

// RecordReceipt signs and (unless Offline) POSTs a Receipt to the Registry.
func (c *Client) RecordReceipt(ctx context.Context, hsCtx *HandshakeContext, in RecordInput) (*RecordOutcome, error) {
	if hsCtx == nil {
		return nil, fmt.Errorf("handshake/client: nil HandshakeContext")
	}
	result := in.Result
	if result == "" {
		result = models.ReceiptOk
	}
	resultHash, err := hashPayload(in.ResultPayload)
	if err != nil {
		return nil, err
	}
	merged := append([]string(nil), hsCtx.ParentReceiptIDs...)
	for _, r := range in.UpstreamReceipts {
		if !contains(merged, r) {
			merged = append(merged, r)
		}
	}

	rec := models.Receipt{
		Version:          handshake.SpecVersion,
		Kind:             "Receipt",
		ID:               mustULID("rc"),
		HandshakeID:      hsCtx.HandshakeID,
		Iss:              c.cfg.DID,
		Sub:              hsCtx.Sub,
		Action:           in.Action,
		ExecutedAt:       iso(time.Now().UTC()),
		Result:           result,
		ResultHash:       resultHash,
		ResultSummary:    in.ResultSummary,
		UpstreamReceipts: merged,
		Alg:              c.cfg.Signer.Algorithm(),
	}
	if err := c.signEnvelope(&rec, &rec.Signature); err != nil {
		return nil, err
	}
	out := &RecordOutcome{ReceiptID: rec.ID, Receipt: rec}

	if c.cfg.Offline {
		return out, nil
	}

	body, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("handshake/client: marshal receipt: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/receipts", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("handshake/client: POST receipt: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("handshake/client: registry rejected receipt %s: HTTP %d %s", rec.ID, resp.StatusCode, string(respBody))
	}
	// Registry returns `{"receipt_id": "...", "leaf_hash": "..."}` on 202.
	// We *must* propagate the leaf_hash back to the caller — downstream
	// inclusion-proof verification keys off it. Silently swallowing an
	// unmarshal error here (the previous behaviour) meant a malformed or
	// schema-drifted Registry response would yield an empty LeafHash on
	// what looked like a successful record, breaking proofs much later
	// in a way that's painful to attribute. Match the Python SDK and
	// surface the parse failure as an error.
	var parsed struct {
		LeafHash string `json:"leaf_hash"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("handshake/client: registry accepted receipt %s but response was malformed: %w (body=%q)", rec.ID, err, string(respBody))
	}
	out.LeafHash = parsed.LeafHash
	return out, nil
}

// FetchReceipt round-trips a receipt by id from the Registry.
func (c *Client) FetchReceipt(ctx context.Context, receiptID string) (map[string]any, error) {
	if c.cfg.Offline {
		return nil, fmt.Errorf("handshake/client: FetchReceipt unavailable in offline mode")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/receipts/"+receiptID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("handshake/client: fetch %s: HTTP %d %s", receiptID, resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("handshake/client: decode receipt: %w", err)
	}
	return out, nil
}

// WaitForAnchor polls FetchReceipt until anchor.status == "anchored" or the
// deadline elapses.
func (c *Client) WaitForAnchor(ctx context.Context, receiptID string, maxWait, poll time.Duration) (map[string]any, error) {
	if maxWait == 0 {
		maxWait = 10 * time.Second
	}
	if poll == 0 {
		poll = 500 * time.Millisecond
	}
	deadline := time.Now().Add(maxWait)
	var last map[string]any
	for time.Now().Before(deadline) {
		rec, err := c.FetchReceipt(ctx, receiptID)
		if err != nil {
			return nil, err
		}
		last = rec
		if anchor, ok := rec["anchor"].(map[string]any); ok {
			if status, _ := anchor["status"].(string); status == "anchored" {
				return rec, nil
			}
		}
		select {
		case <-time.After(poll):
		case <-ctx.Done():
			return last, ctx.Err()
		}
	}
	return last, fmt.Errorf("handshake/client: receipt %s not anchored within %s", receiptID, maxWait)
}

// signEnvelope canonicalises the envelope (with signature stripped) and
// writes the base64url signature back into the supplied target field. The
// envelope/value type system in encoding/json means we serialise twice
// (once for canonicalisation, again on the wire) — fine for Phase 4 because
// the canonical form is the only output that matters for verification.
func (c *Client) signEnvelope(envelope any, sigField *string) error {
	*sigField = ""
	raw, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("handshake/client: marshal envelope: %w", err)
	}
	canon, err := jcs.CanonicalizeBytes(raw)
	if err != nil {
		return fmt.Errorf("handshake/client: canonicalize: %w", err)
	}
	sig, err := c.cfg.Signer.Sign(canon)
	if err != nil {
		return fmt.Errorf("handshake/client: sign: %w", err)
	}
	*sigField = base64.RawURLEncoding.EncodeToString(sig)
	return nil
}

// ---- helpers --------------------------------------------------------------

func iso(t time.Time) string { return t.Format("2006-01-02T15:04:05Z") }

func randB64u(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is fatal; surface as a pseudo-deterministic
		// value rather than panic to keep call sites simple.
		copy(buf, []byte("handshake-rand-fallback"))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func mustULID(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// hex fallback — never expected, but cheap to write.
		return prefix + "_" + hex.EncodeToString(raw[:])
	}
	var n big128
	for _, b := range raw {
		n = n.shl8().or64(uint64(b))
	}
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[n.lo&0x1f]
		n = n.shr5()
	}
	return prefix + "_" + string(out)
}

// big128 is a small fixed-width 128-bit integer used solely for ULID
// encoding. Avoids pulling in math/big for what is a 26-character base32
// digit pump.
type big128 struct{ hi, lo uint64 }

func (b big128) shl8() big128 {
	return big128{hi: (b.hi << 8) | (b.lo >> 56), lo: b.lo << 8}
}
func (b big128) or64(v uint64) big128 { return big128{hi: b.hi, lo: b.lo | v} }
func (b big128) shr5() big128 {
	return big128{hi: b.hi >> 5, lo: (b.lo >> 5) | (b.hi << 59)}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hashPayload(payload any) (models.HashValue, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	canon, err := jcs.Canonicalize(payload)
	if err != nil {
		return models.HashValue{}, fmt.Errorf("handshake/client: hash payload: %w", err)
	}
	sum := sha256.Sum256(canon)
	return models.HashValue{Alg: models.HashSHA256, Value: hex.EncodeToString(sum[:])}, nil
}
