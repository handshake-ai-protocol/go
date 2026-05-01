package middleware_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/client"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/middleware"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/signing"
	"github.com/handshake-protocol/handshake-ai/packages/handshake-go/verify"
)

func newOfflineClient(t *testing.T) *client.Client {
	t.Helper()
	kp, err := signing.GenerateEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	c, err := client.New(client.Config{
		RegistryURL: "http://example.invalid",
		DID:         "did:hsk:test.go.middleware",
		Signer:      client.NewSoftwareSigner(kp.Private),
		Offline:     true,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// keysFor exposes the client's signing public key under its DID so the
// middleware verifier can resolve it. Production callers would resolve via
// the Registry's /.well-known/handshake/did.json endpoint instead.
func keysFor(c *client.Client) map[string][]byte {
	return map[string][]byte{c.DID(): c.Signer().PublicKey()}
}

func TestHTTP_RejectsMissingHeader(t *testing.T) {
	c := newOfflineClient(t)
	h := middleware.HTTP(middleware.Config{
		Client:             c,
		Keys:               keysFor(c),
		ReceiverDID:        "did:hsk:server",
		AllowInMemoryNonces: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestHTTP_VerifiesAndExposesContext(t *testing.T) {
	c := newOfflineClient(t)
	tok, _ := c.Delegate(client.DelegateInput{Sub: c.DID(), Aud: "did:hsk:server", Capability: "http.test"})
	hsCtx, _ := c.Handshake(client.HandshakeInput{
		Aud:        "did:hsk:server",
		Capability: "http.test",
		Chain:      []models.DelegationToken{*tok},
	})
	body, err := json.Marshal(hsCtx.Request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString(body)

	var seen *models.HandshakeRequest
	h := middleware.HTTP(middleware.Config{
		Client:             c,
		Keys:               keysFor(c),
		ReceiverDID:        "did:hsk:server",
		EmitReceipt:        false,
		AllowInMemoryNonces: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, ok := middleware.FromContext(r.Context())
		if ok {
			seen = req
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(middleware.HandshakeHeader, header)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if seen == nil {
		t.Fatalf("FromContext returned nothing")
	}
	if seen.Capability.Name != "http.test" {
		t.Fatalf("capability mismatch: %s", seen.Capability.Name)
	}
}

// TestHTTP_EmitsReceipt verifies the post-response Receipt is sent to the
// configured Registry. The Registry stand-in records the POST body and
// signals via a channel so the test can assert without sleeping.
func TestHTTP_EmitsReceipt(t *testing.T) {
	var (
		mu        sync.Mutex
		receipts  []map[string]any
		receivedC = make(chan struct{}, 1)
	)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		mu.Lock()
		receipts = append(receipts, parsed)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"leaf_hash":"x"}`))
		select {
		case receivedC <- struct{}{}:
		default:
		}
	}))
	defer registry.Close()

	kp, _ := signing.GenerateEd25519()
	c, _ := client.New(client.Config{
		RegistryURL: registry.URL,
		DID:         "did:hsk:test.go.mw.live",
		Signer:      client.NewSoftwareSigner(kp.Private),
	})

	tok, _ := c.Delegate(client.DelegateInput{Sub: c.DID(), Aud: c.DID(), Capability: "http.test"})
	hsCtx, _ := c.Handshake(client.HandshakeInput{
		Aud:        c.DID(),
		Capability: "http.test",
		Chain:      []models.DelegationToken{*tok},
	})
	body, _ := json.Marshal(hsCtx.Request)
	header := base64.RawURLEncoding.EncodeToString(body)

	h := middleware.HTTP(middleware.Config{
		Client:             c,
		Keys:               keysFor(c),
		ReceiverDID:        c.DID(),
		EmitReceipt:        true,
		AllowInMemoryNonces: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set(middleware.HandshakeHeader, header)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler status: %d", rr.Code)
	}

	select {
	case <-receivedC:
	case <-time.After(3 * time.Second):
		t.Fatalf("registry never saw the post-response receipt")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receipts) != 1 {
		t.Fatalf("want 1 receipt, got %d", len(receipts))
	}
	r := receipts[0]
	if r["kind"] != "Receipt" {
		t.Fatalf("envelope kind=%v", r["kind"])
	}
	if r["action"] != "GET /check" {
		t.Fatalf("action=%v", r["action"])
	}
	if r["result"] != "ok" {
		t.Fatalf("result=%v", r["result"])
	}
}

// TestHTTP_RejectsForgedSignature proves the middleware actually verifies the
// outer signature: we tamper with one byte of the signed envelope and expect
// HTTP 401 with a structured error_code, not a 200.
func TestHTTP_RejectsForgedSignature(t *testing.T) {
	c := newOfflineClient(t)
	tok, err := c.Delegate(client.DelegateInput{
		Sub: c.DID(), Aud: "did:hsk:server", Capability: "http.test",
	})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	hsCtx, err := c.Handshake(client.HandshakeInput{
		Aud:        "did:hsk:server",
		Capability: "http.test",
		Chain:      []models.DelegationToken{*tok},
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// Tamper: flip the capability name AFTER signing. Verifier must reject.
	hsCtx.Request.Capability.Name = "http.test.tampered"
	body, _ := json.Marshal(hsCtx.Request)
	header := base64.RawURLEncoding.EncodeToString(body)

	var handlerRan bool
	h := middleware.HTTP(middleware.Config{
		Client:             c,
		Keys:               keysFor(c),
		ReceiverDID:        "did:hsk:server",
		EmitReceipt:        false,
		AllowInMemoryNonces: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(middleware.HandshakeHeader, header)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if handlerRan {
		t.Fatalf("handler ran despite forged signature")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v body=%s", err, rr.Body.String())
	}
	if resp["error"] != "handshake_rejected" {
		t.Fatalf("error=%v want handshake_rejected", resp["error"])
	}
	if resp["error_code"] == nil || resp["rejected_at_step"] == nil {
		t.Fatalf("missing structured fields: %v", resp)
	}
}

// TestHTTP_ConcurrentVerifyRaceFree fires N parallel requests through the
// middleware sharing a single in-memory NonceStore. Run under `go test -race`
// to catch a `concurrent map writes` panic — historic regression that the
// architect-review surfaced.
func TestHTTP_ConcurrentVerifyRaceFree(t *testing.T) {
	c := newOfflineClient(t)
	h := middleware.HTTP(middleware.Config{
		Client:             c,
		Keys:               keysFor(c),
		ReceiverDID:        "did:hsk:server",
		EmitReceipt:        false,
		AllowInMemoryNonces: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const N = 32
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			// Each goroutine builds its own envelope so nonces don't collide.
			tok, err := c.Delegate(client.DelegateInput{
				Sub: c.DID(), Aud: "did:hsk:server", Capability: "http.race",
			})
			if err != nil {
				t.Errorf("delegate: %v", err)
				return
			}
			hsCtx, err := c.Handshake(client.HandshakeInput{
				Aud:        "did:hsk:server",
				Capability: "http.race",
				Chain:      []models.DelegationToken{*tok},
			})
			if err != nil {
				t.Errorf("handshake: %v", err)
				return
			}
			body, _ := json.Marshal(hsCtx.Request)
			header := base64.RawURLEncoding.EncodeToString(body)

			req := httptest.NewRequest(http.MethodGet, "/race", nil)
			req.Header.Set(middleware.HandshakeHeader, header)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("want 200, got %d body=%s", rr.Code, rr.Body.String())
			}
		}()
	}
	wg.Wait()
}

// TestHTTP_RejectsMissingKeys proves we fail-closed when the resolver is nil.
// AllowInMemoryNonces is set so the test reaches the Keys check.
func TestHTTP_RejectsMissingKeys(t *testing.T) {
	c := newOfflineClient(t)
	h := middleware.HTTP(middleware.Config{
		Client:             c,
		ReceiverDID:        c.DID(),
		AllowInMemoryNonces: true,
		// Keys deliberately omitted — must fail-closed.
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run when Keys is nil")
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(middleware.HandshakeHeader, "abc")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 (misconfigured), got %d", rr.Code)
	}
}

// TestHTTP_RejectsMissingNonceStore proves that omitting both Nonces and
// AllowInMemoryNonces is a fail-closed misconfiguration (HTTP 500 on every
// request) rather than silently falling back to a process-local store.
func TestHTTP_RejectsMissingNonceStore(t *testing.T) {
	c := newOfflineClient(t)
	h := middleware.HTTP(middleware.Config{
		Client:      c,
		Keys:        keysFor(c),
		ReceiverDID: c.DID(),
		// Nonces and AllowInMemoryNonces deliberately omitted.
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run when Nonces is not configured")
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 (misconfigured), got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestHTTP_ExplicitNonceStore shows that a caller-supplied NonceStore is used.
func TestHTTP_ExplicitNonceStore(t *testing.T) {
	c := newOfflineClient(t)
	h := middleware.HTTP(middleware.Config{
		Client:      c,
		Keys:        keysFor(c),
		ReceiverDID: "did:hsk:server",
		EmitReceipt: false,
		Nonces:      verify.NewInMemoryNonceStore(120),
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok, _ := c.Delegate(client.DelegateInput{Sub: c.DID(), Aud: "did:hsk:server", Capability: "http.test"})
	hsCtx, _ := c.Handshake(client.HandshakeInput{
		Aud:        "did:hsk:server",
		Capability: "http.test",
		Chain:      []models.DelegationToken{*tok},
	})
	body, _ := json.Marshal(hsCtx.Request)
	header := base64.RawURLEncoding.EncodeToString(body)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(middleware.HandshakeHeader, header)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// Silence unused-import warnings if any helpers are removed in future edits.
var _ = context.Background
