// SPDX-License-Identifier: MIT
// Package middleware provides Phase 4 server-side adapters that verify
// inbound Handshake artefacts and emit Receipts as side effects.
//
// HTTP wire convention (mirrors the Python FastAPI middleware):
//
//      Handshake-Request: <base64url(canonical-json HandshakeRequest)>
//
// On every request the middleware:
//  1. Reads + base64url-decodes + JSON-parses the header.
//  2. Runs the full Phase 2 chain-walk verifier (verify.VerifyHandshakeRequest)
//     under the supplied KeyResolver, NonceStore, and ReceiverDID.
//  3. Rejects with HTTP 400 (malformed) or 401 (verification failed) before
//     the wrapped handler runs.
//
// After a successful response, a Receipt is recorded best-effort — emit
// errors are surfaced via OnReceiptError but never propagated to the client.
//
// SECURITY: cfg.Keys must be non-nil. A nil resolver is treated as a server
// misconfiguration and every request is rejected with HTTP 500. This is
// fail-closed by design — the previous decode-only behaviour was an auth
// bypass.
package middleware

import (
        "context"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net/http"
        "time"

        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/client"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/models"
        "github.com/handshake-protocol/handshake-ai/packages/handshake-go/verify"
)

// HandshakeHeader is the wire-format HTTP header name.
const HandshakeHeader = "Handshake-Request"

type ctxKey struct{}

// Config configures HTTP.
type Config struct {
        // Client signs Receipts emitted on the response side.
        Client *client.Client
        // Keys resolves issuer DID strings to raw 32-byte Ed25519 public keys.
        // REQUIRED. If nil, every request is rejected with HTTP 500.
        Keys map[string][]byte
        // ReceiverDID is the DID of THIS service. The verifier rejects envelopes
        // whose `aud` does not match. Defaults to Client.DID() when empty.
        ReceiverDID string
        // SkewSecs is the freshness-window tolerance in seconds. Defaults to 60.
        SkewSecs int
        // Now returns the verifier's wall clock. Defaults to time.Now.
        Now func() time.Time
        // Nonces stores observed nonces for replay defence.
        //
        // SECURITY: this field must be set explicitly in multi-instance
        // deployments (multiple pods, workers, or processes behind a load
        // balancer). An in-memory store is only safe when the service runs
        // as a single process; otherwise a valid signed request can be
        // replayed against a different instance within the freshness window.
        //
        // To opt into the built-in process-local store (acceptable for
        // single-instance services or development) set AllowInMemoryNonces
        // to true and leave Nonces nil. Leaving both unset is treated as a
        // server misconfiguration and every request is rejected with HTTP 500.
        Nonces verify.NonceStore
        // AllowInMemoryNonces opts into a process-local in-memory nonce store
        // when Nonces is nil. This is NOT safe for multi-instance deployments
        // (each instance has an independent store so cross-pod replay is
        // undetectable). Set to true only for single-instance services or
        // local development; always supply an explicit Nonces backend in
        // production multi-instance environments.
        AllowInMemoryNonces bool
        // Revocations resolves principal + delegation revocations. Defaults to
        // an empty static resolver.
        Revocations verify.RevocationResolver
        // ResolveAction returns the Receipt action string for a request.
        // Default: "<METHOD> <URL.Path>".
        ResolveAction func(*http.Request) string
        // EmitReceipt toggles the post-response Receipt emission. Default: true
        // when Client is non-nil.
        EmitReceipt bool
        // OnReceiptError, if non-nil, is invoked when post-response receipt
        // emission fails. The default is to silently swallow the error.
        OnReceiptError func(error)
}

// HTTP wraps an http.Handler so every request is gated by a verifiable
// HandshakeRequest header and produces a Receipt on the way out.
func HTTP(cfg Config) func(http.Handler) http.Handler {
        if cfg.ResolveAction == nil {
                cfg.ResolveAction = func(r *http.Request) string {
                        return r.Method + " " + r.URL.Path
                }
        }
        if cfg.SkewSecs == 0 {
                cfg.SkewSecs = 60
        }
        if cfg.Now == nil {
                cfg.Now = time.Now
        }
        // Fail-closed on nonce store misconfiguration: require callers to be
        // explicit about their replay-protection strategy.
        if cfg.Nonces == nil && !cfg.AllowInMemoryNonces {
                // Nonce store is required. Return a middleware that always
                // rejects with 500 so the misconfiguration is caught at
                // start-up in integration tests rather than silently skipping
                // replay protection in production.
                return func(next http.Handler) http.Handler {
                        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                                writeJSONError(w, http.StatusInternalServerError,
                                        "handshake middleware misconfigured: Nonces store is required; "+
                                                "supply a distributed NonceStore or set AllowInMemoryNonces: true "+
                                                "to opt into process-local replay protection (not safe for multi-instance deployments)")
                        })
                }
        }
        if cfg.Nonces == nil {
                cfg.Nonces = verify.NewInMemoryNonceStore(120)
        }
        if cfg.Revocations == nil {
                cfg.Revocations = &verify.StaticRevocationResolver{}
        }
        if cfg.ReceiverDID == "" && cfg.Client != nil {
                cfg.ReceiverDID = cfg.Client.DID()
        }
        emitReceipt := cfg.EmitReceipt
        if !emitReceipt && cfg.Client != nil {
                emitReceipt = true
        }
        keyResolver := newStaticKeyResolver(cfg.Keys)

        return func(next http.Handler) http.Handler {
                return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                        // Fail-closed: a nil key resolver is a server misconfiguration.
                        if cfg.Keys == nil {
                                writeJSONError(w, http.StatusInternalServerError, "handshake middleware misconfigured: Keys resolver is required")
                                return
                        }
                        if cfg.ReceiverDID == "" {
                                writeJSONError(w, http.StatusInternalServerError, "handshake middleware misconfigured: ReceiverDID is required")
                                return
                        }
                        headerValue := r.Header.Get(HandshakeHeader)
                        if headerValue == "" {
                                writeJSONError(w, http.StatusBadRequest, "missing Handshake-Request header")
                                return
                        }
                        req, err := decodeRequest(headerValue)
                        if err != nil {
                                writeJSONError(w, http.StatusBadRequest, "invalid Handshake-Request: "+err.Error())
                                return
                        }

                        vctx := &verify.Context{
                                ReceiverDID: cfg.ReceiverDID,
                                Now:         cfg.Now(),
                                SkewSecs:    cfg.SkewSecs,
                                Keys:        keyResolver,
                                Nonces:      cfg.Nonces,
                                Revocations: cfg.Revocations,
                        }
                        result := verify.VerifyHandshakeRequest(req, vctx)
                        if !result.Accepted() {
                                writeVerifyRefusal(w, result.Refusal)
                                return
                        }

                        r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, req))

                        rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
                        next.ServeHTTP(rw, r)

                        if !emitReceipt || cfg.Client == nil {
                                return
                        }
                        // Best-effort post-response receipt. Failures are reported via
                        // OnReceiptError but never affect the response.
                        go func() {
                                ctx := context.Background()
                                hsCtx, hsErr := cfg.Client.Handshake(client.HandshakeInput{
                                        Aud:        req.Iss,
                                        Capability: req.Capability.Name,
                                })
                                if hsErr != nil {
                                        reportErr(cfg.OnReceiptError, hsErr)
                                        return
                                }
                                resultCode := models.ReceiptOk
                                if rw.status >= 400 {
                                        resultCode = models.ReceiptError
                                }
                                summary, _ := json.Marshal(map[string]any{
                                        "transport": "http",
                                        "status":    rw.status,
                                })
                                if _, err := cfg.Client.RecordReceipt(ctx, hsCtx, client.RecordInput{
                                        Action:        cfg.ResolveAction(r),
                                        Result:        resultCode,
                                        ResultPayload: map[string]any{"status": rw.status, "path": r.URL.Path},
                                        ResultSummary: summary,
                                }); err != nil {
                                        reportErr(cfg.OnReceiptError, err)
                                }
                        }()
                })
        }
}

// FromContext returns the verified inbound HandshakeRequest, if any.
func FromContext(ctx context.Context) (*models.HandshakeRequest, bool) {
        v, ok := ctx.Value(ctxKey{}).(*models.HandshakeRequest)
        return v, ok
}

func decodeRequest(headerValue string) (*models.HandshakeRequest, error) {
        raw, err := base64.RawURLEncoding.DecodeString(headerValue)
        if err != nil {
                return nil, err
        }
        var req models.HandshakeRequest
        if err := json.Unmarshal(raw, &req); err != nil {
                return nil, err
        }
        return &req, nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
        w.Header().Set("content-type", "application/json")
        w.WriteHeader(status)
        _ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeVerifyRefusal(w http.ResponseWriter, refusal *verify.Refusal) {
        w.Header().Set("content-type", "application/json")
        w.WriteHeader(http.StatusUnauthorized)
        body := map[string]any{
                "error":            "handshake_rejected",
                "error_code":       string(refusal.ErrorCode),
                "rejected_at_step": string(refusal.RejectedAtStep),
                "detail":           refusal.Detail,
        }
        if refusal.RejectedDelegationID != "" {
                body["rejected_delegation_id"] = refusal.RejectedDelegationID
        }
        _ = json.NewEncoder(w).Encode(body)
}

func reportErr(handler func(error), err error) {
        if handler != nil {
                handler(err)
        }
}

// statusRecorder captures the response status so the post-response Receipt
// can include it.
type statusRecorder struct {
        http.ResponseWriter
        status int
}

func (r *statusRecorder) WriteHeader(code int) {
        r.status = code
        r.ResponseWriter.WriteHeader(code)
}

// staticKeyResolver adapts a map[string][]byte into verify.KeyResolver. We
// keep it private so callers always go through Config.Keys.
type staticKeyResolver struct {
        m map[string][]byte
}

func newStaticKeyResolver(m map[string][]byte) *staticKeyResolver {
        return &staticKeyResolver{m: m}
}

func (r *staticKeyResolver) Resolve(did string) ([]byte, bool) {
        if r == nil || r.m == nil {
                return nil, false
        }
        v, ok := r.m[did]
        return v, ok
}

// Compile-time assertion that staticKeyResolver implements verify.KeyResolver.
var _ verify.KeyResolver = (*staticKeyResolver)(nil)

// Sentinel kept so removing the helper from the public API is a deliberate
// breaking change rather than an accidental drop.
var _ = fmt.Sprintf
