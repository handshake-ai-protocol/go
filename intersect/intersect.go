// Package intersect implements the capability-constraint algebra spec §10
// calls out as the security-critical core of the verifier. The
// implementation mirrors `packages/handshake-rs/src/intersect.rs` byte-for-
// byte: the same key-prefix typing rules, the same per-type meet operator,
// and the same human-readable rejection messages so the conformance
// harness can substring-match `detail_must_include` across languages.
//
// The algebra forms a join-semilattice: commutative, associative,
// idempotent, monotone under narrowing. See `intersect_test.go` for the
// stdlib `testing/quick`-driven property tests.
package intersect

import (
	"fmt"
	"sort"
)

// ConstraintType categorizes a constraint key into one of the typed
// algebra slots. The typing rule is a documented per-key prefix
// convention (mirroring the Rust core) so JSON authors don't need to
// wrap every value in a typed envelope.
type ConstraintType int

const (
	// NumericMax: upper bound. Intersection = min(d, r); reject if r > d.
	NumericMax ConstraintType = iota
	// NumericMin: lower bound. Intersection = max(d, r); reject if r < d.
	NumericMin
	// StringPattern: regex-shaped. Intersection valid iff equal.
	StringPattern
	// Enum: set membership. Intersection = set-intersection; empty rejects.
	Enum
	// TimeWindow / RateLimit: Phase 2 ships exact-equality only. Full algebra
	// arrives in Phase 2.1.
	TimeWindow
	RateLimit
	// ResourcePath: glob string. Phase 2 ships exact match; full glob
	// containment is Phase 2.1.
	ResourcePath
	// ExactMatch: unrecognized key — require byte-equal values.
	ExactMatch
)

// InferType infers the constraint type from the JSON key + value shape.
// Mirror of `ConstraintType::infer` in handshake-rs.
func InferType(key string, value any) ConstraintType {
	if isNumber(value) {
		if hasPrefix(key, "max_") || key == "max" {
			return NumericMax
		}
		if hasPrefix(key, "min_") || key == "min" {
			return NumericMin
		}
	}
	if hasSuffix(key, "_pattern") {
		return StringPattern
	}
	if key == "enum" || hasSuffix(key, "_enum") {
		return Enum
	}
	if key == "time_window" || hasSuffix(key, "_window") {
		return TimeWindow
	}
	if key == "rate_limit" || hasSuffix(key, "_rate") {
		return RateLimit
	}
	if key == "resource_path" || hasSuffix(key, "_path") {
		return ResourcePath
	}
	return ExactMatch
}

// ScopeViolation is the structured failure mode of `Intersect`. The
// `Reason` string is byte-stable across Rust + Go so cross-language
// `detail_must_include` substring assertions in the conformance vectors
// hold.
type ScopeViolation struct {
	Key    string
	Reason string
}

func (e *ScopeViolation) Error() string { return e.Reason }

// Intersect returns the narrowed constraint set when admissible, or a
// `*ScopeViolation` describing the first failure encountered. The traversal
// order matches the Rust core (sorted, deduped union of both keysets) so
// error messages on first-failure are deterministic.
func Intersect(d, r map[string]any) (map[string]any, error) {
	// Walk every key on both sides in deterministic order. A constraint
	// present only on `d` carries through (request didn't narrow it). A
	// constraint present only on `r` is admissible (request narrowed
	// further on a dimension the delegation didn't bound).
	allKeys := make(map[string]struct{}, len(d)+len(r))
	for k := range d {
		allKeys[k] = struct{}{}
	}
	for k := range r {
		allKeys[k] = struct{}{}
	}
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]any, len(keys))
	for _, key := range keys {
		dv, dOk := d[key]
		rv, rOk := r[key]
		switch {
		case dOk && !rOk:
			out[key] = dv
		case !dOk && rOk:
			out[key] = rv
		case dOk && rOk:
			ty := InferType(key, dv)
			narrowed, err := intersectOne(key, ty, dv, rv)
			if err != nil {
				return nil, err
			}
			out[key] = narrowed
		}
	}
	return out, nil
}

func intersectOne(key string, ty ConstraintType, d, r any) (any, error) {
	switch ty {
	case NumericMax:
		dn, rn, err := bothNumbers(key, d, r)
		if err != nil {
			return nil, err
		}
		if rn > dn {
			return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("requested %s=%s exceeds delegated max %s", key, fmtNum(rn), fmtNum(dn))}
		}
		// Pick the narrower side and return its original value to preserve
		// integer typing (otherwise JSON re-encoding would float-promote).
		if rn <= dn {
			return r, nil
		}
		return d, nil
	case NumericMin:
		dn, rn, err := bothNumbers(key, d, r)
		if err != nil {
			return nil, err
		}
		if rn < dn {
			return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("requested %s=%s below delegated min %s", key, fmtNum(rn), fmtNum(dn))}
		}
		if rn >= dn {
			return r, nil
		}
		return d, nil
	case Enum:
		da, ok := d.([]any)
		if !ok {
			return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("constraint %s declared as enum but delegated value is not an array", key)}
		}
		ra, ok := r.([]any)
		if !ok {
			return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("constraint %s declared as enum but requested value is not an array", key)}
		}
		// Set intersection preserving the request's order — mirrors Rust.
		narrowed := make([]any, 0, len(ra))
		for _, rv := range ra {
			for _, dv := range da {
				if jsonEqual(rv, dv) {
					narrowed = append(narrowed, rv)
					break
				}
			}
		}
		if len(narrowed) == 0 {
			return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("requested enum %s disjoint from delegated set", key)}
		}
		return narrowed, nil
	case TimeWindow, RateLimit:
		// Phase 2 ships exact-equality semantics; full algebra in Phase 2.1.
		if jsonEqual(d, r) {
			return d, nil
		}
		return nil, &ScopeViolation{
			Key:    key,
			Reason: fmt.Sprintf("constraint %s differs between delegation and request (full %s algebra is Phase 2.1; exact match required for now)", key, typeName(ty)),
		}
	case StringPattern, ResourcePath, ExactMatch:
		if jsonEqual(d, r) {
			return d, nil
		}
		return nil, &ScopeViolation{
			Key:    key,
			Reason: fmt.Sprintf("constraint %s requires exact match between delegation and request", key),
		}
	default:
		return nil, &ScopeViolation{Key: key, Reason: fmt.Sprintf("unknown constraint type for key %s", key)}
	}
}

func bothNumbers(key string, d, r any) (float64, float64, error) {
	dn, ok := toNumber(d)
	if !ok {
		return 0, 0, &ScopeViolation{Key: key, Reason: fmt.Sprintf("delegated %s is not a number", key)}
	}
	rn, ok := toNumber(r)
	if !ok {
		return 0, 0, &ScopeViolation{Key: key, Reason: fmt.Sprintf("requested %s is not a number", key)}
	}
	return dn, rn, nil
}

func isNumber(v any) bool {
	_, ok := toNumber(v)
	return ok
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

func fmtNum(n float64) string {
	// Go's default %v on a float64 that's actually an integer prints
	// "100" — matches serde_json's integer rendering on the Rust side
	// for the purpose of the `detail_must_include` substring match.
	if n == float64(int64(n)) {
		return fmt.Sprintf("%d", int64(n))
	}
	return fmt.Sprintf("%g", n)
}

func jsonEqual(a, b any) bool {
	// JSON-decoded values can be deeply nested — `reflect.DeepEqual` is
	// what `encoding/json` callers conventionally reach for and is what
	// the rest of this package uses for byte-level equivalence checks.
	return deepEqual(a, b)
}

func deepEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, val := range av {
			bval, ok := bv[k]
			if !ok || !deepEqual(val, bval) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		// Numbers may compare unequal under == because of int vs float64
		// surfacing through the same JSON unmarshal. Normalize via toNumber.
		if an, aok := toNumber(a); aok {
			if bn, bok := toNumber(b); bok {
				return an == bn
			}
		}
		return a == b
	}
}

func typeName(t ConstraintType) string {
	switch t {
	case NumericMax:
		return "NumericMax"
	case NumericMin:
		return "NumericMin"
	case StringPattern:
		return "StringPattern"
	case Enum:
		return "Enum"
	case TimeWindow:
		return "TimeWindow"
	case RateLimit:
		return "RateLimit"
	case ResourcePath:
		return "ResourcePath"
	case ExactMatch:
		return "ExactMatch"
	default:
		return "Unknown"
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
func hasSuffix(s, p string) bool {
	return len(s) >= len(p) && s[len(s)-len(p):] == p
}
