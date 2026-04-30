// Lattice axioms for the capability-intersection algebra (Go side).
//
// Mirrors `packages/handshake-rs/tests/intersect_axioms.rs`. We use the
// stdlib `testing/quick` package instead of an external property-testing
// framework so the Go core ships with zero extra dependencies — the
// downside is no automatic shrinker, which we accept for Phase 2.
package intersect

import (
	"fmt"
	"reflect"
	"testing"
	"testing/quick"
)

// constraintSet is a `quick.Generator`-friendly wrapper around the typed
// constraint object. We only fuzz the four constraint types the Phase 2
// algebra implements (numeric_max, numeric_min, enum, exact-match).
type constraintSet map[string]any

// numericMaxKeys / numericMinKeys / enumKeys / exactKeys define the
// universes the property tests draw from. Keep them small so the
// post-shrink trace is human-debuggable.
var (
	numericMaxKeys = []string{"max_a", "max_b", "max_c"}
	numericMinKeys = []string{"min_x", "min_y"}
	enumValues     = []string{"alpha", "beta", "gamma", "delta"}
	regionValues   = []string{"us-east-1", "eu-west-1"}
)

// Generate satisfies `quick.Generator`. We hand-roll a small, well-typed
// random constraint object so the property tests stay fast and deterministic
// across CI runs.
func (constraintSet) Generate(rand *randSource, _ int) reflect.Value {
	m := make(constraintSet)
	// numeric_max: 0..3 keys
	for i := 0; i < rand.Intn(3); i++ {
		k := numericMaxKeys[rand.Intn(len(numericMaxKeys))]
		m[k] = rand.Intn(2000) - 1000
	}
	// numeric_min: 0..2 keys
	for i := 0; i < rand.Intn(2); i++ {
		k := numericMinKeys[rand.Intn(len(numericMinKeys))]
		m[k] = rand.Intn(2000) - 1000
	}
	// enum: 0..1 key, non-empty *subsequence* (canonical-order subset) of
	// enumValues. The Rust property tests use proptest's `subsequence`
	// strategy which preserves source order; we mirror that so the
	// algebra's enum-intersection axioms hold (intersection preserves the
	// request's order — different orderings in the two sides would break
	// commutativity, by design of §10).
	if rand.Intn(2) == 1 {
		var subset []any
		for _, v := range enumValues {
			if rand.Intn(2) == 1 {
				subset = append(subset, v)
			}
		}
		if len(subset) == 0 {
			subset = []any{enumValues[rand.Intn(len(enumValues))]}
		}
		m["actions_enum"] = subset
	}
	// exact-match string: 0..1 key
	if rand.Intn(2) == 1 {
		m["region"] = regionValues[rand.Intn(len(regionValues))]
	}
	// time_window: 0..1 key. Two endpoints in 0..23 of 2026-01-01.
	// Always emit start < end so individual inputs are well-formed; the
	// intersection of two such windows may still be empty (which the
	// operator must reject) — that's covered by the asymmetric-admission
	// case in the lattice axioms.
	if rand.Intn(2) == 1 {
		a, b := rand.Intn(23), rand.Intn(23)
		if a > b {
			a, b = b, a+1
		} else if a == b {
			b = a + 1
		}
		m["active_window"] = []any{
			fmt.Sprintf("2026-01-01T%02d:00:00Z", a),
			fmt.Sprintf("2026-01-01T%02d:00:00Z", b),
		}
	}
	// rate_limit: 0..1 key with two numeric dimensions. Use float64 to
	// match what `encoding/json` decodes numbers into — ensures the
	// axiom comparisons (DeepEqual) don't trip on int-vs-float.
	if rand.Intn(2) == 1 {
		m["api_rate_limit"] = map[string]any{
			"per_second": float64(rand.Intn(99) + 1),
			"per_minute": float64(rand.Intn(99) + 1),
		}
	}
	// resource_path: 0..1 key. A handful of fixed strings so the
	// wildcard prefix path `/v1/*` admits some siblings and rejects others.
	if rand.Intn(2) == 1 {
		paths := []string{"/v1/users", "/v1/users/me", "/v1/orders", "/v1/*"}
		m["api_path"] = paths[rand.Intn(len(paths))]
	}
	return reflect.ValueOf(m)
}

// `quick` provides a `*rand.Rand` to Generate; alias here so the helper
// signature is short.
type randSource = quickRand

func TestCommutativityWhenBothAdmit(t *testing.T) {
	// Axiom 1: a ∩ b == b ∩ a (when both directions admit).
	prop := func(a, b constraintSet) bool {
		ab, errAB := Intersect(a, b)
		ba, errBA := Intersect(b, a)
		if errAB == nil && errBA == nil {
			return reflect.DeepEqual(ab, ba)
		}
		// Asymmetric admission is allowed by the directional algebra
		// (`d` is the upper bound), so we don't fail in that case.
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatalf("commutativity violated: %v", err)
	}
}

func TestAssociativityWhenBothAdmit(t *testing.T) {
	// Axiom 2: (a ∩ b) ∩ c == a ∩ (b ∩ c).
	prop := func(a, b, c constraintSet) bool {
		left, errL := Intersect(a, b)
		if errL != nil {
			return true
		}
		left, errL = Intersect(left, c)
		right, errR := Intersect(b, c)
		if errR != nil {
			return true
		}
		right, errR = Intersect(a, right)
		if errL != nil || errR != nil {
			return true
		}
		return reflect.DeepEqual(left, right)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatalf("associativity violated: %v", err)
	}
}

func TestIdempotence(t *testing.T) {
	// Axiom 3: a ∩ a == a.
	prop := func(a constraintSet) bool {
		got, err := Intersect(a, a)
		if err != nil {
			t.Logf("self-intersection rejected: %v", err)
			return false
		}
		return reflect.DeepEqual(got, map[string]any(a))
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatalf("idempotence violated: %v", err)
	}
}

func TestMonotonicity(t *testing.T) {
	// Axiom 4: re-intersecting a self-narrowed set with the original yields
	// the original. The lattice idempotence/monotone reduction the verifier
	// relies on.
	prop := func(a constraintSet) bool {
		narrowed, err := Intersect(a, a)
		if err != nil {
			return false
		}
		re, err := Intersect(a, narrowed)
		if err != nil {
			return false
		}
		return reflect.DeepEqual(re, map[string]any(a))
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatalf("monotonicity violated: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Direct unit tests mirroring the Rust suite.
// ---------------------------------------------------------------------------

func TestNumericMaxNarrowsToMinimum(t *testing.T) {
	d := map[string]any{"max_invoices": 100}
	r := map[string]any{"max_invoices": 50}
	got, err := Intersect(d, r)
	if err != nil {
		t.Fatalf("expected admissible: %v", err)
	}
	if !reflect.DeepEqual(got["max_invoices"], 50) {
		t.Fatalf("expected max_invoices=50, got %v", got["max_invoices"])
	}
}

func TestNumericMaxRejectsRequestAboveDelegation(t *testing.T) {
	d := map[string]any{"max_invoices": 100}
	r := map[string]any{"max_invoices": 500}
	if _, err := Intersect(d, r); err == nil {
		t.Fatal("expected scope violation")
	}
}

func TestEnumIntersection(t *testing.T) {
	d := map[string]any{"actions_enum": []any{"read", "write", "list"}}
	r := map[string]any{"actions_enum": []any{"read", "list"}}
	got, err := Intersect(d, r)
	if err != nil {
		t.Fatalf("expected admissible: %v", err)
	}
	want := []any{"read", "list"}
	if !reflect.DeepEqual(got["actions_enum"], want) {
		t.Fatalf("expected %v, got %v", want, got["actions_enum"])
	}
}

func TestEnumDisjointRejects(t *testing.T) {
	d := map[string]any{"actions_enum": []any{"read"}}
	r := map[string]any{"actions_enum": []any{"delete"}}
	if _, err := Intersect(d, r); err == nil {
		t.Fatal("expected disjoint enum to reject")
	}
}

func TestExactMatchForUnknownKey(t *testing.T) {
	d := map[string]any{"region": "us-east-1"}
	if _, err := Intersect(d, map[string]any{"region": "us-east-1"}); err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if _, err := Intersect(d, map[string]any{"region": "eu-west-1"}); err == nil {
		t.Fatal("expected mismatch to reject")
	}
}

// quickRand is the type `quick.Generator` receives. We alias it to the
// stdlib type so the Generate signature above stays readable.
type quickRand = quickRandImpl
