// SPDX-License-Identifier: MIT
// Package intersect — `quick.Generator` plumbing.
//
// `testing/quick` hands generators a `*rand.Rand` from `math/rand`, which
// does not satisfy `cryptorand.Reader` and is exactly the right tool for
// reproducible property testing. We re-export it under a short alias so
// the test file stays readable.
package intersect

import "math/rand"

// quickRandImpl is the concrete random source `quick.Generator.Generate`
// receives. The stdlib's `testing/quick.Config` seeds a fresh `*rand.Rand`
// per call so the property tests are deterministic across runs.
type quickRandImpl = rand.Rand
