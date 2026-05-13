package profile_test

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/profile"
)

// secondBundle is goldenBundle with a strictly-greater bundle_version and
// the kotakneo broker disabled. A test that flips between the two and reads
// concurrently must never see a torn / partial result.
var secondBundle = func() string {
	s := goldenBundle
	s = strings.Replace(s, "bundle_version: 2026-05-13-001", "bundle_version: 2026-05-13-002", 1)
	s = strings.Replace(s,
		"    host: gw-napi.kotaksecurities.com\n    enabled: true",
		"    host: gw-napi.kotaksecurities.com\n    enabled: false", 1)
	return s
}()

func loadRouter(t *testing.T, yaml string) *profile.Router {
	t.Helper()
	env := newTestEnv(t, yaml)
	res, err := profile.LoadAndVerify(env.opts())
	if err != nil {
		t.Fatalf("LoadAndVerify: %v", err)
	}
	return res.Router
}

func TestHolder_LoadNilUntilStore(t *testing.T) {
	t.Parallel()
	h := profile.NewHolder(nil)
	if got := h.Load(); got != nil {
		t.Errorf("Load on empty holder = %v, want nil", got)
	}
}

func TestHolder_StoreReturnsPrevious(t *testing.T) {
	t.Parallel()
	r1 := loadRouter(t, goldenBundle)
	r2 := loadRouter(t, secondBundle)
	h := profile.NewHolder(r1)
	if got := h.Store(r2); got != r1 {
		t.Errorf("Store did not return previous router")
	}
	if got := h.Load(); got != r2 {
		t.Errorf("Load after Store did not return new router")
	}
}

// TestHolder_ConcurrentSwap exercises the arch §13.5 invariant: while
// readers are looking up routes, a Store of a new Router must not produce
// torn results. Every Lookup must either see the old router consistently or
// the new one consistently — never a mix.
func TestHolder_ConcurrentSwap(t *testing.T) {
	t.Parallel()
	rOld := loadRouter(t, goldenBundle)   // kotakneo enabled
	rNew := loadRouter(t, secondBundle)   // kotakneo disabled, bundle_version bumped
	h := profile.NewHolder(rOld)

	const readers = 16
	const lookupsPerReader = 4000

	var wg sync.WaitGroup
	var torn atomic.Int64    // a Lookup result that doesn't match the loaded router's expected output
	var swapped atomic.Int64 // count of swaps observed

	// Reader goroutines: each does many lookups, each lookup against a
	// freshly Loaded pointer. The invariant is that *the router we loaded*
	// is the one we got the answer from — internal consistency.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < lookupsPerReader; j++ {
				r := h.Load()
				m := r.Lookup("kotakneo", "POST", "/Orders/2.0/quick/order/cancel")
				// Old router: kotakneo enabled -> match present.
				// New router: kotakneo disabled -> nil.
				// Determine which router we sampled by its BundleVersion.
				switch r.BundleVersion() {
				case "2026-05-13-001":
					if m == nil {
						torn.Add(1)
					}
				case "2026-05-13-002":
					if m != nil {
						torn.Add(1)
					}
				default:
					torn.Add(1)
				}
			}
		}()
	}

	// One swapper goroutine flips back and forth a few hundred times to
	// maximise the chance of catching a reader mid-lookup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for k := 0; k < 500; k++ {
			toggle = !toggle
			if toggle {
				h.Store(rNew)
			} else {
				h.Store(rOld)
			}
			swapped.Add(1)
		}
	}()

	wg.Wait()

	if torn.Load() != 0 {
		t.Errorf("torn reads observed: %d (expected 0)", torn.Load())
	}
	if swapped.Load() == 0 {
		t.Errorf("expected swaps to have run")
	}
}
