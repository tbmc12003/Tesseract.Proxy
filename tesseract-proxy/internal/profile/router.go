package profile

import (
	"fmt"
	"regexp"
	"strings"
)

// Router is the immutable route table built from one Bundle. It is safe for
// concurrent reads; mutation happens by replacing the pointer (see arch
// §13.5 atomic-swap pattern; the actual atomic.Pointer wrapping lives at
// the call site — P2.4).
type Router struct {
	bundleVersion string
	byBroker      map[string]*brokerRoutes
}

type brokerRoutes struct {
	profile *BrokerProfile
	routes  []compiledRoute
}

type compiledRoute struct {
	method   string
	template string // original path template, for diagnostics
	re       *regexp.Regexp
	endpoint *OrderEndpoint
}

// Match describes a successful router lookup.
type Match struct {
	Broker   *BrokerProfile
	Endpoint *OrderEndpoint
}

// BundleVersion returns the bundle_version this Router was built from.
func (r *Router) BundleVersion() string { return r.bundleVersion }

// Brokers returns the broker profiles indexed by this Router, in insertion
// (bundle) order.
func (r *Router) Brokers() []*BrokerProfile {
	out := make([]*BrokerProfile, 0, len(r.byBroker))
	for _, br := range r.byBroker {
		out = append(out, br.profile)
	}
	return out
}

// Lookup returns the matching broker + endpoint for (brokerID, method,
// path), or nil if no allowlist entry matches. Disabled brokers never
// match. The path matching is exact for literal segments and `[^/]+` for
// `{var}` placeholders.
func (r *Router) Lookup(brokerID, method, path string) *Match {
	br, ok := r.byBroker[brokerID]
	if !ok {
		return nil
	}
	if !br.profile.Enabled {
		return nil
	}
	for i := range br.routes {
		rt := &br.routes[i]
		if rt.method != method {
			continue
		}
		if rt.re.MatchString(path) {
			return &Match{Broker: br.profile, Endpoint: rt.endpoint}
		}
	}
	return nil
}

func (b *Bundle) buildRouter() (*Router, error) {
	r := &Router{
		bundleVersion: b.BundleVersion,
		byBroker:      make(map[string]*brokerRoutes, len(b.Brokers)),
	}
	for i := range b.Brokers {
		bp := &b.Brokers[i]
		routes := make([]compiledRoute, 0, len(bp.OrderEndpoints))
		for j := range bp.OrderEndpoints {
			ep := &bp.OrderEndpoints[j]
			re, err := compilePathTemplate(ep.Path)
			if err != nil {
				return nil, fmt.Errorf("profile: brokers[%d] (%s) endpoint[%d]: %w", i, bp.ID, j, err)
			}
			routes = append(routes, compiledRoute{
				method:   ep.Method,
				template: ep.Path,
				re:       re,
				endpoint: ep,
			})
		}
		r.byBroker[bp.ID] = &brokerRoutes{profile: bp, routes: routes}
	}
	return r, nil
}

// compilePathTemplate converts an arch-§13.2 path template into an anchored
// regular expression. The template syntax is intentionally narrow:
// literal characters and `{var}` placeholders, nothing else. Validation
// (validatePath) has already rejected regex specials, so the substitution
// here is safe.
func compilePathTemplate(tmpl string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteByte('^')
	i := 0
	for i < len(tmpl) {
		c := tmpl[i]
		if c == '{' {
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("unclosed placeholder in %q", tmpl)
			}
			sb.WriteString(`[^/]+`)
			i += end + 1
			continue
		}
		sb.WriteString(regexp.QuoteMeta(string(c)))
		i++
	}
	sb.WriteByte('$')
	return regexp.Compile(sb.String())
}
