package profile

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// currentSchemaVersion is the schema_version this binary accepts. Bumping
// this requires a coordinated binary release; see arch §13.4 (pinned pubkey
// is the durable trust anchor, schema_version is the durable compat anchor).
const currentSchemaVersion = 1

// validate enforces structural and semantic rules on a parsed Bundle. It
// runs *before* a Router is built, on the validated bytes, so any failure
// here means the bundle never reaches the route table.
func (b *Bundle) validate() error {
	if b.SchemaVersion != currentSchemaVersion {
		return fmt.Errorf("profile: schema_version %d not supported (want %d)", b.SchemaVersion, currentSchemaVersion)
	}
	if strings.TrimSpace(b.BundleVersion) == "" {
		return fmt.Errorf("profile: bundle_version: required")
	}
	if strings.TrimSpace(b.Issuer) == "" {
		return fmt.Errorf("profile: issuer: required")
	}
	if b.IssuedAt.IsZero() {
		return fmt.Errorf("profile: issued_at: required")
	}
	if strings.TrimSpace(b.MinProxyVersion) == "" {
		return fmt.Errorf("profile: min_proxy_version: required")
	}
	if _, err := parseSemver(b.MinProxyVersion); err != nil {
		return fmt.Errorf("profile: min_proxy_version: %w", err)
	}
	if len(b.Brokers) == 0 {
		return fmt.Errorf("profile: brokers: at least one broker required")
	}

	seenID := make(map[string]struct{}, len(b.Brokers))
	for i := range b.Brokers {
		if err := validateBroker(&b.Brokers[i]); err != nil {
			return fmt.Errorf("profile: brokers[%d] (%s): %w", i, b.Brokers[i].ID, err)
		}
		if _, dup := seenID[b.Brokers[i].ID]; dup {
			return fmt.Errorf("profile: brokers: duplicate id %q", b.Brokers[i].ID)
		}
		seenID[b.Brokers[i].ID] = struct{}{}
	}
	return nil
}

var brokerIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

func validateBroker(bp *BrokerProfile) error {
	if !brokerIDRe.MatchString(bp.ID) {
		return fmt.Errorf("id: invalid (want lowercase letters, digits, underscore; max 32 chars), got %q", bp.ID)
	}
	if strings.TrimSpace(bp.DisplayName) == "" {
		return fmt.Errorf("display_name: required")
	}
	if err := validateHost(bp.Host); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	if len(bp.OrderEndpoints) == 0 {
		return fmt.Errorf("order_endpoints: at least one endpoint required")
	}
	seen := make(map[string]struct{}, len(bp.OrderEndpoints))
	for i := range bp.OrderEndpoints {
		if err := validateEndpoint(&bp.OrderEndpoints[i]); err != nil {
			return fmt.Errorf("order_endpoints[%d]: %w", i, err)
		}
		key := bp.OrderEndpoints[i].Method + " " + bp.OrderEndpoints[i].Path
		if _, dup := seen[key]; dup {
			return fmt.Errorf("order_endpoints: duplicate %s", key)
		}
		seen[key] = struct{}{}
	}
	if bp.RateLimit.PerUserRPS < 0 || bp.RateLimit.PerUserBurst < 0 {
		return fmt.Errorf("rate_limit: must be non-negative")
	}
	return nil
}

// validateHost enforces arch §13.2: literal hostname only — no wildcards,
// no raw IPs. Internal test hosts ending in ".local" are explicitly allowed.
func validateHost(h string) error {
	if h == "" {
		return fmt.Errorf("required")
	}
	if strings.ContainsAny(h, "*?[]") {
		return fmt.Errorf("wildcards not allowed: %q", h)
	}
	if ip := net.ParseIP(h); ip != nil {
		return fmt.Errorf("raw IP not allowed: %q", h)
	}
	// Each label must be LDH and not start/end with hyphen.
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("must be a dotted hostname: %q", h)
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("empty label in %q", h)
		}
		if len(l) > 63 {
			return fmt.Errorf("label too long in %q", h)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label starts/ends with hyphen in %q", h)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' {
				return fmt.Errorf("invalid char %q in host %q", c, h)
			}
		}
	}
	return nil
}

func validateEndpoint(e *OrderEndpoint) error {
	if _, ok := knownMethods[e.Method]; !ok {
		return fmt.Errorf("method %q not in {GET,POST,PUT,PATCH,DELETE}", e.Method)
	}
	if _, ok := knownKinds[e.Kind]; !ok {
		return fmt.Errorf("kind %q is not a recognised endpoint kind", e.Kind)
	}
	return validatePath(e.Path)
}

// validatePath enforces arch §13.2: paths use {var} template syntax only,
// never regex. Allowed chars outside placeholders: [A-Za-z0-9_.~/-]. Inside
// {...}: a single identifier matching [A-Za-z_][A-Za-z0-9_]*.
//
// We compile the template into a regex at router-build time; rejecting
// regex specials here keeps the eventual compiled regex predictable and
// stops smuggling of `.*` / alternations through path templates.
func validatePath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must start with /", p)
	}
	i := 0
	for i < len(p) {
		c := p[i]
		switch c {
		case '{':
			end := strings.IndexByte(p[i:], '}')
			if end < 0 {
				return fmt.Errorf("path %q: unclosed { placeholder", p)
			}
			name := p[i+1 : i+end]
			if !isValidVarName(name) {
				return fmt.Errorf("path %q: invalid placeholder name %q", p, name)
			}
			i += end + 1
		case '}':
			return fmt.Errorf("path %q: stray }", p)
		default:
			if !isValidPathByte(c) {
				return fmt.Errorf("path %q: invalid character %q (regex-special characters are not allowed; use {var} for placeholders)", p, c)
			}
			i++
		}
	}
	return nil
}

func isValidPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '/', '-', '_', '.', '~':
		return true
	}
	return false
}

func isValidVarName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		if i > 0 {
			ok = ok || (c >= '0' && c <= '9')
		}
		if !ok {
			return false
		}
	}
	return true
}
