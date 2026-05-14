// Package profile loads, verifies, and validates the signed broker bundle
// (arch §13.2 / §13.4 / §13.5) and builds an immutable Router from it.
//
// Trust anchor: the ECDSA P-256 signing pubkey is pinned at install time. The
// bundle YAML carries no trust signal by itself — every load path goes
// through detached-signature verification against the pinned pubkey before
// any field is acted upon.
package profile

import "time"

// Bundle is the parsed broker bundle. Field tags mirror arch §13.6.
type Bundle struct {
	SchemaVersion   int             `yaml:"schema_version"   json:"schema_version"`
	BundleVersion   string          `yaml:"bundle_version"   json:"bundle_version"`
	IssuedAt        time.Time       `yaml:"issued_at"        json:"issued_at"`
	Issuer          string          `yaml:"issuer"           json:"issuer"`
	MinProxyVersion string          `yaml:"min_proxy_version" json:"min_proxy_version"`
	Brokers         []BrokerProfile `yaml:"brokers"          json:"brokers"`
}

// BrokerProfile is a single broker's routing + idempotency + rate-limit
// description.
type BrokerProfile struct {
	ID             string            `yaml:"id"              json:"id"`
	DisplayName    string            `yaml:"display_name"    json:"display_name"`
	Host           string            `yaml:"host"            json:"host"`
	Enabled        bool              `yaml:"enabled"         json:"enabled"`
	OrderEndpoints []OrderEndpoint   `yaml:"order_endpoints" json:"order_endpoints"`
	Idempotency    IdempotencyConfig `yaml:"idempotency"     json:"idempotency"`
	RateLimit      RateLimitConfig   `yaml:"rate_limit"      json:"rate_limit"`
}

// OrderEndpoint is one row of the allowlist: (method, path, kind).
type OrderEndpoint struct {
	Method string       `yaml:"method" json:"method"`
	Path   string       `yaml:"path"   json:"path"`
	Kind   EndpointKind `yaml:"kind"   json:"kind"`
}

// EndpointKind is the semantic category of an order endpoint. The proxy
// itself is broker-agnostic; the kind is for audit logging and rate-limit
// segmentation, not for routing.
type EndpointKind string

const (
	KindPlace         EndpointKind = "place"
	KindModify        EndpointKind = "modify"
	KindCancel        EndpointKind = "cancel"
	KindPlaceMulti    EndpointKind = "place_multi"
	KindModifyMulti   EndpointKind = "modify_multi"
	KindCancelMulti   EndpointKind = "cancel_multi"
	KindPlaceMultileg EndpointKind = "place_multileg"
	KindExit          EndpointKind = "exit"
	KindExitPositions EndpointKind = "exit_positions"
	KindCancelCover   EndpointKind = "cancel_cover"
	KindCancelBracket EndpointKind = "cancel_bracket"
)

// knownKinds enumerates the accepted EndpointKind values. Anything outside
// this set is rejected at validation time.
var knownKinds = map[EndpointKind]struct{}{
	KindPlace: {}, KindModify: {}, KindCancel: {},
	KindPlaceMulti: {}, KindModifyMulti: {}, KindCancelMulti: {},
	KindPlaceMultileg: {},
	KindExit:          {}, KindExitPositions: {},
	KindCancelCover: {}, KindCancelBracket: {},
}

// knownMethods enumerates the HTTP methods we accept in the bundle.
var knownMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
}

// IdempotencyConfig captures the per-broker idempotency wiring.
type IdempotencyConfig struct {
	ClientOrderIDHeader   string `yaml:"client_order_id_header"    json:"client_order_id_header"`
	ClientOrderIDBodyPath string `yaml:"client_order_id_body_path" json:"client_order_id_body_path"`
	EchoInResponsePath    string `yaml:"echo_in_response_path"     json:"echo_in_response_path"`
}

// RateLimitConfig is the per-user token-bucket rate-limit for a broker.
type RateLimitConfig struct {
	PerUserRPS   int `yaml:"per_user_rps"   json:"per_user_rps"`
	PerUserBurst int `yaml:"per_user_burst" json:"per_user_burst"`
}
