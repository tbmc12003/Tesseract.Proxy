// Package log is a small wrapper around log/slog that constructs a
// configured *slog.Logger from explicit Options.
//
// Design notes:
//   - The wrapper is deliberately thin. Application code uses *slog.Logger
//     directly; this package only handles construction + validation.
//   - JSON output is the default and the format used in production (the
//     audit pipeline and operator tooling expect structured records).
//   - No global default logger is exposed. Each consumer receives a
//     *slog.Logger by injection.
package log

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Options configures a Logger. The zero value is invalid; callers must set
// at minimum Output. Level and Format default to "info" and "json" when
// empty.
type Options struct {
	// Level is one of: debug, info, warn (alias: warning), error.
	// Empty means "info".
	Level string

	// Format is one of: json, text.
	// Empty means "json".
	Format string

	// Output is the sink. Required; typically os.Stderr.
	Output io.Writer
}

// New constructs a *slog.Logger from opts. It returns an error on unknown
// Level / Format values or a nil Output.
func New(opts Options) (*slog.Logger, error) {
	if opts.Output == nil {
		return nil, fmt.Errorf("log: Output is required")
	}

	lvl, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	handlerOpts := &slog.HandlerOptions{
		Level: lvl,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "", "json":
		handler = slog.NewJSONHandler(opts.Output, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(opts.Output, handlerOpts)
	default:
		return nil, fmt.Errorf("log: unknown format %q (want json|text)", opts.Format)
	}

	return slog.New(handler), nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log: unknown level %q (want debug|info|warn|error)", s)
	}
}
