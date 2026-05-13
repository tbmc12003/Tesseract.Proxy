//go:build windows

package main

import "os"

// installReloadSignals on Windows returns channels that never fire.
// SIGHUP and SIGUSR1 don't exist on Windows; the reload + poke flows
// are available via the /admin/* endpoints (POST /admin/bundle/reload).
func installReloadSignals() (hup, usr1 <-chan os.Signal, stop func()) {
	never := make(chan os.Signal, 1)
	return never, never, func() {}
}
