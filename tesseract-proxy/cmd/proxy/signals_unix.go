//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// installReloadSignals returns channels firing on SIGHUP and SIGUSR1 plus
// a stop function. Unix-only; the Windows build supplies a stub that
// returns never-firing channels.
func installReloadSignals() (hup, usr1 <-chan os.Signal, stop func()) {
	hupCh := make(chan os.Signal, 1)
	usrCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	signal.Notify(usrCh, syscall.SIGUSR1)
	return hupCh, usrCh, func() {
		signal.Stop(hupCh)
		signal.Stop(usrCh)
	}
}
