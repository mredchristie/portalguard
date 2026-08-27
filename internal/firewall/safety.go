package firewall

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// releaseTimeout bounds the teardown attempt made while the process is dying.
// It must be short: we would rather retry by hand than hang on exit.
const releaseTimeout = 5 * time.Second

// Logf is the minimal logging shape the safety net needs.
type Logf func(format string, args ...any)

// SafetyNet guarantees that Portalguard's rules are torn down when the process
// goes away for any reason we can observe: a normal return, a panic, or a
// termination signal.
//
// It cannot help with SIGKILL or a power cut. Backends must therefore keep
// their rules in a container that does not survive a reboot, and the CLI must
// always offer a manual `portalguard release` escape hatch.
type SafetyNet struct {
	backend Backend
	logf    Logf

	once   sync.Once
	sigCh  chan os.Signal
	doneCh chan struct{}
}

// ==== catching the exits we can see =======================================
// Signals and panics. Not kill -9 - that is what make rescue is for.

// InstallSafetyNet starts watching for termination signals. The returned
// SafetyNet must be stopped (usually with defer) once the caller no longer
// wants automatic teardown.
func InstallSafetyNet(b Backend, logf Logf) *SafetyNet {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &SafetyNet{
		backend: b,
		logf:    logf,
		sigCh:   make(chan os.Signal, 1),
		doneCh:  make(chan struct{}),
	}
	signal.Notify(s.sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go s.watch()
	return s
}

func (s *SafetyNet) watch() {
	select {
	case sig := <-s.sigCh:
		s.logf("received %s: releasing firewall rules before exit", sig)
		s.Release()
		// Restore the default disposition and re-raise so the exit status
		// reflects the signal rather than a plain os.Exit(0).
		signal.Stop(s.sigCh)
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(sig)
		}
		// If re-raising did not kill us (SIGHUP with a handler elsewhere),
		// fall back to a hard exit rather than continuing with rules gone.
		time.Sleep(2 * time.Second)
		os.Exit(1)
	case <-s.doneCh:
		return
	}
}

// Release tears the rules down now. It is safe to call repeatedly.
func (s *SafetyNet) Release() {
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	if err := s.backend.Release(ctx); err != nil {
		// This is the one failure the user must never miss: it means the
		// machine may still be locked down.
		s.logf("FIREWALL RELEASE FAILED: %v", err)
		s.logf("run `sudo %s release` (or `sudo pfctl -a portalguard -F all`) to restore networking", os.Args[0])
	}
}

// Stop ends signal watching without touching the firewall.
func (s *SafetyNet) Stop() {
	s.once.Do(func() {
		signal.Stop(s.sigCh)
		close(s.doneCh)
	})
}

// Guard runs fn and releases the firewall if fn panics, then re-panics. Use it
// around any code path that has already called Lockdown.
func Guard(b Backend, logf Logf, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if logf != nil {
				logf("panic while firewall was engaged: %v -- releasing rules", r)
			}
			ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
			defer cancel()
			_ = b.Release(ctx)
			panic(r)
		}
	}()
	return fn()
}
