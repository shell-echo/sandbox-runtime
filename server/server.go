// Package server defines the long-running server abstraction and the lifecycle
// that starts a set of servers together and shuts them down gracefully on an OS
// signal or a startup failure.
package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/logger"
)

// shutdownTimeout bounds how long graceful shutdown of all servers may take.
const shutdownTimeout = 30 * time.Second

// Server is a long-running component managed by RunE. Startup blocks until the
// server stops (e.g. http.Server.ListenAndServe) or fails; Shutdown stops it,
// honouring the context deadline.
type Server interface {
	Startup() error
	Shutdown(context.Context) error
}

// RunE starts every server concurrently and blocks until either an OS signal
// (SIGINT/SIGTERM) arrives or any server's Startup fails, then shuts them all
// down within shutdownTimeout and returns the joined startup/shutdown errors.
//
// Note: it blocks indefinitely for servers whose Startup returns nil only at
// shutdown; a one-shot task that returns nil immediately would hang it.
func RunE(srvs map[string]Server) error {
	if len(srvs) == 0 {
		return errors.New("no servers enabled")
	}

	var (
		uperrs []error
		upmu   sync.Mutex
		upwg   sync.WaitGroup
	)
	upfail := make(chan struct{}, 1)
	for name, srv := range srvs {
		upwg.Add(1)
		go func(name string, s Server) {
			defer upwg.Done()
			if err := s.Startup(); err != nil {
				upmu.Lock()
				uperrs = append(uperrs, fmt.Errorf("%s startup: %w", name, err))
				upmu.Unlock()
				select {
				case upfail <- struct{}{}:
				default:
				}
			}
		}(name, srv)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	select {
	case s := <-sig:
		logger.Infof("shutdown signal received: %s", s)
	case <-upfail:
		upmu.Lock()
		first := uperrs[0]
		upmu.Unlock()
		logger.Errorf("server startup failed, shutting down others: %s", first)
	}

	downctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var (
		downerrs []error
		downmu   sync.Mutex
		downwg   sync.WaitGroup
	)
	for name, srv := range srvs {
		downwg.Add(1)
		go func(name string, s Server) {
			defer downwg.Done()
			if err := s.Shutdown(downctx); err != nil {
				downmu.Lock()
				downerrs = append(downerrs, fmt.Errorf("%s shutdown: %w", name, err))
				downmu.Unlock()
			}
		}(name, srv)
	}
	downwg.Wait()
	upwg.Wait()

	logger.Info("server exiting")
	return errors.Join(append(uperrs, downerrs...)...)
}
