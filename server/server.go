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
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/logger"
)

// shutdownTimeout bounds how long graceful shutdown of all servers may take.
const shutdownTimeout = 30 * time.Second

// Server is a long-running component managed by RunE. Startup binds and serves
// until the server stops or fails, and must abandon pending bind/start work when
// its context is cancelled. Shutdown stops an active server while honouring the
// caller's deadline.
type Server interface {
	Startup(context.Context) error
	Shutdown(context.Context) error
}

type startupResult struct {
	name string
	err  error
}

// RunE starts every server concurrently and blocks until either an OS signal
// (SIGINT/SIGTERM) arrives or any server's Startup returns, then shuts them all
// down within shutdownTimeout and returns the joined startup/shutdown errors.
// A nil Startup return before coordinated shutdown is treated as an unexpected
// stop so the process cannot remain partially available.
func RunE(srvs map[string]Server) error {
	if len(srvs) == 0 {
		return errors.New("no servers enabled")
	}
	for name, srv := range srvs {
		if isNilServer(srv) {
			return fmt.Errorf("server %q is nil", name)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	startupContext, cancelStartup := context.WithCancel(context.Background())
	defer cancelStartup()

	startupResults := make(chan startupResult, len(srvs))
	var upwg sync.WaitGroup
	for name, srv := range srvs {
		upwg.Add(1)
		go func(name string, s Server) {
			defer upwg.Done()
			startupResults <- startupResult{name: name, err: s.Startup(startupContext)}
		}(name, srv)
	}

	startupResultsConsumed := 0
	var startupErrors []error
	select {
	case s := <-sig:
		logger.Infof("shutdown signal received: %s", s)
	case result := <-startupResults:
		startupResultsConsumed++
		first := startupResultError(result, true, false)
		startupErrors = append(startupErrors, first)
		logger.Errorf("server startup failed, shutting down others: %s", first)
	}
	cancelStartup()

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
	for startupResultsConsumed < len(srvs) {
		result := <-startupResults
		startupResultsConsumed++
		if err := startupResultError(result, false, true); err != nil {
			startupErrors = append(startupErrors, err)
		}
	}

	logger.Info("server exiting")
	return errors.Join(append(startupErrors, downerrs...)...)
}

func startupResultError(result startupResult, unexpectedNil, coordinatedCancellation bool) error {
	if result.err != nil {
		if coordinatedCancellation && errors.Is(result.err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("%s startup: %w", result.name, result.err)
	}
	if unexpectedNil {
		return fmt.Errorf("%s startup: stopped unexpectedly", result.name)
	}
	return nil
}

func isNilServer(srv Server) bool {
	if srv == nil {
		return true
	}
	value := reflect.ValueOf(srv)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
