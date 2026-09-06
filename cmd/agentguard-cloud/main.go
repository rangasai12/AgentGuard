// Command agentguard-cloud runs the hosted dashboard backend: the Control
// API (agent-facing, /v1/) and the Web API (browser-facing, /api/) served
// from one process against one Postgres database. See
// dashboard/server.New's doc comment for why both live in one binary for
// Phase 1.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agentguard/dashboard/server"
	"agentguard/dashboard/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentguard-cloud:", err)
		os.Exit(1)
	}
}

func run() error {
	dsn := os.Getenv("AGENTGUARD_CLOUD_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres:///agentguard_dashboard_dev"
	}
	addr := os.Getenv("AGENTGUARD_CLOUD_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8090"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		return fmt.Errorf("migrating schema: %w", err)
	}

	httpServer := &http.Server{Addr: addr, Handler: server.New(s)}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("agentguard-cloud listening on %s (db: %s)", addr, dsn)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}
