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
	"strings"
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

// loadDotEnv reads KEY=VALUE lines from a ".env" file in the current
// directory, if one exists, and sets any that aren't already present in
// the environment (a real env var always wins over the file). Blank lines
// and lines starting with "#" are skipped; surrounding quotes on the value
// are trimmed. This exists only for optional local-dev keys like
// OPENAI_API_KEY (see docs/conventions.md and the classifier's own doc
// comment) — deliberately minimal (no export keyword, no multiline
// values, no interpolation) rather than pulling in a dotenv dependency for
// a handful of lines.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // no .env file — nothing to load, not an error
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}

func run() error {
	loadDotEnv(".env")

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
