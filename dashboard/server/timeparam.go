package server

import (
	"fmt"
	"net/http"
	"time"
)

// parseTimeParam reads an RFC3339 timestamp query parameter, returning nil
// if it's absent (an open-ended bound) or an error if it's present but
// unparseable.
func parseTimeParam(r *http.Request, name string) (*time.Time, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("expected RFC3339 (e.g. 2026-09-05T00:00:00Z), got %q: %w", raw, err)
	}
	return &t, nil
}
