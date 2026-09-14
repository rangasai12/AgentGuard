package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// stubCloudServer stands in for dashboard/server's webapi.go, asserting the
// exact request shapes agentctl cloud must send: JSON body for signup and
// for the agent name, but tenant_id as a QUERY PARAM (not body JSON) on
// /api/agents — the exact convention an external developer had to
// reverse-engineer (see CHANGELOG "Fix 3"). A test against the real
// convention here would have caught a client sending tenant_id in the
// body before it ever shipped.
func stubCloudServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/signup", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("signup: decoding body: %v", err)
		}
		for _, field := range []string{"company_name", "email", "password"} {
			if body[field] == "" {
				t.Fatalf("signup: expected JSON body field %q, got %+v", field, body)
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "ag_session", Value: "fake-session-token", Path: "/"})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"user_id": "user_1", "tenant_id": "tenant_1"})
	})

	mux.HandleFunc("POST /api/agents", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("tenant_id"); got != "tenant_1" {
			t.Fatalf("expected tenant_id as a query param, got query=%q body-would-be-wrong-place", got)
		}
		if len(r.URL.Query().Get("name")) > 0 {
			t.Fatalf("name must not be sent as a query param, got %q", r.URL.RawQuery)
		}
		cookie, err := r.Cookie("ag_session")
		if err != nil || cookie.Value != "fake-session-token" {
			t.Fatalf("expected the session cookie from signup to be replayed, got err=%v cookie=%v", err, cookie)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("agents create: decoding body: %v", err)
		}
		if body["name"] == "" {
			t.Fatalf("agents create: expected JSON body field %q, got %+v", "name", body)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": "agent_1", "registration_token": "reg-token-xyz"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCloudSignupThenAgentsCreateSendsExactRequestShapes(t *testing.T) {
	srv := stubCloudServer(t)
	statePath := filepath.Join(t.TempDir(), "cloud-session.json")

	var stdout, stderr bytes.Buffer
	code := runCloud([]string{"signup", "--api-url", srv.URL, "--company", "Acme", "--email", "u@acme.example", "--password", "password123", "--state", statePath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cloud signup: exit %d, stderr=%s", code, stderr.String())
	}

	sess, err := loadCloudSession(statePath)
	if err != nil {
		t.Fatalf("loadCloudSession: %v", err)
	}
	if sess.SessionCookie != "fake-session-token" || sess.TenantID != "tenant_1" {
		t.Fatalf("expected the session and tenant to be saved, got %+v", sess)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCloud([]string{"agents", "create", "--state", statePath, "test-agent"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cloud agents create: exit %d, stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("reg-token-xyz")) {
		t.Fatalf("expected the registration token in stdout, got %s", stdout.String())
	}
}

func TestCloudAgentsCreateWithoutSignupFailsWithAHelpfulError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "does-not-exist.json")
	var stdout, stderr bytes.Buffer
	code := runCloud([]string{"agents", "create", "--state", statePath, "test-agent"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected a non-zero exit when no session is saved")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("cloud signup")) {
		t.Fatalf("expected the error to point at `cloud signup`, got %s", stderr.String())
	}
}
