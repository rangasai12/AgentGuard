package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"agentguard/dashboard/store"
)

func TestParseClassifierResponse(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		wantErr bool
		verb    string
	}{
		{"clean json", `{"verb": "delete", "reason": "removes a record", "confidence": 0.9}`, false, "delete"},
		{"wrapped in prose", "Sure, here is the answer:\n```json\n{\"verb\": \"read\", \"reason\": \"looks up data\", \"confidence\": 0.8}\n```\nHope that helps.", false, "read"},
		{"unrecognized verb", `{"verb": "modify", "reason": "x", "confidence": 0.5}`, true, ""},
		{"no json object", "I cannot classify this tool.", true, ""},
		{"malformed json", `{"verb": "read", "reason": }`, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verb, _, _, err := parseClassifierResponse(c.text)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got verb %q", c.text, verb)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verb != c.verb {
				t.Fatalf("verb = %q, want %q", verb, c.verb)
			}
		})
	}
}

func TestToolClassifierHeuristicFallbackAndUserOverride(t *testing.T) {
	_, s, _, tenantID, agentID, _ := setupAnomalyAgent(t)
	ctx := context.Background()

	// A function-type tool call with a name the heuristic can read cleanly.
	if err := s.InsertEvents(ctx, tenantID, agentID, []store.IngestedEvent{
		{Timestamp: time.Now(), ActionType: "function", Resource: "delete_customer", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"delete_customer","description":"Deletes a customer record."}`)},
	}); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	// No OPENAI_API_KEY is set in the test environment, so this
	// exercises the heuristic fallback path, not a real network call.
	classifier := newToolClassifier()
	if classifier.apiKey != "" {
		t.Skip("OPENAI_API_KEY is set in this environment; heuristic-fallback test would exercise the live LLM path instead")
	}
	if err := classifier.classifyUnclassified(ctx, s, tenantID); err != nil {
		t.Fatalf("classifyUnclassified: %v", err)
	}

	tools, err := s.ListToolCatalog(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListToolCatalog: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 cataloged tool, got %+v", tools)
	}
	tool := tools[0]
	if tool.VerbSource != "heuristic" || tool.Verb != "delete" {
		t.Fatalf("delete_customer classified as %+v, want verb=delete source=heuristic", tool)
	}

	// An admin overrides it.
	if err := s.SetToolVerb(ctx, tenantID, "function", "delete_customer", "permission", "user override", nil, "user"); err != nil {
		t.Fatalf("SetToolVerb: %v", err)
	}

	// Re-running classification must never touch a user-set row.
	if err := classifier.classifyUnclassified(ctx, s, tenantID); err != nil {
		t.Fatalf("classifyUnclassified (second pass): %v", err)
	}
	tools, err = s.ListToolCatalog(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListToolCatalog: %v", err)
	}
	if tools[0].Verb != "permission" || tools[0].VerbSource != "user" {
		t.Fatalf("classifier overwrote a user override: %+v", tools[0])
	}
}
