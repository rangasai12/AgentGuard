// classifier.go assigns a coarse verb (read/write/delete/permission/
// unknown) to every mcp_tool/function row in a tenant's tool catalog, so
// the anomaly detector's "operation" kind can bucket calls by effect
// rather than by name. It calls OpenAI's Chat Completions API directly
// over net/http — the one place this codebase talks to an LLM, and the
// one sanctioned exception to the SDKs' zero-dependency rule (this code
// runs only in the cloud binary, never shipped to a customer's process;
// see docs/conventions.md). When no API key is configured, or the call
// fails, classification falls back to engine.HeuristicVerb — the same
// fallback built-in action types always use — so a missing/misbehaving
// classifier never blocks ingest or leaves a tool permanently
// unclassified.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"agentguard/dashboard/store"
	"agentguard/engine"
)

var validVerbs = map[string]bool{
	string(engine.VerbRead): true, string(engine.VerbWrite): true, string(engine.VerbDelete): true,
	string(engine.VerbPermission): true, string(engine.VerbUnknown): true,
}

const defaultClassifierModel = "gpt-4o-mini"

// toolClassifier is the whole state one cloud process needs to classify
// tools: an HTTP client, an API key (empty disables the LLM path), and
// which model to ask.
type toolClassifier struct {
	httpClient *http.Client
	apiKey     string
	model      string
}

func newToolClassifier() *toolClassifier {
	return &toolClassifier{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		apiKey:     os.Getenv("OPENAI_API_KEY"),
		model:      envOr("AGENTGUARD_CLASSIFIER_MODEL", defaultClassifierModel),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// classifyUnclassified assigns a verb to every one of tenantID's catalog
// rows that doesn't have one yet (verb_source == ""). A row an admin has
// already overridden (verb_source == "user") is never selected here — see
// store.SetToolVerb / store.ListToolCatalog.
//
// A single row's classification or write failing (including the whole
// pass running out of its time budget partway through a batch of several
// new tools) is logged and skipped rather than aborting the rest of the
// loop: one slow or misbehaving call must never keep unrelated tools from
// getting classified in the same pass, and a row left unclassified here
// simply gets picked up on the next ingest's pass — verb_source stays ""
// until it succeeds. Only a failure to list the catalog at all — meaning
// there is nothing to loop over — is returned to the caller.
func (c *toolClassifier) classifyUnclassified(ctx context.Context, s *store.Store, tenantID string) error {
	catalog, err := s.ListToolCatalog(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, row := range catalog {
		if row.VerbSource != "" {
			continue
		}
		verb, reason, confidence, source := c.classifyOne(ctx, row)
		if err := s.SetToolVerb(ctx, tenantID, row.ActionType, row.Resource, verb, reason, confidence, source); err != nil {
			log.Printf("agentguard-cloud: setting verb for %s:%s: %v (will retry on a later ingest)", row.ActionType, row.Resource, err)
			continue
		}
	}
	return nil
}

func (c *toolClassifier) classifyOne(ctx context.Context, row store.ToolCatalogEntry) (verb, reason string, confidence *float64, source string) {
	if c.apiKey != "" {
		if v, r, conf, err := c.askLLM(ctx, row); err == nil {
			return v, r, &conf, "llm"
		}
	}
	fallback := engine.HeuristicVerb(engine.ActionType(row.ActionType), row.Resource)
	return string(fallback), "heuristic fallback (no classifier key configured, or the call failed)", nil, "heuristic"
}

// classifierPrompt is the one place the tool-classification instructions
// live, shared between the real call and (indirectly, by construction)
// anything that tests response parsing.
const classifierPrompt = `You classify one AI agent tool call by its effect. Answer with a single line of JSON only, no other text: {"verb": "...", "reason": "...", "confidence": 0.0}. verb must be exactly one of: read, write, delete, permission, unknown. Use "unknown" if the name and description do not make the effect clear. reason is a short (<15 words) justification. confidence is 0.0-1.0.

Tool to classify:
name: %s
argument names: %s
description: %s`

func (c *toolClassifier) askLLM(ctx context.Context, row store.ToolCatalogEntry) (verb, reason string, confidence float64, err error) {
	prompt := fmt.Sprintf(classifierPrompt, row.Resource, strings.Join(row.ArgKeys, ", "), row.Description)

	reqBody, err := json.Marshal(map[string]any{
		"model":           c.model,
		"max_tokens":      200,
		"temperature":     0,
		"messages":        []map[string]string{{"role": "user", "content": prompt}},
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return "", "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("classifier API returned status %d", resp.StatusCode)
	}

	var body struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", "", 0, err
	}
	if len(body.Choices) == 0 {
		return "", "", 0, fmt.Errorf("classifier API returned no choices")
	}
	return parseClassifierResponse(body.Choices[0].Message.Content)
}

// parseClassifierResponse validates the model's answer independently of
// the network call, so the parsing/validation logic has a test that never
// touches the network.
func parseClassifierResponse(text string) (verb, reason string, confidence float64, err error) {
	var parsed struct {
		Verb       string  `json:"verb"`
		Reason     string  `json:"reason"`
		Confidence float64 `json:"confidence"`
	}
	// The model is asked for JSON only, but tolerate a stray code fence or
	// leading/trailing text around the one JSON object.
	start, end := strings.IndexByte(text, '{'), strings.LastIndexByte(text, '}')
	if start < 0 || end < start {
		return "", "", 0, fmt.Errorf("no JSON object in classifier response: %q", text)
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &parsed); err != nil {
		return "", "", 0, fmt.Errorf("invalid JSON in classifier response: %w", err)
	}
	if !validVerbs[parsed.Verb] {
		return "", "", 0, fmt.Errorf("classifier returned an unrecognized verb %q", parsed.Verb)
	}
	return parsed.Verb, parsed.Reason, parsed.Confidence, nil
}
