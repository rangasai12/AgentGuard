package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"agentguard/dashboard/store"
)

// httpClient is a minimal client for agentguard-cloud's Control API
// (dashboard/server/controlapi.go) — one small file rather than a
// generated SDK, since this binary only ever talks to five endpoints.
type httpClient struct {
	base   string
	apiKey string
	http   *http.Client
}

func (c *httpClient) register(registrationToken string) (agentID, apiKey string, err error) {
	var resp struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if err := c.postJSON("/v1/agents/register", "", map[string]string{"registration_token": registrationToken}, &resp); err != nil {
		return "", "", err
	}
	return resp.AgentID, resp.APIKey, nil
}

func (c *httpClient) postEvents(events []store.IngestedEvent) error {
	return c.postJSON("/v1/events", c.apiKey, map[string]any{"events": events}, nil)
}

func (c *httpClient) syncPending(pending []store.SyncedPending) error {
	return c.postJSON("/v1/pending/sync", c.apiKey, map[string]any{"pending": pending}, nil)
}

func (c *httpClient) pendingResolutions() ([]store.ResolutionRequest, error) {
	var resp struct {
		Resolutions []store.ResolutionRequest `json:"resolutions"`
	}
	if err := c.getJSON("/v1/pending/resolutions", c.apiKey, &resp); err != nil {
		return nil, err
	}
	return resp.Resolutions, nil
}

func (c *httpClient) ackResolution(localID, resolution string) error {
	return c.postJSON("/v1/pending/ack", c.apiKey, map[string]string{"local_id": localID, "resolution": resolution}, nil)
}

func (c *httpClient) postJSON(path, apiKey string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return c.do(req, out)
}

func (c *httpClient) getJSON(path, apiKey string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return c.do(req, out)
}

func (c *httpClient) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return fmt.Errorf("%s %s: %d %s", req.Method, req.URL.Path, resp.StatusCode, errBody.Error)
		}
		return fmt.Errorf("%s %s: %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
