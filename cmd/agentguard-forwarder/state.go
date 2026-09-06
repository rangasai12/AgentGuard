package main

import (
	"encoding/json"
	"os"
)

// forwarderState is this process's only local persistence: its api key
// (from redeeming a registration token once) and how far into the audit
// log it's already shipped. Losing this file just means re-registering
// (the dashboard's "Add Agent" flow issues a fresh token) and re-shipping
// from offset 0 — a rare, self-healing failure mode, not data loss of
// anything the local daemon itself depends on.
type forwarderState struct {
	AgentID string `json:"agent_id,omitempty"`
	APIKey  string `json:"api_key,omitempty"`
	Offset  int64  `json:"offset"`
}

func loadState(path string) (forwarderState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return forwarderState{}, nil
	}
	if err != nil {
		return forwarderState{}, err
	}
	var st forwarderState
	if err := json.Unmarshal(data, &st); err != nil {
		return forwarderState{}, err
	}
	return st, nil
}

func saveState(path string, st forwarderState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
