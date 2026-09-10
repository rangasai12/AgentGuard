// Command agentguard-forwarder is the only new component that runs on a
// customer's own machine to connect their local AgentGuard daemon to the
// hosted dashboard (agentguard-cloud). It does three things, all against
// the daemon's existing, unmodified interfaces:
//
//  1. Tails the local JSONL audit log (checkpointed by byte offset, so a
//     restart never re-sends or drops events) and ships new events
//     upstream.
//  2. Polls the daemon's existing `pending_approvals` socket command and
//     syncs the snapshot upstream, so the dashboard can show a live
//     pending-approvals queue.
//  3. Polls the Control API for approvals a human resolved from the
//     browser, and relays each one to the local daemon via its existing
//     `approve`/`deny` socket commands — then acks the relay so the
//     dashboard can show the approval as actually enforced, not just
//     "clicked".
//
// The daemon, the audit log, and the approval broker are all completely
// unaware this process exists. If agentguard-cloud is unreachable, this
// process just logs and retries next tick — local policy enforcement is
// never affected, and `agentctl approve`/`deny` on the machine itself
// always still works as a fallback.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"agentguard/cli"
	"agentguard/daemon"
	"agentguard/dashboard/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentguard-forwarder:", err)
		os.Exit(1)
	}
}

func run() error {
	controlAPI := flag.String("control-api", envOr("AGENTGUARD_CONTROL_API", "http://127.0.0.1:8090"), "base URL of the agentguard-cloud Control API")
	socketPath := flag.String("socket", cli.DefaultSocketPath(), "local daemon unix socket path")
	auditLogPath := flag.String("audit-log", cli.DefaultAuditLogPath(), "local daemon JSONL audit log path")
	statePath := flag.String("state", envOr("AGENTGUARD_FORWARDER_STATE", cli.DefaultSocketPath()+".forwarder-state.json"), "path to persist this forwarder's api key and audit-log read offset")
	registerToken := flag.String("register-token", "", "one-time registration token from the dashboard's \"Add Agent\" flow; redeemed once and then ignored on later runs")
	pollInterval := flag.Duration("poll-interval", 2*time.Second, "how often to sync pending approvals and check for resolutions")
	once := flag.Bool("once", false, "run a single sync cycle and exit, instead of looping forever (for tests/scripting)")
	flag.Parse()

	st, err := loadState(*statePath)
	if err != nil {
		return fmt.Errorf("loading state file: %w", err)
	}

	client := &httpClient{base: *controlAPI, http: &http.Client{Timeout: 10 * time.Second}}

	if *registerToken != "" {
		agentID, apiKey, err := client.register(*registerToken)
		if err != nil {
			return fmt.Errorf("registering with control API: %w", err)
		}
		st.APIKey = apiKey
		st.AgentID = agentID
		if err := saveState(*statePath, st); err != nil {
			return fmt.Errorf("saving state after registration: %w", err)
		}
		log.Printf("registered as agent %s", agentID)
	}
	if st.APIKey == "" {
		return fmt.Errorf("no api key on file at %s; run once with -register-token=<token from the dashboard>", *statePath)
	}
	client.apiKey = st.APIKey

	f := &forwarder{
		client:       client,
		socketPath:   *socketPath,
		auditLogPath: *auditLogPath,
		statePath:    *statePath,
		state:        st,
	}

	if *once {
		f.tick()
		return nil
	}

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()
	log.Printf("agentguard-forwarder running: daemon=%s controlAPI=%s interval=%s", *socketPath, *controlAPI, *pollInterval)
	for range ticker.C {
		f.tick()
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// forwarder holds everything one sync cycle needs.
type forwarder struct {
	client       *httpClient
	socketPath   string
	auditLogPath string
	statePath    string
	state        forwarderState
}

// tick runs one full sync cycle: relay resolutions, sync pending
// approvals, ship new audit events. Every step logs and continues on
// error rather than aborting the whole cycle — a Control API blip on one
// step shouldn't block the others.
func (f *forwarder) tick() {
	if err := f.relayResolutions(); err != nil {
		log.Printf("relaying resolutions: %v", err)
	}
	if err := f.syncPending(); err != nil {
		log.Printf("syncing pending approvals: %v", err)
	}
	if err := f.shipNewEvents(); err != nil {
		log.Printf("shipping audit events: %v", err)
	}
}

func (f *forwarder) syncPending() error {
	c, err := cli.Dial(f.socketPath)
	if err != nil {
		return fmt.Errorf("dialing local daemon: %w", err)
	}
	defer c.Close()

	resp, err := c.Call(daemon.Request{Cmd: "pending_approvals"})
	if err != nil {
		return fmt.Errorf("calling pending_approvals: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("daemon error: %s", resp.Error)
	}

	synced := make([]store.SyncedPending, len(resp.Pending))
	for i, p := range resp.Pending {
		synced[i] = store.SyncedPending{
			LocalID:     p.ID,
			Actor:       p.Actor,
			ActionType:  string(p.Action.Type),
			Resource:    p.Action.Resource(),
			MatchedRule: p.MatchedRule,
			Reason:      p.Reason,
		}
	}
	return f.client.syncPending(synced)
}

// relayResolutions asks the Control API which pending approvals a human
// resolved from the browser, relays each to the local daemon via the same
// approve/deny socket command `agentctl approve/deny` already uses, and
// acks each success so the dashboard can distinguish "clicked" from
// "actually enforced by the local daemon".
func (f *forwarder) relayResolutions() error {
	resolutions, err := f.client.pendingResolutions()
	if err != nil {
		return fmt.Errorf("fetching resolutions: %w", err)
	}
	if len(resolutions) == 0 {
		return nil
	}

	c, err := cli.Dial(f.socketPath)
	if err != nil {
		return fmt.Errorf("dialing local daemon: %w", err)
	}
	defer c.Close()

	for _, r := range resolutions {
		cmd := "approve"
		if r.Resolution == "deny" {
			cmd = "deny"
		}
		resp, err := c.Call(daemon.Request{Cmd: cmd, ID: r.LocalID})
		if err != nil {
			log.Printf("relaying %s of %s to local daemon: %v", r.Resolution, r.LocalID, err)
			continue
		}
		if !resp.OK {
			// The daemon may have already resolved this locally (e.g. it
			// timed out between our last sync and now) — log and move on
			// rather than treating it as fatal for the whole tick.
			log.Printf("local daemon rejected %s of %s: %s", r.Resolution, r.LocalID, resp.Error)
			continue
		}
		if err := f.client.ackResolution(r.LocalID, r.Resolution); err != nil {
			log.Printf("acking %s of %s: %v", r.Resolution, r.LocalID, err)
		}
	}
	return nil
}

// shipNewEvents reads any audit log lines written since the last saved
// offset, ships them upstream, and — only on a successful ack — persists
// the new offset. Failing to advance the offset on a failed ship is what
// makes this safe to retry: a dropped upstream request just means the same
// bytes get re-read and re-sent next tick.
//
// Events are shipped in batches of at most maxShipBatch, looping until the
// log is drained, since a line can now carry arguments and an output
// preview and an unbounded backlog would otherwise become one huge POST.
func (f *forwarder) shipNewEvents() error {
	for {
		events, newOffset, err := readNewEvents(f.auditLogPath, f.state.Offset, maxShipBatch)
		if err != nil {
			return fmt.Errorf("reading audit log: %w", err)
		}
		if len(events) == 0 {
			return nil
		}
		if err := f.client.postEvents(events); err != nil {
			return fmt.Errorf("posting %d events: %w", len(events), err)
		}
		f.state.Offset = newOffset
		if err := saveState(f.statePath, f.state); err != nil {
			return err
		}
		if len(events) < maxShipBatch {
			return nil
		}
	}
}

// maxShipBatch is the most audit events shipped in one POST /v1/events.
const maxShipBatch = 500

// readNewEvents reads audit.go's JSONL format starting at byte offset,
// returning only complete lines (a partial trailing line — the daemon
// mid-write — is left for the next read), at most maxEvents of them, and
// the new offset to persist. Outcome patch lines (kind = "outcome") are
// shipped as-is; the Control API merges them into the decision they name.
func readNewEvents(path string, offset int64, maxEvents int) ([]store.IngestedEvent, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, offset, nil // daemon hasn't logged anything yet
		}
		return nil, offset, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, offset, err
	}

	var events []store.IngestedEvent
	consumed := int64(0)
	for maxEvents <= 0 || len(events) < maxEvents {
		idx := bytes.IndexByte(data[consumed:], '\n')
		if idx == -1 {
			break // partial line; wait for it to be completed next tick
		}
		line := data[consumed : consumed+int64(idx)]
		consumed += int64(idx) + 1

		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev daemon.AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("skipping unparseable audit log line: %v", err)
			continue
		}
		ie := store.IngestedEvent{
			Timestamp:    ev.Timestamp,
			Actor:        ev.Actor,
			ActionType:   string(ev.ActionType),
			Resource:     ev.Resource,
			Decision:     string(ev.Decision),
			MatchedRule:  ev.MatchedRule,
			Reason:       ev.Reason,
			ApprovalID:   ev.ApprovalID,
			LatencyMS:    ev.LatencyMS,
			Kind:         ev.Kind,
			EventID:      ev.EventID,
			RunID:        ev.RunID,
			AgentVersion: ev.AgentVersion,
			PolicyHash:   ev.PolicyHash,
		}
		if ev.Action != nil {
			if raw, err := json.Marshal(ev.Action); err == nil {
				ie.Action = raw
			}
		}
		if ev.Outcome != nil {
			ie.Outcome = &store.EventOutcome{
				Status:       ev.Outcome.Status,
				ExecMS:       ev.Outcome.ExecMS,
				Output:       ev.Outcome.Output,
				OutputBytes:  ev.Outcome.OutputBytes,
				OutputSHA256: ev.Outcome.OutputSHA256,
				Error:        ev.Outcome.Error,
			}
		}
		events = append(events, ie)
	}
	return events, offset + consumed, nil
}
