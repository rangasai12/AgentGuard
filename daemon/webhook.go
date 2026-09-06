package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookPayload is the JSON body POSTed to a configured webhook URL when an
// action requires human approval. The top-level "text" field alone is
// enough for a Slack Incoming Webhook (which only looks at that field);
// every other field is there for a generic JSON consumer that wants
// structured data instead of parsing a sentence.
type WebhookPayload struct {
	Text        string `json:"text"`
	ApprovalID  string `json:"approval_id"`
	Actor       string `json:"actor,omitempty"`
	ActionType  string `json:"action_type"`
	Resource    string `json:"resource"`
	MatchedRule string `json:"matched_rule"`
	Reason      string `json:"reason,omitempty"`
}

// WebhookNotifier returns a Notifier that POSTs a JSON payload describing a
// pending approval to url, instructing the recipient to resolve it via
// `agentctl approve`/`deny` — this is a notification channel, not a full
// remote-approval mechanism: the daemon's socket is local-only in v0.2, so
// resolving the approval still happens via a client (the CLI, today) that
// can reach that socket, typically on the same machine or over an SSH
// tunnel/port-forward. Wiring a webhook callback (e.g. Slack interactive
// message buttons) into an actual remote "click to approve" is future work
// that would need the socket exposed over the network, which is a bigger
// change than this notifier alone.
//
// POST failures are reported to errLog (if non-nil) but never returned or
// otherwise surfaced to the approval flow — see the Notifier doc comment on
// why a broken webhook must never turn into a stuck or wrongly-resolved
// action. If client is nil, a client with a 5s timeout is used.
func WebhookNotifier(url string, client *http.Client, errLog func(error)) Notifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return func(p PendingApproval) {
		payload := WebhookPayload{
			Text: fmt.Sprintf(
				"[agentguard] approval required (id=%s): %s %s — %s\nRun `agentctl approve %s` or `agentctl deny %s`",
				p.ID, p.Action.Type, p.Action.Resource(), p.MatchedRule, p.ID, p.ID,
			),
			ApprovalID:  p.ID,
			Actor:       p.Actor,
			ActionType:  string(p.Action.Type),
			Resource:    p.Action.Resource(),
			MatchedRule: p.MatchedRule,
			Reason:      p.Reason,
		}

		data, err := json.Marshal(payload)
		if err != nil {
			logErr(errLog, fmt.Errorf("marshaling webhook payload: %w", err))
			return
		}

		resp, err := client.Post(url, "application/json", bytes.NewReader(data))
		if err != nil {
			logErr(errLog, fmt.Errorf("posting approval notification to webhook: %w", err))
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			logErr(errLog, fmt.Errorf("webhook %s returned status %d", url, resp.StatusCode))
		}
	}
}

func logErr(errLog func(error), err error) {
	if errLog != nil {
		errLog(err)
	}
}
