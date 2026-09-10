package engine

import (
	"fmt"
	"testing"
)

func TestValidateRejectsBadVersion(t *testing.T) {
	_, err := ParsePolicy([]byte("version: 2\n"))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestValidateRejectsFilesystemRuleWithBothAllowAndDeny(t *testing.T) {
	yaml := `
version: 1
filesystem:
  - allow: read
    deny: write
    paths: ["/x"]
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error when both allow and deny set on one filesystem rule")
	}
}

func TestValidateRejectsFilesystemRuleWithNeitherAllowNorDeny(t *testing.T) {
	yaml := `
version: 1
filesystem:
  - paths: ["/x"]
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error when neither allow nor deny set")
	}
}

func TestValidateRejectsEmptyPaths(t *testing.T) {
	yaml := `
version: 1
filesystem:
  - allow: read
    paths: []
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for empty paths list")
	}
}

func TestValidateRejectsInvalidAccessMode(t *testing.T) {
	yaml := `
version: 1
filesystem:
  - allow: execute
    paths: ["/x"]
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid access mode")
	}
}

func TestValidateRejectsMCPToolWithNoFlags(t *testing.T) {
	yaml := `
version: 1
mcp:
  servers:
    - name: srv
      tools:
        - name: some_tool
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error when an mcp tool rule sets none of allow/deny/require_approval")
	}
}

func TestValidateRejectsFunctionRuleWithNoFlags(t *testing.T) {
	yaml := `
version: 1
functions:
  rules:
    - name: charge_customer
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error when a functions rule sets none of allow/deny/require_approval")
	}
}

func TestValidateRejectsFunctionRuleWithNoName(t *testing.T) {
	yaml := `
version: 1
functions:
  rules:
    - allow: true
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error when a functions rule has no name")
	}
}

func TestValidateRejectsFunctionConditionWithBadOp(t *testing.T) {
	yaml := `
version: 1
functions:
  rules:
    - name: charge_customer
      conditions:
        - arg: amount
          op: "~="
          value: 100
      allow: true
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for an unsupported condition operator")
	}
}

func TestValidateRejectsFunctionConditionWithNoArg(t *testing.T) {
	yaml := `
version: 1
functions:
  rules:
    - name: charge_customer
      conditions:
        - op: "<"
          value: 100
      allow: true
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for a condition with no arg")
	}
}

func TestValidateRejectsBadDefault(t *testing.T) {
	yaml := `
version: 1
network:
  default: maybe
`
	_, err := ParsePolicy([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid default value")
	}
}

func TestValidAccessorsUseDefaults(t *testing.T) {
	p, err := ParsePolicy([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ApprovalTimeoutSeconds() != 300 {
		t.Errorf("expected default timeout 300, got %d", p.ApprovalTimeoutSeconds())
	}
	if p.OnTimeoutResult() != Deny {
		t.Errorf("expected default on-timeout to be deny, got %s", p.OnTimeoutResult())
	}
}

func TestLoadPolicyMissingFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParsePolicySetsHash(t *testing.T) {
	a, err := ParsePolicy([]byte("version: 1\nname: a\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	b, err := ParsePolicy([]byte("version: 1\nname: b\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(a.Hash) != 12 || a.Hash == b.Hash {
		t.Errorf("expected distinct 12-hex hashes for distinct policy text, got %q and %q", a.Hash, b.Hash)
	}
	again, _ := ParsePolicy([]byte("version: 1\nname: a\n"))
	if again.Hash != a.Hash {
		t.Errorf("expected the hash to be a pure function of the policy text, got %q vs %q", again.Hash, a.Hash)
	}
}

func TestRedactArgs(t *testing.T) {
	p, err := ParsePolicy([]byte("version: 1\naudit:\n  redact_args: [password, token]\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	in := map[string]any{"user": "u", "password": "p", "n": 1}
	out := p.RedactArgs(in)
	if out["password"] != "[redacted]" || out["user"] != "u" || out["n"] != 1 {
		t.Errorf("unexpected redaction result: %v", out)
	}
	if in["password"] != "p" {
		t.Error("RedactArgs must not mutate its input")
	}
	if _, ok := out["token"]; ok {
		t.Error("a listed key absent from the input must not be added")
	}
	untouched := map[string]any{"a": 1}
	if got := p.RedactArgs(untouched); fmt.Sprintf("%p", got) != fmt.Sprintf("%p", untouched) {
		t.Error("expected the same map back when nothing needs redacting")
	}
	if _, err := ParsePolicy([]byte("version: 1\naudit:\n  redact_args: [\"\"]\n")); err == nil {
		t.Error("expected an empty redact_args key to be rejected")
	}
}
