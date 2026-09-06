package engine

import "testing"

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
