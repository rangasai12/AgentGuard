package engine

import "testing"

const sampleTraceYAML = `
version: 1
cases:
  - name: "write inside workspace allowed"
    action:
      type: fs_write
      path: /workspace/main.go
    want: allow
  - name: "write outside workspace denied"
    action:
      type: fs_write
      path: /etc/passwd
    want: deny
  - name: "rm -rf requires approval"
    action:
      type: shell
      command: "rm -rf /workspace/build"
    want: require_approval
`

func TestParseTestSuite(t *testing.T) {
	s, err := ParseTestSuite([]byte(sampleTraceYAML))
	if err != nil {
		t.Fatalf("ParseTestSuite: %v", err)
	}
	if len(s.Cases) != 3 {
		t.Fatalf("expected 3 cases, got %d", len(s.Cases))
	}
	if s.Cases[0].Action.Path != "/workspace/main.go" {
		t.Errorf("expected yaml action fields to parse using the same names as json, got %+v", s.Cases[0].Action)
	}
}

func TestParseTestSuiteRejectsBadVersion(t *testing.T) {
	_, err := ParseTestSuite([]byte("version: 2\ncases: []\n"))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseTestSuiteRejectsMissingName(t *testing.T) {
	yaml := `
version: 1
cases:
  - action: {type: shell, command: "ls"}
    want: allow
`
	_, err := ParseTestSuite([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing case name")
	}
}

func TestParseTestSuiteRejectsDuplicateName(t *testing.T) {
	yaml := `
version: 1
cases:
  - name: "dup"
    action: {type: shell, command: "ls"}
    want: allow
  - name: "dup"
    action: {type: shell, command: "pwd"}
    want: allow
`
	_, err := ParseTestSuite([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for duplicate case name")
	}
}

func TestParseTestSuiteRejectsInvalidWant(t *testing.T) {
	yaml := `
version: 1
cases:
  - name: "bad"
    action: {type: shell, command: "ls"}
    want: maybe
`
	_, err := ParseTestSuite([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid want value")
	}
}

func TestParseTestSuiteRejectsMissingActionType(t *testing.T) {
	yaml := `
version: 1
cases:
  - name: "bad"
    action: {command: "ls"}
    want: allow
`
	_, err := ParseTestSuite([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing action.type")
	}
}

func TestRunTestSuitePassAndFail(t *testing.T) {
	policy := loadTestPolicy(t) // from decision_test.go: allows /workspace/**, denies write elsewhere, etc.

	suite, err := ParseTestSuite([]byte(`
version: 1
cases:
  - name: "correct expectation"
    action: {type: fs_write, path: /workspace/main.go}
    want: allow
  - name: "wrong expectation on purpose"
    action: {type: fs_write, path: /etc/passwd}
    want: allow
`))
	if err != nil {
		t.Fatalf("ParseTestSuite: %v", err)
	}

	results := RunTestSuite(policy, suite)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Pass {
		t.Errorf("expected case 0 to pass, got %+v", results[0])
	}
	if results[1].Pass {
		t.Errorf("expected case 1 to fail (policy denies, case wants allow), got %+v", results[1])
	}
	if results[1].Got.Result != Deny {
		t.Errorf("expected actual decision Deny, got %s", results[1].Got.Result)
	}
}

func TestLoadTestSuiteMissingFile(t *testing.T) {
	_, err := LoadTestSuite("/nonexistent/traces.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
