package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const starterPolicyTemplate = `version: 1
name: my-agent-policy

# Start narrow and widen deliberately. Unlisted actions are denied by
# default (except secrets, see policy-spec/schema.yaml) — see that file for
# the full DSL reference and precedence rules.

filesystem:
  - allow: read_write
    paths: ["./workspace/**"]
  - deny: write
    paths: ["**"]
    reason: "writes outside ./workspace are never allowed"

network:
  default: deny
  allow: []
  # - domain: "api.example.com"
  #   methods: ["GET"]

shell:
  default: deny
  allow: []
  # - pattern: "git *"

escalation:
  approval_timeout_seconds: 300
  on_timeout: deny
`

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "policy.yaml", "path to write the starter policy to")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if _, err := os.Stat(*output); err == nil {
		fmt.Fprintf(stderr, "agentctl init: refusing to overwrite existing file %s\n", *output)
		return 1
	}
	if err := os.WriteFile(*output, []byte(starterPolicyTemplate), 0o644); err != nil {
		fmt.Fprintf(stderr, "agentctl init: writing %s: %v\n", *output, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote starter policy to %s\n", *output)
	return 0
}
