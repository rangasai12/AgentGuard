package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"agentguard/daemon"
	"agentguard/engine"
	networkproxy "agentguard/proxy/network"
)

func runProxy(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl proxy <start|ca> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "start":
		return runProxyStart(rest, stdout, stderr)
	case "ca":
		return runProxyCA(rest, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: agentctl proxy <start|ca> [flags]")
		return 2
	}
}

func runProxyStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "policy.yaml", "path to the policy file")
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on")
	auditPath := fs.String("audit", DefaultAuditLogPath(), "path to the JSONL audit log")
	caCertPath := fs.String("ca-cert", DefaultCACertPath(), "path to the interception CA certificate (created if missing)")
	caKeyPath := fs.String("ca-key", DefaultCAKeyPath(), "path to the interception CA private key (created if missing)")
	actor := fs.String("actor", "", "actor name recorded in audit events")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	policy, err := engine.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: loading policy: %v\n", err)
		return 1
	}

	if err := EnsureParentDir(*caCertPath); err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: preparing CA directory: %v\n", err)
		return 1
	}
	ca, err := networkproxy.LoadOrGenerateCA(*caCertPath, *caKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: %v\n", err)
		return 1
	}

	if err := EnsureParentDir(*auditPath); err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: preparing audit log directory: %v\n", err)
		return 1
	}
	audit, err := daemon.NewAuditLogger(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: opening audit log: %v\n", err)
		return 1
	}
	defer audit.Close()

	proxy := networkproxy.New(policy, audit, ca, *actor)

	fmt.Fprintf(stdout, "agentguard network proxy listening on %s (policy: %s)\n", *addr, *policyPath)
	fmt.Fprintf(stdout, "point your client's HTTP(S)_PROXY at this address, and trust the CA certificate:\n  %s\n", *caCertPath)
	fmt.Fprintln(stdout, "(see `agentctl proxy ca` for details on trusting it). Press Ctrl-C to stop.")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := proxy.ListenAndServe(ctx, *addr); err != nil {
		fmt.Fprintf(stderr, "agentctl proxy start: %v\n", err)
		return 1
	}
	return 0
}

func runProxyCA(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	caCertPath := fs.String("ca-cert", DefaultCACertPath(), "path to the interception CA certificate (created if missing)")
	caKeyPath := fs.String("ca-key", DefaultCAKeyPath(), "path to the interception CA private key (created if missing)")
	export := fs.String("export", "", "also write the CA certificate (PEM) to this path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := EnsureParentDir(*caCertPath); err != nil {
		fmt.Fprintf(stderr, "agentctl proxy ca: preparing CA directory: %v\n", err)
		return 1
	}
	ca, err := networkproxy.LoadOrGenerateCA(*caCertPath, *caKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl proxy ca: %v\n", err)
		return 1
	}

	if *export != "" {
		if err := os.WriteFile(*export, ca.CertPEM(), 0o644); err != nil {
			fmt.Fprintf(stderr, "agentctl proxy ca: writing %s: %v\n", *export, err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote CA certificate to %s\n", *export)
	}

	fmt.Fprintf(stdout, "CA certificate: %s\n", *caCertPath)
	fmt.Fprintln(stdout, `
The network proxy intercepts HTTPS by presenting certificates signed by this
local CA, so a client must be told to trust it or every HTTPS request will
fail with a certificate error. This is NOT installed into your system trust
store automatically — that's a deliberately invasive step left to you. Common
ways to trust it for one process without touching the OS/browser trust store:

  Python (requests):      export REQUESTS_CA_BUNDLE=<ca-cert path>
  curl:                    curl --cacert <ca-cert path> ...
  Node.js:                 export NODE_EXTRA_CA_CERTS=<ca-cert path>
  Most other tools:        export SSL_CERT_FILE=<ca-cert path>

And point the client at the proxy itself:
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080`)
	return 0
}

// DefaultCACertPath returns the default path for the network proxy's
// interception CA certificate, overridable via AGENTGUARD_CA_CERT.
func DefaultCACertPath() string {
	if v := os.Getenv("AGENTGUARD_CA_CERT"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agentguard", "ca.crt")
	}
	return filepath.Join(os.TempDir(), "agentguard-ca.crt")
}

// DefaultCAKeyPath returns the default path for the network proxy's
// interception CA private key, overridable via AGENTGUARD_CA_KEY.
func DefaultCAKeyPath() string {
	if v := os.Getenv("AGENTGUARD_CA_KEY"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agentguard", "ca.key")
	}
	return filepath.Join(os.TempDir(), "agentguard-ca.key")
}
