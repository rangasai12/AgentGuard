package cli

import (
	"flag"
	"fmt"
	"io"

	"agentguard/daemon"
)

func runApproveOrDeny(args []string, stdout, stderr io.Writer, cmd string) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", DefaultSocketPath(), "unix socket path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(stderr, "usage: agentctl %s <id>\n", cmd)
		return 2
	}

	client, err := Dial(*socketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()

	resp, err := client.Call(daemon.Request{Cmd: cmd, ID: rest[0]})
	if err != nil {
		fmt.Fprintf(stderr, "agentctl %s: %v\n", cmd, err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "agentctl %s: %s\n", cmd, resp.Error)
		return 1
	}
	verb := "approved"
	if cmd == "deny" {
		verb = "denied"
	}
	fmt.Fprintf(stdout, "%s %s\n", verb, rest[0])
	return 0
}
