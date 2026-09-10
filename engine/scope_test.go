package engine

import "testing"

func TestScopeKey(t *testing.T) {
	cases := []struct {
		typ  ActionType
		res  string
		want string
	}{
		{ActionFSRead, "/workspace/docs/a.md", "fs_read:/workspace/docs/"},
		{ActionFSRead, "/workspace/docs/b.md", "fs_read:/workspace/docs/"},
		{ActionFSWrite, "/Users/dev/.aws/credentials", "fs_write:/Users/dev/.aws/"},
		{ActionFSRead, "/etc/passwd", "fs_read:/etc/"},
		{ActionFSRead, "/toplevel", "fs_read:/"},
		{ActionFSRead, "/", "fs_read:/"},
		{ActionFSRead, "relative.txt", "fs_read:."},
		{ActionFSRead, "", "fs_read:"},
		{ActionShell, "curl -X POST https://x", "shell:curl"},
		{ActionShell, "  rm -rf /tmp/x", "shell:rm"},
		{ActionShell, "", "shell:"},
		{ActionNetwork, "GET api.stripe.com", "network:GET api.stripe.com"},
		{ActionMCPTool, "crm.update_customer", "mcp_tool:crm.update_customer"},
		{ActionFunction, "send_email", "function:send_email"},
		{ActionSecretEnv, "AWS_SECRET", "secret_env:AWS_SECRET"},
	}
	for _, c := range cases {
		if got := ScopeKey(c.typ, c.res); got != c.want {
			t.Errorf("ScopeKey(%s, %q) = %q, want %q", c.typ, c.res, got, c.want)
		}
	}
}
