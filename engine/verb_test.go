package engine

import "testing"

func TestHeuristicVerb(t *testing.T) {
	cases := []struct {
		actionType ActionType
		resource   string
		want       Verb
	}{
		{ActionFSRead, "/etc/hosts", VerbRead},
		{ActionFSWrite, "/workspace/a", VerbWrite},
		{ActionSecretEnv, "AWS_SECRET_ACCESS_KEY", VerbPermission},
		{ActionNetwork, "GET api.example.com", VerbRead},
		{ActionNetwork, "HEAD api.example.com", VerbRead},
		{ActionNetwork, "POST api.example.com", VerbWrite},
		{ActionNetwork, "DELETE api.example.com", VerbDelete},
		{ActionNetwork, "api.example.com", VerbUnknown}, // no method prefix
		{ActionShell, "rm -rf /tmp/x", VerbDelete},
		{ActionShell, "cat file.txt", VerbRead},
		{ActionShell, "git commit -m x", VerbWrite},
		{ActionShell, "chmod 700 x", VerbPermission},
		{ActionShell, "some-random-binary --flag", VerbUnknown},
		{ActionShell, "", VerbUnknown},
		{ActionMCPTool, "crm.lookup_customer", VerbRead},
		{ActionMCPTool, "crm.delete_customer", VerbDelete},
		{ActionMCPTool, "crm.update_customer", VerbWrite},
		{ActionMCPTool, "crm.grant_access", VerbPermission},
		{ActionMCPTool, "crm.frobnicate", VerbUnknown},
		{ActionFunction, "scale_service", VerbWrite},
		{ActionFunction, "revoke_access", VerbPermission},
	}
	for _, c := range cases {
		if got := HeuristicVerb(c.actionType, c.resource); got != c.want {
			t.Errorf("HeuristicVerb(%q, %q) = %q, want %q", c.actionType, c.resource, got, c.want)
		}
	}
}
