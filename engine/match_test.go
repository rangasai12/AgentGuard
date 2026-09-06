package engine

import "testing"

func TestMatchPathGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/workspace/**", "/workspace/a/b/c.go", true},
		{"/workspace/**", "/workspace", true},
		{"/workspace/**", "/workspace/", true},
		{"/workspace/**", "/etc/passwd", false},
		{"/workspace/*.go", "/workspace/main.go", true},
		{"/workspace/*.go", "/workspace/sub/main.go", false}, // single * doesn't cross '/'
		{"**", "/anything/at/all", true},
	}
	for _, c := range cases {
		got := matchPathGlob(c.pattern, c.path)
		if got != c.want {
			t.Errorf("matchPathGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatchAnyGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"rm -rf *", "rm -rf /workspace/build", true},
		{"rm -rf *", "rm -rf", false}, // pattern requires a trailing space + something after '*': "rm -rf " + anything
		{"git *", "git commit -am wip", true},
		{"curl * | sh*", "curl http://x | sh -s", true},
		{"curl * | sh*", "curl http://x", false},
	}
	for _, c := range cases {
		got := matchAnyGlob(c.pattern, c.s)
		if got != c.want {
			t.Errorf("matchAnyGlob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GITHUB.COM", true},
		{"api.github.com", "evil.com", false},
		{"*.githubusercontent.com", "raw.githubusercontent.com", true},
		{"*.githubusercontent.com", "githubusercontent.com", true},
		{"*.githubusercontent.com", "notgithubusercontent.com", false},
	}
	for _, c := range cases {
		got := matchDomain(c.pattern, c.host)
		if got != c.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestIsIPLiteral(t *testing.T) {
	if !isIPLiteral("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be an IP literal")
	}
	if !isIPLiteral("::1") {
		t.Error("expected ::1 to be an IP literal")
	}
	if isIPLiteral("api.github.com") {
		t.Error("expected hostname to not be an IP literal")
	}
}
