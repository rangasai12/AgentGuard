package engine

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

// globCache memoizes compiled glob patterns since the same policy rules are
// evaluated repeatedly (once per action) for the lifetime of a daemon/proxy process.
var globCache sync.Map // map[string]*regexp.Regexp

// matchPathGlob reports whether path matches a glob pattern where "**" matches any
// number of path segments (including zero) and a single "*" matches within one
// segment only. Both pattern and path are compared as slash-separated segments so
// that "/workspace/**" matches "/workspace" itself as well as anything beneath it.
// Callers must pass an already-cleaned path (see path.Clean) — this function does
// no traversal normalization itself.
func matchPathGlob(pattern, path string) bool {
	patSegs := splitPathSegs(pattern)
	pathSegs := splitPathSegs(path)
	return matchSegs(patSegs, pathSegs)
}

func splitPathSegs(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// matchSegs recursively matches pattern segments against path segments, where a
// "**" segment matches zero or more remaining path segments.
func matchSegs(pat, path []string) bool {
	if len(pat) == 0 {
		return len(path) == 0
	}
	if pat[0] == "**" {
		if len(pat) == 1 {
			return true
		}
		for i := 0; i <= len(path); i++ {
			if matchSegs(pat[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if !compileGlob(pat[0], false).MatchString(path[0]) {
		return false
	}
	return matchSegs(pat[1:], path[1:])
}

// matchAnyGlob reports whether s matches a glob pattern where "*" matches any
// sequence of characters, including spaces and path separators. Used for shell
// command patterns, which are not path-structured.
func matchAnyGlob(pattern, s string) bool {
	re := compileGlob(pattern, true)
	return re.MatchString(s)
}

// compileGlob compiles a single glob fragment to a regexp. When
// starCrossesSegments is true, "*" matches any sequence of characters
// (used for shell command patterns). When false, "*" matches within a single
// path segment only — callers in that mode always pass one path segment at a
// time (see matchSegs), so "**" as a whole segment is handled by the caller,
// not by this function.
func compileGlob(pattern string, starCrossesSegments bool) *regexp.Regexp {
	key := "path:" + pattern
	if starCrossesSegments {
		key = "any:" + pattern
	}
	if v, ok := globCache.Load(key); ok {
		return v.(*regexp.Regexp)
	}

	var b strings.Builder
	b.WriteString("^")
	for _, c := range pattern {
		switch {
		case c == '*':
			if starCrossesSegments {
				b.WriteString(".*")
			} else {
				b.WriteString("[^/]*")
			}
		case c == '?':
			if starCrossesSegments {
				b.WriteString(".")
			} else {
				b.WriteString("[^/]")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	globCache.Store(key, re)
	return re
}

// matchDomain reports whether host matches a policy domain pattern: an exact
// match, or a "*.example.com" pattern matching example.com and any subdomain.
// Comparison is case-insensitive.
func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return pattern == host
}

// isIPLiteral reports whether host is a raw IPv4/IPv6 address rather than a hostname.
func isIPLiteral(host string) bool {
	return net.ParseIP(host) != nil
}

// methodAllowed reports whether method is permitted by a rule's method list.
// An empty list means "all methods".
func methodAllowed(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// fsAccessCovers reports whether a rule's access mode (read/write/read_write)
// covers the requested action type.
func fsAccessCovers(access string, actionType ActionType) bool {
	switch access {
	case "read_write":
		return actionType == ActionFSRead || actionType == ActionFSWrite
	case "read":
		return actionType == ActionFSRead
	case "write":
		return actionType == ActionFSWrite
	}
	return false
}
