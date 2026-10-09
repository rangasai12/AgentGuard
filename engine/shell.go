package engine

import (
	"fmt"
	"path"
	"strings"
)

// shellCommand is one command found inside a shell command line, in the two
// forms evaluateShell matches against. allow is the command's own text
// (leading shell keywords like `then`/`do` removed) — what an allow pattern
// has to cover. deny adds normalized variants a deny pattern should also
// catch: quotes removed (`r"m" -rf /`), the program's directory dropped
// (`/bin/rm`), and wrapper programs stripped (`sudo`, `env X=1`, `xargs`,
// `nohup`, ...). Deny matches any form; allow only the literal one, so
// `sudo git push` still needs a pattern that allows sudo.
type shellCommand struct {
	allow string
	deny  []string
}

// maxShellDepth bounds recursion through `bash -c`, `eval` and `$(...)`, so a
// pathologically nested command fails closed instead of recursing forever.
const maxShellDepth = 8

// parseShellCommands splits a shell command line into every command it would
// run: across `;`, `&&`, `||`, `|`, `&`, newlines and `( )` subshells, inside
// `$(...)`, backticks and `<(...)`, and through `sh -c '...'` and `eval`. It
// never expands or runs anything. An error (an unclosed quote or paren, or
// nesting past maxShellDepth) means the line can't be read reliably, and the
// caller denies it.
func parseShellCommands(line string) ([]shellCommand, error) {
	return parseShellDepth(line, 0)
}

func parseShellDepth(line string, depth int) ([]shellCommand, error) {
	if depth > maxShellDepth {
		return nil, fmt.Errorf("nested more than %d levels deep", maxShellDepth)
	}
	segs, subs, err := splitShell(line)
	if err != nil {
		return nil, err
	}
	var out []shellCommand
	for _, seg := range segs {
		text := stripShellKeywords(seg)
		if text == "" {
			continue
		}
		words, err := shellWords(text)
		if err != nil {
			return nil, err
		}
		if len(words) == 0 || shellNonCommand[words[0]] {
			continue
		}
		cmd := shellCommand{allow: text}
		addForm := func(f string) {
			for _, have := range cmd.deny {
				if have == f {
					return
				}
			}
			cmd.deny = append(cmd.deny, f)
		}
		addForm(text)
		addForm(strings.Join(words, " "))
		inner := unwrapShellCommand(words)
		if len(inner) > 0 {
			inner[0] = path.Base(inner[0])
			addForm(strings.Join(inner, " "))
		}
		out = append(out, cmd)

		if script, ok := nestedShellScript(inner); ok {
			nested, err := parseShellDepth(script, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
		}
	}
	for _, sub := range subs {
		nested, err := parseShellDepth(sub, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, nested...)
	}
	return out, nil
}

// splitShell cuts line into top-level command segments and returns, separately,
// the bodies of every command substitution it contains (`$(...)`, backticks,
// `<(...)`/`>(...)`), which the caller parses recursively. Substitutions are
// also left in place in their segment's text, so the outer command is still
// judged as written.
func splitShell(line string) (segs, subs []string, err error) {
	var cur strings.Builder
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			segs = append(segs, t)
		}
		cur.Reset()
	}
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
			cur.WriteByte(c)
			continue
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(c)
			cur.WriteByte(line[i+1])
			i++
			continue
		case c == '\'' && !inDouble:
			inSingle = true
			cur.WriteByte(c)
			continue
		case c == '"':
			inDouble = !inDouble
			cur.WriteByte(c)
			continue
		case c == '`':
			end := closingBacktick(line, i+1)
			if end < 0 {
				return nil, nil, fmt.Errorf("unclosed backtick")
			}
			subs = append(subs, line[i+1:end])
			cur.WriteString(line[i : end+1])
			i = end
			continue
		case i+1 < len(line) && line[i+1] == '(' && (c == '$' || (!inDouble && (c == '<' || c == '>'))):
			end := closingParen(line, i+1)
			if end < 0 {
				return nil, nil, fmt.Errorf("unclosed %q", line[i:i+2])
			}
			subs = append(subs, line[i+2:end])
			cur.WriteString(line[i : end+1])
			i = end
			continue
		case inDouble:
			cur.WriteByte(c)
			continue
		}
		switch c {
		case ';', '\n', '(', ')':
			flush()
		case '|':
			flush()
			if i+1 < len(line) && (line[i+1] == '|' || line[i+1] == '&') {
				i++
			}
		case '&':
			switch {
			case i+1 < len(line) && line[i+1] == '&':
				flush()
				i++
			case (i > 0 && (line[i-1] == '>' || line[i-1] == '<')) || (i+1 < len(line) && line[i+1] == '>'):
				cur.WriteByte(c) // a redirection: 2>&1, &>file
			default:
				flush() // a background job: `a & b` runs both
			}
		default:
			cur.WriteByte(c)
		}
	}
	if inSingle || inDouble {
		return nil, nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return segs, subs, nil
}

// closingBacktick returns the index of the backtick closing one opened just
// before from, or -1.
func closingBacktick(s string, from int) int {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '`':
			return i
		}
	}
	return -1
}

// closingParen returns the index of the ')' matching the '(' at open,
// skipping quoted text and nested parens, or -1.
func closingParen(s string, open int) int {
	depth := 0
	inSingle, inDouble := false, false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case c == '\\':
			i++
		case c == '\'' && !inDouble:
			inSingle = true
		case c == '"':
			inDouble = !inDouble
		case inDouble:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// shellWords splits one command segment into words the way the shell would,
// removing quotes and backslash escapes, without expanding anything.
func shellWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, inSingle, inDouble := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`\n", s[i+1]) >= 0 {
				cur.WriteByte(s[i+1])
				i++
			} else {
				cur.WriteByte(c)
			}
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			inSingle, inWord = true, true
		case c == '"':
			inDouble, inWord = true, true
		case c == '\\':
			if i+1 < len(s) {
				cur.WriteByte(s[i+1])
				i++
			}
			inWord = true
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unclosed quote")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// shellKeywords are reserved words that can open a segment without being a
// command themselves (`if x; then rm -rf /; fi` puts `rm` after `then`).
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true,
}

// shellNonCommand are segment-opening words whose segment runs nothing by
// itself: closers, and loop/case headers whose bodies are their own segments
// (any `$(...)` in a header is still parsed, as a substitution).
var shellNonCommand = map[string]bool{
	"fi": true, "done": true, "esac": true, "}": true,
	"for": true, "select": true, "case": true,
}

// stripShellKeywords removes leading shell keywords from a segment's text.
func stripShellKeywords(seg string) string {
	for {
		seg = strings.TrimSpace(seg)
		word, rest, _ := strings.Cut(seg, " ")
		if !shellKeywords[word] {
			return seg
		}
		seg = rest
	}
}

// shellWrapperFlagsWithArg lists, per wrapper program, the flags that take a
// separate argument, so `sudo -u root rm -rf /` unwraps to `rm -rf /`.
var shellWrapperFlagsWithArg = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-C": true, "-p": true, "-h": true, "-U": true, "-D": true, "-r": true, "-t": true},
	"doas":    {"-u": true, "-C": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"nice":    {"-n": true},
	"nohup":   {},
	"time":    {},
	"command": {},
	"exec":    {"-a": true},
	"builtin": {},
	"stdbuf":  {},
	"timeout": {"-s": true, "-k": true},
	"xargs":   {"-I": true, "-n": true, "-P": true, "-L": true, "-s": true, "-d": true, "-E": true, "-a": true},
}

// unwrapShellCommand strips leading VAR=value assignments and wrapper
// programs (with their flags) to reach the command that actually runs.
func unwrapShellCommand(words []string) []string {
	out := append([]string(nil), words...)
	for len(out) > 0 {
		w := out[0]
		if isShellAssignment(w) {
			out = out[1:]
			continue
		}
		name := path.Base(w)
		withArg, ok := shellWrapperFlagsWithArg[name]
		if !ok {
			return out
		}
		out = out[1:]
		for len(out) > 0 && strings.HasPrefix(out[0], "-") {
			flag := out[0]
			out = out[1:]
			if flag == "--" {
				break
			}
			if withArg[flag] && len(out) > 0 {
				out = out[1:]
			}
		}
		if name == "timeout" && len(out) > 0 {
			out = out[1:] // the duration
		}
	}
	return out
}

func isShellAssignment(w string) bool {
	name, _, ok := strings.Cut(w, "=")
	if !ok || name == "" {
		return false
	}
	for i, c := range name {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

var shellInterpreters = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}

// nestedShellScript returns the script a command hands to another shell:
// the argument of `sh -c` (or `bash -lc`, ...), or everything after `eval`.
func nestedShellScript(words []string) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	name := path.Base(words[0])
	if name == "eval" {
		return strings.Join(words[1:], " "), len(words) > 1
	}
	if !shellInterpreters[name] {
		return "", false
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") || strings.HasPrefix(w, "--") {
			continue
		}
		if strings.Contains(w, "c") && i+1 < len(words) {
			return words[i+1], true
		}
	}
	return "", false
}
