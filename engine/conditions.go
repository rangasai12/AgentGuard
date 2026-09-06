package engine

import "fmt"

// conditionHolds reports whether the action's argument named c.Arg satisfies
// c (see ArgCondition's doc for operator semantics). A missing argument
// never satisfies any condition — it's treated the same as any other
// non-match, falling through to the next rule/default rather than erroring.
func conditionHolds(c ArgCondition, args map[string]any) bool {
	actual, ok := args[c.Arg]
	if !ok {
		return false
	}
	switch c.Op {
	case "<", "<=", ">", ">=":
		a, aok := toFloat64(actual)
		b, bok := toFloat64(c.Value)
		if !aok || !bok {
			return false // ordering only makes sense between numbers
		}
		switch c.Op {
		case "<":
			return a < b
		case "<=":
			return a <= b
		case ">":
			return a > b
		default: // ">="
			return a >= b
		}
	case "=", "==":
		return valuesEqual(actual, c.Value)
	case "!=":
		return !valuesEqual(actual, c.Value)
	default:
		return false
	}
}

// toFloat64 normalizes any Go numeric type to float64, so a condition's
// Value (decoded from YAML, which preserves whole numbers as int) can be
// compared against an action's argument (decoded from JSON over the wire,
// which represents every number as float64) without the caller having to
// care which side came from which encoding.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

// valuesEqual compares two condition operands for "="/"==="/"!=". Numbers
// compare numerically regardless of concrete Go type (so a YAML int 1000
// equals a JSON-decoded float64 1000.0); everything else (strings, bools)
// compares via its %v representation, which is exact for those types
// without a dedicated case for every scalar kind a policy or SDK might send.
func valuesEqual(a, b any) bool {
	if af, aok := toFloat64(a); aok {
		if bf, bok := toFloat64(b); bok {
			return af == bf
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
