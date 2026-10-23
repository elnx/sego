package sego

import (
	"regexp"
	"slices"
)

// Matching helpers. These mirror setools' setools/util.py so that query
// results are identical.

// matchIndirect matches a type or attribute criterion against a rule operand.
//
// When indirect, an attribute criterion matches any rule whose operand shares
// a type with the criterion's expansion (and a regular expression matches if
// any of the operand's expanded types matches). When direct, the operand
// itself is matched, so attributes only match attribute operands.
func matchIndirect(operand, criteria *Type, indirect bool, pattern *regexp.Regexp) bool {
	if indirect {
		if pattern != nil {
			for _, t := range operand.Expand() {
				if pattern.MatchString(t.Name) {
					return true
				}
			}
			return false
		}
		return slices.ContainsFunc(criteria.Expand(), func(c *Type) bool {
			return slices.Contains(operand.Expand(), c)
		})
	}
	if pattern != nil {
		return pattern.MatchString(operand.Name)
	}
	return operand == criteria
}

// matchRegexOrSet implements setools' match_regex_or_set: a regular expression
// matches any element, otherwise the sets are compared for equality or
// overlap.
func matchRegexOrSet(elements []string, criteria []string, equal bool, pattern *regexp.Regexp) bool {
	if pattern != nil {
		return slices.ContainsFunc(elements, pattern.MatchString)
	}
	if equal {
		return sameStringSet(elements, criteria)
	}
	return slices.ContainsFunc(criteria, func(c string) bool { return slices.Contains(elements, c) })
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}

// matchRange implements setools' match_range for MLS range criteria. Exactly
// one of the flags is expected to be set; with none set the ranges must be
// equal.
func matchRange(obj, criteria *Range, subset, overlap, superset, proper bool) bool {
	switch {
	case overlap:
		return (lowLE(obj.Low, criteria.Low) && lowLE(criteria.Low, obj.High)) ||
			(lowLE(obj.Low, criteria.High) && lowLE(criteria.High, obj.High)) ||
			(lowLE(criteria.Low, obj.Low) && lowLE(obj.High, criteria.High))
	case subset:
		if proper {
			return (lowLT(obj.Low, criteria.Low) && lowLE(criteria.High, obj.High)) ||
				(lowLE(obj.Low, criteria.Low) && lowLT(criteria.High, obj.High))
		}
		return lowLE(obj.Low, criteria.Low) && lowLE(criteria.High, obj.High)
	case superset:
		if proper {
			return (lowLT(criteria.Low, obj.Low) && lowLE(obj.High, criteria.High)) ||
				(lowLE(criteria.Low, obj.Low) && lowLT(obj.High, criteria.High))
		}
		return lowLE(criteria.Low, obj.Low) && lowLE(obj.High, criteria.High)
	default:
		return obj.Low.sameLevel(criteria.Low) && obj.High.sameLevel(criteria.High)
	}
}

// lowLE compares two levels by sensitivity and then by category set, matching
// setools' Level ordering.
func lowLE(a, b *Level) bool { return compareLevels(a, b) <= 0 }
func lowLT(a, b *Level) bool { return compareLevels(a, b) < 0 }

func compareLevels(a, b *Level) int {
	if a.sensitivity() != b.sensitivity() {
		if a.sensitivity() < b.sensitivity() {
			return -1
		}
		return 1
	}
	ac, bc := a.categoryValues(), b.categoryValues()
	if len(ac) != len(bc) {
		if len(ac) < len(bc) {
			return -1
		}
		return 1
	}
	for i := range ac {
		if ac[i] != bc[i] {
			if ac[i] < bc[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
