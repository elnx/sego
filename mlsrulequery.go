package sego

import (
	"errors"
	"regexp"
)

// RangeMatchMode selects how an MLS range criterion is compared against a
// rule's range. The default is an exact match; the other modes mirror setools'
// range query flags.
type RangeMatchMode int

// Range match modes.
const (
	RangeExact RangeMatchMode = iota
	RangeOverlap
	RangeSubset
	RangeSuperset
)

// MLSRuleQuery searches range_transition rules.
type MLSRuleQuery struct {
	policy *Policy

	ruletypes map[RuleType]bool

	source         *Type
	sourcePattern  *regexp.Regexp
	sourceIndirect bool
	target         *Type
	targetPattern  *regexp.Regexp
	targetIndirect bool
	classes        map[*Class]bool
	classPattern   *regexp.Regexp
	def            *Range
	mode           RangeMatchMode
	proper         bool
}

// NewMLSRuleQuery returns a query over p with no criteria set.
func NewMLSRuleQuery(p *Policy) *MLSRuleQuery {
	return &MLSRuleQuery{policy: p}
}

// SetRuletypes limits the query to the given rule types. No rule types means
// every rule type.
func (q *MLSRuleQuery) SetRuletypes(types ...RuleType) {
	q.ruletypes = make(map[RuleType]bool, len(types))
	for _, t := range types {
		q.ruletypes[t] = true
	}
}

// SetSource matches the rule source with the same semantics as TERuleQuery.
func (q *MLSRuleQuery) SetSource(name string, indirect, regex bool) error {
	q.sourceIndirect = indirect
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.sourcePattern, q.source = pattern, nil
		return nil
	}
	t, err := q.policy.TypeByName(name)
	if err != nil {
		return err
	}
	q.source, q.sourcePattern = t, nil
	return nil
}

// SetTarget matches the rule target with the same semantics as TERuleQuery.
func (q *MLSRuleQuery) SetTarget(name string, indirect, regex bool) error {
	q.targetIndirect = indirect
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.targetPattern, q.target = pattern, nil
		return nil
	}
	t, err := q.policy.TypeByName(name)
	if err != nil {
		return err
	}
	q.target, q.targetPattern = t, nil
	return nil
}

// SetClasses matches rules with any of the named object classes.
func (q *MLSRuleQuery) SetClasses(names []string) error {
	q.classes, q.classPattern = nil, nil
	if len(names) == 0 {
		return nil
	}
	classes := make(map[*Class]bool, len(names))
	for _, name := range names {
		c, err := q.policy.ClassByName(name)
		if err != nil {
			return err
		}
		classes[c] = true
	}
	q.classes = classes
	return nil
}

// SetClassPattern matches rules whose object class name matches the regular
// expression.
func (q *MLSRuleQuery) SetClassPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	q.classPattern, q.classes = re, nil
	return nil
}

// SetRange matches the rule's default range. The range text is resolved
// against the policy, e.g. "s0:c0.c3" or "s0:c0 - s3:c1".
func (q *MLSRuleQuery) SetRange(text string) error {
	if !q.policy.MLS() {
		// A range needs MLS symbols, so a policy compiled without MLS
		// cannot answer the criterion at all.
		return errors.New("MLS is not enabled in this policy")
	}
	rng, err := q.policy.ParseRange(text)
	if err != nil {
		return err
	}
	q.def = rng
	return nil
}

// SetRangeMatchMode selects how ranges are compared. RangeSuperset with proper
// set requires a proper superset, as setools does.
func (q *MLSRuleQuery) SetRangeMatchMode(mode RangeMatchMode, proper bool) {
	q.mode, q.proper = mode, proper
}

// Results runs the query.
func (q *MLSRuleQuery) Results() []Rule {
	var out []Rule
	for _, rule := range q.policy.MLSRules() {
		if q.matches(rule) {
			out = append(out, rule)
		}
	}
	return out
}

func (q *MLSRuleQuery) matches(rule Rule) bool {
	if q.ruletypes != nil && !q.ruletypes[rule.Kind()] {
		return false
	}
	r, ok := rule.(*MLSRule)
	if !ok {
		return false
	}
	if q.source != nil || q.sourcePattern != nil {
		if !matchIndirect(r.Source, q.source, q.sourceIndirect, q.sourcePattern) {
			return false
		}
	}
	if q.target != nil || q.targetPattern != nil {
		if !matchIndirect(r.Target, q.target, q.targetIndirect, q.targetPattern) {
			return false
		}
	}
	if q.classPattern != nil {
		if !q.classPattern.MatchString(r.Class.Name) {
			return false
		}
	} else if q.classes != nil && !q.classes[r.Class] {
		return false
	}
	if q.def != nil {
		var subset, overlap, superset bool
		switch q.mode {
		case RangeOverlap:
			overlap = true
		case RangeSubset:
			subset = true
		case RangeSuperset:
			superset = true
		}
		if !matchRange(r.Default, q.def, subset, overlap, superset, q.proper) {
			return false
		}
	}
	return true
}
