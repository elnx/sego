package sego

import "regexp"

// RBACRuleQuery searches role allow and role_transition rules.
//
// Role criteria are resolved by name. A role_transition target is always a
// type in a kernel policy, so a target name is resolved as a type or attribute
// first and only then as a role, mirroring setools; a rule can therefore never
// match a role-typed target criterion.
type RBACRuleQuery struct {
	policy *Policy

	ruletypes map[RuleType]bool

	source        *Role
	sourcePattern *regexp.Regexp
	target        *Type
	targetRole    *Role
	targetPattern *regexp.Regexp
	classes       map[*Class]bool
	classPattern  *regexp.Regexp
	def           *Role
	defPattern    *regexp.Regexp
}

// NewRBACRuleQuery returns a query over p with no criteria set.
func NewRBACRuleQuery(p *Policy) *RBACRuleQuery {
	return &RBACRuleQuery{policy: p}
}

// SetRuletypes limits the query to the given rule types. No rule types means
// every rule type.
func (q *RBACRuleQuery) SetRuletypes(types ...RuleType) {
	q.ruletypes = make(map[RuleType]bool, len(types))
	for _, t := range types {
		q.ruletypes[t] = true
	}
}

// SetSource matches the role allow or role_transition source role.
func (q *RBACRuleQuery) SetSource(name string, regex bool) error {
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.sourcePattern, q.source = pattern, nil
		return nil
	}
	role, err := q.policy.RoleByName(name)
	if err != nil {
		return err
	}
	q.source, q.sourcePattern = role, nil
	return nil
}

// SetTarget matches the rule target: a type or attribute for role_transition
// rules, a role for role allow rules.
func (q *RBACRuleQuery) SetTarget(name string, regex bool) error {
	q.target, q.targetRole, q.targetPattern = nil, nil, nil
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.targetPattern = pattern
		return nil
	}
	if t, err := q.policy.TypeByName(name); err == nil {
		q.target = t
		return nil
	}
	role, err := q.policy.RoleByName(name)
	if err != nil {
		return err
	}
	q.targetRole = role
	return nil
}

// SetClasses matches rules with any of the named object classes. Role allow
// rules have no class, so they never match a class criterion.
func (q *RBACRuleQuery) SetClasses(names []string) error {
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
func (q *RBACRuleQuery) SetClassPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	q.classPattern, q.classes = re, nil
	return nil
}

// SetDefault matches the new role of role_transition rules.
func (q *RBACRuleQuery) SetDefault(name string, regex bool) error {
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.defPattern, q.def = pattern, nil
		return nil
	}
	role, err := q.policy.RoleByName(name)
	if err != nil {
		return err
	}
	q.def, q.defPattern = role, nil
	return nil
}

// Results runs the query.
func (q *RBACRuleQuery) Results() []Rule {
	var out []Rule
	for _, rule := range q.policy.RBACRules() {
		if q.matches(rule) {
			out = append(out, rule)
		}
	}
	return out
}

func (q *RBACRuleQuery) matches(rule Rule) bool {
	if q.ruletypes != nil && !q.ruletypes[rule.Kind()] {
		return false
	}
	switch r := rule.(type) {
	case *RoleAllowRule:
		return q.matchesRoleAllow(r)
	case *RoleTransitionRule:
		return q.matchesRoleTransition(r)
	}
	return false
}

func (q *RBACRuleQuery) matchesRoleAllow(r *RoleAllowRule) bool {
	if !q.matchSource(r.Source) || !q.matchRoleTarget(r.Target) {
		return false
	}
	// Role allow rules have no object class and no default, so class and
	// default criteria drop them.
	if q.classes != nil || q.classPattern != nil {
		return false
	}
	if q.def != nil || q.defPattern != nil {
		return false
	}
	return true
}

func (q *RBACRuleQuery) matchesRoleTransition(r *RoleTransitionRule) bool {
	if !q.matchSource(r.Source) || !q.matchTypeTarget(r.Target) {
		return false
	}
	if !q.matchClass(r.Class) {
		return false
	}
	if q.defPattern != nil {
		return q.defPattern.MatchString(r.Default.Name)
	}
	if q.def != nil {
		return r.Default == q.def
	}
	return true
}

func (q *RBACRuleQuery) matchSource(source *Role) bool {
	if q.sourcePattern != nil {
		return q.sourcePattern.MatchString(source.Name)
	}
	if q.source != nil {
		return source == q.source
	}
	return true
}

func (q *RBACRuleQuery) matchTypeTarget(target *Type) bool {
	if q.targetPattern != nil {
		return q.targetPattern.MatchString(target.Name)
	}
	if q.targetRole != nil {
		// The criterion resolved to a role, which cannot equal a type.
		return false
	}
	if q.target != nil {
		return target == q.target
	}
	return true
}

func (q *RBACRuleQuery) matchRoleTarget(target *Role) bool {
	if q.targetPattern != nil {
		return q.targetPattern.MatchString(target.Name)
	}
	if q.target != nil {
		return false
	}
	if q.targetRole != nil {
		return target == q.targetRole
	}
	return true
}

func (q *RBACRuleQuery) matchClass(class *Class) bool {
	if q.classPattern != nil {
		return q.classPattern.MatchString(class.Name)
	}
	if q.classes != nil {
		return q.classes[class]
	}
	return true
}
