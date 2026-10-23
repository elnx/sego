package sego

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// TERuleQuery searches type enforcement rules: allow, auditallow, dontaudit,
// allowxperm, auditallowxperm, dontauditxperm, type_transition, type_change and
// type_member.
//
// A criterion that is not set matches everything. Criteria are resolved when
// they are set, so lookup errors are reported by the setter, and matching
// happens in Results.
type TERuleQuery struct {
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
	perms          []string
	permsEqual     bool
	permsSubset    bool
	xperms         *XPermSet
	xpermsEqual    bool
	def            *Type
	defPattern     *regexp.Regexp
	booleans       map[*Boolean]bool
	booleanPattern *regexp.Regexp
	booleanEqual   bool
}

// NewTERuleQuery returns a query over p with no criteria set.
func NewTERuleQuery(p *Policy) *TERuleQuery {
	return &TERuleQuery{policy: p}
}

// SetRuletypes limits the query to the given rule types. No rule types means
// every rule type.
func (q *TERuleQuery) SetRuletypes(types ...RuleType) {
	q.ruletypes = make(map[RuleType]bool, len(types))
	for _, t := range types {
		q.ruletypes[t] = true
	}
}

// SetSource matches the rule source. A pattern matches if any expanded type of
// the rule's source matches; a name is resolved as a type or attribute unless
// regex is set. When indirect, attributes match through their member types.
func (q *TERuleQuery) SetSource(name string, indirect, regex bool) error {
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

// SetTarget matches the rule target, with the same semantics as SetSource.
func (q *TERuleQuery) SetTarget(name string, indirect, regex bool) error {
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
func (q *TERuleQuery) SetClasses(names []string) error {
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
func (q *TERuleQuery) SetClassPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	q.classPattern, q.classes = re, nil
	return nil
}

// SetPerms matches rules that grant any of the permissions. Permissions are
// validated against the query's object classes, or against every class in the
// policy when no class criterion is set.
func (q *TERuleQuery) SetPerms(perms []string) error {
	q.perms = nil
	if len(perms) == 0 {
		return nil
	}
	if err := q.policy.validatePerms(perms, q.selectedClasses()); err != nil {
		return err
	}
	q.perms = perms
	return nil
}

// SetPermsEqual requires the rule's permissions to be exactly the criteria.
func (q *TERuleQuery) SetPermsEqual(equal bool) { q.permsEqual = equal }

// SetPermsSubset requires the criteria to be a subset of the rule's
// permissions.
func (q *TERuleQuery) SetPermsSubset(subset bool) { q.permsSubset = subset }

// SetXPerms matches extended permission rules whose permissions overlap the
// criteria, or are exactly the criteria when equal is set.
func (q *TERuleQuery) SetXPerms(xperms *XPermSet, equal bool) {
	q.xperms, q.xpermsEqual = xperms, equal
}

// SetDefault matches the default type of type_transition and type_change
// rules. Attributes always match through their member types.
func (q *TERuleQuery) SetDefault(name string, regex bool) error {
	if regex {
		pattern, err := regexp.Compile(name)
		if err != nil {
			return err
		}
		q.defPattern, q.def = pattern, nil
		return nil
	}
	t, err := q.policy.TypeByName(name)
	if err != nil {
		return err
	}
	q.def, q.defPattern = t, nil
	return nil
}

// SetBooleans matches rules inside conditionals that reference any of the
// named booleans.
func (q *TERuleQuery) SetBooleans(names []string) error {
	q.booleans, q.booleanPattern = nil, nil
	if len(names) == 0 {
		return nil
	}
	bools := make(map[*Boolean]bool, len(names))
	for _, name := range names {
		b, err := q.policy.BooleanByName(name)
		if err != nil {
			return err
		}
		bools[b] = true
	}
	q.booleans = bools
	return nil
}

// SetBooleanPattern matches rules inside conditionals that reference a boolean
// whose name matches the regular expression.
func (q *TERuleQuery) SetBooleanPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	q.booleanPattern, q.booleans = re, nil
	return nil
}

// SetBooleanEqual requires the conditional to reference exactly the criteria
// booleans.
func (q *TERuleQuery) SetBooleanEqual(equal bool) { q.booleanEqual = equal }

// selectedClasses returns the classes the permission criteria are validated
// against, or nil when the whole policy applies.
func (q *TERuleQuery) selectedClasses() []*Class {
	if q.classes == nil {
		return nil
	}
	out := make([]*Class, 0, len(q.classes))
	for c := range q.classes {
		out = append(out, c)
	}
	return out
}

// Results runs the query.
func (q *TERuleQuery) Results() []Rule {
	var out []Rule
	for _, rule := range q.policy.TERules() {
		if q.matches(rule) {
			out = append(out, rule)
		}
	}
	return out
}

func (q *TERuleQuery) matches(rule Rule) bool {
	if q.ruletypes != nil && !q.ruletypes[rule.Kind()] {
		return false
	}
	switch r := rule.(type) {
	case *AVRule:
		return q.matchesAV(r.Source, r.Target, r.Class, r.Perms, nil, nil, r.Conditional)
	case *AVRuleXperm:
		return q.matchesAV(r.Source, r.Target, r.Class, nil, r.Perms, &r.XPermType, r.Conditional)
	case *TERule:
		return q.matchesType(r.Source, r.Target, r.Class, r.Default, r.Conditional)
	case *FileNameTERule:
		return q.matchesType(r.Source, r.Target, r.Class, r.Default, nil)
	}
	return false
}

// matchesAV matches an AV rule. perms is the rule's permission set, or nil for
// extended permission rules, where xpermPerms and xpermType describe the
// rule instead.
func (q *TERuleQuery) matchesAV(source, target *Type, class *Class, perms []string,
	xpermPerms *XPermSet, xpermType *string, cond *Conditional) bool {
	if !q.matchSourceTarget(source, target) {
		return false
	}
	if q.def != nil || q.defPattern != nil {
		// Permission rules have no default type.
		return false
	}
	if !q.matchClass(class) {
		return false
	}
	if len(q.perms) > 0 {
		switch {
		case xpermType != nil:
			// Extended permission rules treat regular permission
			// criteria as the extended permission kind.
			if q.permsEqual && len(q.perms) > 1 {
				return false
			}
			if !containsString(q.perms, *xpermType) {
				return false
			}
		case perms == nil:
			// Permission criteria never match rules that carry no
			// permissions.
			return false
		case q.permsSubset:
			if !containsAll(perms, q.perms) {
				return false
			}
		case !matchRegexOrSet(perms, q.perms, q.permsEqual, nil):
			return false
		}
	}
	if q.xperms != nil {
		if perms != nil || xpermPerms == nil {
			// Rules without extended permissions never match.
			return false
		}
		if q.xpermsEqual {
			if !xpermPerms.Equal(q.xperms) {
				return false
			}
		} else if !xpermPerms.Intersects(q.xperms) {
			return false
		}
	}
	return q.matchCond(cond)
}

func (q *TERuleQuery) matchesType(source, target *Type, class *Class, def *Type, cond *Conditional) bool {
	if !q.matchSourceTarget(source, target) || !q.matchClass(class) {
		return false
	}
	if len(q.perms) > 0 {
		// Type rules carry a default type, not permissions.
		return false
	}
	if q.def != nil || q.defPattern != nil {
		if def == nil || !matchIndirect(def, q.def, true, q.defPattern) {
			return false
		}
	}
	if q.xperms != nil {
		// Only extended permission rules can match xperm criteria.
		return false
	}
	return q.matchCond(cond)
}

func (q *TERuleQuery) matchSourceTarget(source, target *Type) bool {
	if q.source != nil || q.sourcePattern != nil {
		if !matchIndirect(source, q.source, q.sourceIndirect, q.sourcePattern) {
			return false
		}
	}
	if q.target != nil || q.targetPattern != nil {
		if !matchIndirect(target, q.target, q.targetIndirect, q.targetPattern) {
			return false
		}
	}
	return true
}

func (q *TERuleQuery) matchClass(class *Class) bool {
	if q.classPattern != nil {
		return q.classPattern.MatchString(class.Name)
	}
	if q.classes != nil {
		return q.classes[class]
	}
	return true
}

func (q *TERuleQuery) matchCond(cond *Conditional) bool {
	if q.booleans == nil && q.booleanPattern == nil {
		return true
	}
	if cond == nil {
		return false
	}
	names := make([]string, 0, len(cond.bools))
	for _, b := range cond.bools {
		names = append(names, b.Name)
	}
	if q.booleanPattern != nil {
		return matchRegexOrSet(names, nil, false, q.booleanPattern)
	}
	if q.booleanEqual {
		// The conditional must reference exactly the criteria Booleans.
		if len(cond.bools) != len(q.booleans) {
			return false
		}
		for _, b := range cond.bools {
			if !q.booleans[b] {
				return false
			}
		}
		return true
	}
	for _, b := range cond.bools {
		if q.booleans[b] {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool { return slices.Contains(values, want) }

func containsAll(values, want []string) bool {
	for _, w := range want {
		if !containsString(values, w) {
			return false
		}
	}
	return true
}

// validatePerms checks that every permission exists in at least one of the
// given classes, or in any class of the policy when none are given.
func (p *Policy) validatePerms(perms []string, classes []*Class) error {
	if len(perms) == 0 {
		return nil
	}
	allClasses := classes == nil
	if allClasses {
		classes = p.classes
	}
	invalid := make(map[string]bool, len(perms))
	for _, perm := range perms {
		invalid[perm] = true
	}
	for _, c := range classes {
		for _, perm := range c.perms {
			delete(invalid, perm)
		}
		if len(invalid) == 0 {
			return nil
		}
	}
	missing := make([]string, 0, len(invalid))
	for _, perm := range perms {
		if invalid[perm] {
			missing = append(missing, perm)
		}
	}
	if allClasses {
		return fmt.Errorf("Permission(s) do not exist any class: %s", strings.Join(missing, ", "))
	}
	return fmt.Errorf("Permission(s) do not exist in the specified classes: %s", strings.Join(missing, ", "))
}
