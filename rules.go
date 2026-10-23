package sego

import (
	"fmt"
	"sort"
	"strings"

	"github.com/elnx/sego/policy"
)

// RuleType identifies a rule kind. The values are the policy avtab rule
// specifiers, so rule type sets can be expressed as bit masks.
type RuleType uint16

// Rule types, mirroring setools' TERuletype, RBACRuletype and MLSRuletype.
const (
	Allow           RuleType = policy.AVTabAllow
	AuditAllow      RuleType = policy.AVTabAuditAllow
	DontAudit       RuleType = policy.AVTabAuditDeny
	NeverAllow      RuleType = policy.AVTabNeverAllow
	AllowXPerm      RuleType = policy.AVTabXPermsAllowed
	AuditAllowXPerm RuleType = policy.AVTabXPermsAudit
	DontAuditXPerm  RuleType = policy.AVTabXPermsDontAudit
	NeverAllowXPerm RuleType = policy.AVTabXPermsNever
	TypeTransition  RuleType = policy.AVTabTransition
	TypeMember      RuleType = policy.AVTabMember
	TypeChange      RuleType = policy.AVTabChange
)

// Rule types for the RBAC and MLS rule families, which do not come from the
// avtab and so need values of their own.
const (
	RuleRoleAllow       RuleType = 0x1000
	RuleRoleTransition  RuleType = 0x2000
	RuleRangeTransition RuleType = 0x4000
)

var ruleTypeNames = map[RuleType]string{
	Allow:               "allow",
	AuditAllow:          "auditallow",
	DontAudit:           "dontaudit",
	NeverAllow:          "neverallow",
	AllowXPerm:          "allowxperm",
	AuditAllowXPerm:     "auditallowxperm",
	DontAuditXPerm:      "dontauditxperm",
	NeverAllowXPerm:     "neverallowxperm",
	TypeTransition:      "type_transition",
	TypeMember:          "type_member",
	TypeChange:          "type_change",
	RuleRoleAllow:       "allow",
	RuleRoleTransition:  "role_transition",
	RuleRangeTransition: "range_transition",
}

// String returns the rule type keyword used in policy statements.
func (rt RuleType) String() string {
	if name, ok := ruleTypeNames[rt]; ok {
		return name
	}
	return fmt.Sprintf("<unknown rule type %#x>", uint16(rt))
}

// Rule is a policy rule: it renders itself as a policy statement.
type Rule interface {
	// Kind returns the rule kind.
	Kind() RuleType
	// String renders the rule as a policy statement.
	String() string
}

// AVRule is an allow, auditallow, dontaudit or neverallow rule.
type AVRule struct {
	Ruletype RuleType

	Source *Type
	Target *Type
	Class  *Class
	Perms  []string

	Conditional      *Conditional
	ConditionalBlock bool

	statement string
}

// AVRuleXperm is an allowxperm, auditallowxperm, dontauditxperm or
// neverallowxperm rule.
type AVRuleXperm struct {
	Ruletype RuleType

	Source *Type
	Target *Type
	Class  *Class

	// XPermType is the extended permission kind: "ioctl" or "nlmsg".
	XPermType string
	Perms     *XPermSet

	Conditional      *Conditional
	ConditionalBlock bool

	statement string
}

// TERule is a type_transition, type_change or type_member rule from the avtab.
type TERule struct {
	Ruletype RuleType

	Source  *Type
	Target  *Type
	Class   *Class
	Default *Type

	Conditional      *Conditional
	ConditionalBlock bool

	statement string
}

// FileNameTERule is a filename based type_transition rule.
type FileNameTERule struct {
	Source   *Type
	Target   *Type
	Class    *Class
	Default  *Type
	Filename string

	statement string
}

// RoleAllowRule is a role allow rule.
type RoleAllowRule struct {
	Source *Role
	Target *Role

	statement string
}

// RoleTransitionRule is a role_transition rule.
type RoleTransitionRule struct {
	Source  *Role
	Target  *Type
	Class   *Class
	Default *Role

	statement string
}

// MLSRule is a range_transition rule.
type MLSRule struct {
	Ruletype RuleType

	Source  *Type
	Target  *Type
	Class   *Class
	Default *Range

	statement string
}

// Ruletype returns the rule kind.
func (r *AVRule) Kind() RuleType             { return r.Ruletype }
func (r *AVRuleXperm) Kind() RuleType        { return r.Ruletype }
func (r *TERule) Kind() RuleType             { return r.Ruletype }
func (r *FileNameTERule) Kind() RuleType     { return TypeTransition }
func (r *RoleAllowRule) Kind() RuleType      { return RuleRoleAllow }
func (r *RoleTransitionRule) Kind() RuleType { return RuleRoleTransition }
func (r *MLSRule) Kind() RuleType            { return r.Ruletype }

// String renders the rule as a policy statement, exactly as setools does.
func (r *AVRule) String() string {
	if r.statement != "" {
		return r.statement
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s:%s ", r.Ruletype, r.Source, r.Target, r.Class)
	b.WriteString(formatPerms(r.Perms, ";"))
	if r.Conditional != nil {
		fmt.Fprintf(&b, " [ %s ]:%s", r.Conditional, pyBool(r.ConditionalBlock))
	}
	r.statement = b.String()
	return r.statement
}

// String renders the rule as a policy statement. Extended permission rules
// never carry the conditional suffix, which matches setools.
func (r *AVRuleXperm) String() string {
	if r.statement != "" {
		return r.statement
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s:%s %s ", r.Ruletype, r.Source, r.Target, r.Class, r.XPermType)
	if r.Perms.Ranges() > 1 {
		fmt.Fprintf(&b, "{ %s };", r.Perms)
	} else {
		fmt.Fprintf(&b, "%s;", r.Perms)
	}
	r.statement = b.String()
	return r.statement
}

// String renders the rule as a policy statement.
func (r *TERule) String() string {
	if r.statement != "" {
		return r.statement
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s:%s %s;", r.Ruletype, r.Source, r.Target, r.Class, r.Default)
	if r.Conditional != nil {
		fmt.Fprintf(&b, " [ %s ]:%s", r.Conditional, pyBool(r.ConditionalBlock))
	}
	r.statement = b.String()
	return r.statement
}

// String renders the rule as a policy statement.
func (r *FileNameTERule) String() string {
	if r.statement != "" {
		return r.statement
	}
	r.statement = fmt.Sprintf("%s %s %s:%s %s %s;",
		TypeTransition, r.Source, r.Target, r.Class, r.Default, r.Filename)
	return r.statement
}

// String renders the rule as a policy statement.
func (r *RoleAllowRule) String() string {
	if r.statement != "" {
		return r.statement
	}
	r.statement = fmt.Sprintf("%s %s %s;", RuleRoleAllow, r.Source, r.Target)
	return r.statement
}

// String renders the rule as a policy statement.
func (r *RoleTransitionRule) String() string {
	if r.statement != "" {
		return r.statement
	}
	r.statement = fmt.Sprintf("%s %s %s:%s %s;",
		RuleRoleTransition, r.Source, r.Target, r.Class, r.Default)
	return r.statement
}

// String renders the rule as a policy statement.
func (r *MLSRule) String() string {
	if r.statement != "" {
		return r.statement
	}
	r.statement = fmt.Sprintf("%s %s %s:%s %s;",
		r.Ruletype, r.Source, r.Target, r.Class, r.Default)
	return r.statement
}

// pyBool renders a boolean the way setools' f-strings do.
func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// formatPerms renders a permission set, sorted, in braces when there is more
// than one permission.
func formatPerms(perms []string, suffix string) string {
	if len(perms) == 1 {
		return perms[0] + suffix
	}
	sorted := append([]string(nil), perms...)
	sort.Strings(sorted)
	return "{ " + strings.Join(sorted, " ") + " }" + suffix
}

// SortRules sorts rules by their rendered statement, which is what the tools
// use for output ordering.
func SortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].String() < rules[j].String() })
}

// TERules returns every type enforcement rule in the policy, in policy order:
// the unconditional avtab rules, then the filename transitions, then the rules
// of each conditional block (true block first).
func (p *Policy) TERules() []Rule {
	p.loadRules()
	return p.teRules
}

// RBACRules returns every role allow and role_transition rule, in policy
// order: role allow rules first.
func (p *Policy) RBACRules() []Rule {
	p.loadRules()
	return p.rbacRules
}

// MLSRules returns every range_transition rule, in policy order.
func (p *Policy) MLSRules() []Rule {
	p.loadRules()
	return p.mlsRules
}

func (p *Policy) loadRules() {
	if p.rulesOnce {
		return
	}
	p.rulesOnce = true
	db := p.db
	for _, e := range db.AVTab {
		if rule := p.avRule(e); rule != nil {
			p.teRules = append(p.teRules, rule)
		}
	}
	for _, f := range db.FilenameTrans {
		for _, src := range f.Sources {
			p.teRules = append(p.teRules, &FileNameTERule{
				Source:   p.typeValue(src),
				Target:   p.typeValue(f.Target),
				Class:    p.classValue(f.Class),
				Default:  p.typeValue(f.Default),
				Filename: f.Name,
			})
		}
	}
	for _, c := range db.Conditions {
		cond := p.conditional(c)
		for _, e := range c.TrueRules {
			if rule := p.avRule(e); rule != nil {
				setConditional(rule, cond, true)
				p.teRules = append(p.teRules, rule)
			}
		}
		for _, e := range c.FalseRules {
			if rule := p.avRule(e); rule != nil {
				setConditional(rule, cond, false)
				p.teRules = append(p.teRules, rule)
			}
		}
	}
	for _, rt := range db.RoleAllows {
		p.rbacRules = append(p.rbacRules, &RoleAllowRule{
			Source: p.roleByValue[rt.Role],
			Target: p.roleByValue[rt.NewRole],
		})
	}
	for _, rt := range db.RoleTrans {
		p.rbacRules = append(p.rbacRules, &RoleTransitionRule{
			Source:  p.roleByValue[rt.Role],
			Target:  p.typeValue(rt.Type),
			Class:   p.classValue(rt.Class),
			Default: p.roleByValue[rt.NewRole],
		})
	}
	for _, rt := range db.RangeTrans {
		p.mlsRules = append(p.mlsRules, &MLSRule{
			Ruletype: RuleRangeTransition,
			Source:   p.typeValue(rt.Source),
			Target:   p.typeValue(rt.Target),
			Class:    p.classValue(rt.Class),
			Default:  p.rangeValue(rt.Range),
		})
	}
}

// setConditional attaches a conditional block to a rule that comes from a
// conditional avtab list.
func setConditional(rule Rule, c *Conditional, block bool) {
	switch r := rule.(type) {
	case *AVRule:
		r.Conditional, r.ConditionalBlock = c, block
	case *AVRuleXperm:
		r.Conditional, r.ConditionalBlock = c, block
	case *TERule:
		r.Conditional, r.ConditionalBlock = c, block
	}
}

// avRule converts an avtab entry into its rule object. Entries with an
// unknown or unsupported specifier are skipped, as setools does.
func (p *Policy) avRule(e policy.AVTabEntry) Rule {
	kind := RuleType(e.Specified &^ policy.AVTabEnabled)
	src, tgt, cls := p.typeValue(e.Source), p.typeValue(e.Target), p.classValue(e.Class)
	if src == nil || tgt == nil || cls == nil {
		return nil
	}
	switch {
	case e.Specified&policy.AVTabXPerms != 0:
		if e.XPerms == nil {
			return nil
		}
		perms, xpermType := p.xpermSet(e.XPerms)
		return &AVRuleXperm{
			Ruletype:  kind,
			Source:    src,
			Target:    tgt,
			Class:     cls,
			XPermType: xpermType,
			Perms:     perms,
		}
	case kind == TypeTransition || kind == TypeChange || kind == TypeMember:
		return &TERule{
			Ruletype: kind,
			Source:   src,
			Target:   tgt,
			Class:    cls,
			Default:  p.typeValue(e.Data),
		}
	default:
		vector := e.Data
		if kind == DontAudit {
			// dontaudit rules store the complement of the audited
			// permissions.
			vector = ^vector
		}
		return &AVRule{
			Ruletype: kind,
			Source:   src,
			Target:   tgt,
			Class:    cls,
			Perms:    cls.permVector(vector),
		}
	}
}
