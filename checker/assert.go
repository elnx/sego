package checker

// The assert_te and assert_rbac checks: assert that an allow rule exists (or
// does not exist) for the configured criteria.

import (
	"fmt"
	"io"

	sego "github.com/elnx/sego"
)

// assertTE is the assert_te check.
type assertTE struct {
	checkBase

	source string
	target string
	tclass []string
	perms  []string

	exemptSource map[string]bool
	exemptTarget map[string]bool
	expectSource map[string]bool
	expectTarget map[string]bool
}

func newAssertTE(pol *sego.Policy, name string, config map[string]string, stderr io.Writer, verbose bool) (Check, error) {
	c := &assertTE{checkBase: newCheckBase(pol, name, "assert_te", stderr, verbose)}
	if err := c.validateOptions(config, "source", "target", "tclass", "perms",
		"exempt_source", "exempt_target", "expect_source", "expect_target"); err != nil {
		return nil, err
	}

	// The options are resolved in the reference tool's order, so the first
	// invalid one is the one reported.
	var err error
	if c.source, err = c.single("source", config["source"], lookupTypeOrAttr(pol)); err != nil {
		return nil, err
	}
	if c.target, err = c.single("target", config["target"], lookupTypeOrAttr(pol)); err != nil {
		return nil, err
	}
	if c.tclass, err = c.set("tclass", config["tclass"], true, func(name string) ([]string, error) {
		class, err := pol.ClassByName(name)
		if err != nil {
			return nil, err
		}
		return []string{class.Name}, nil
	}); err != nil {
		return nil, err
	}
	if c.perms, err = c.permSet(config["perms"]); err != nil {
		return nil, err
	}
	if c.exemptSource, err = c.expandedSet("exempt_source", config["exempt_source"], false); err != nil {
		return nil, err
	}
	if c.exemptTarget, err = c.expandedSet("exempt_target", config["exempt_target"], false); err != nil {
		return nil, err
	}
	if c.expectSource, err = c.expandedSet("expect_source", config["expect_source"], true); err != nil {
		return nil, err
	}
	if c.expectTarget, err = c.expandedSet("expect_target", config["expect_target"], true); err != nil {
		return nil, err
	}

	if c.source == "" && c.target == "" && len(c.tclass) == 0 && len(c.perms) == 0 {
		return nil, configErrorf("At least one of source, target, tclass, or perms options must be set.")
	}
	return c, nil
}

// single resolves a single name option.
func (c *assertTE) single(option, value string, lookup func(string) (string, error)) (string, error) {
	value = trimOption(value)
	if value == "" {
		return "", nil
	}
	got, err := lookup(value)
	if err != nil {
		return "", configErrorf("%s: Invalid _internal_%s setting: %s", c.name, option, err)
	}
	return got, nil
}

// set resolves a set option to its names.
func (c *assertTE) set(option, value string, strict bool,
	lookup func(string) ([]string, error)) ([]string, error) {
	set, err := parseSet(c.name, option, value, strict, c.stderr, c.verbose, lookup)
	if err != nil {
		return nil, err
	}
	return sortedNames(set), nil
}

// expandedSet resolves a set option, expanding attributes into their member
// types.
func (c *assertTE) expandedSet(option, value string, strict bool) (map[string]bool, error) {
	return parseSet(c.name, option, value, strict, c.stderr, c.verbose, func(name string) ([]string, error) {
		t, err := c.policy.TypeByName(name)
		if err != nil {
			return nil, err
		}
		return typeExpansion(t), nil
	})
}

// permSet parses the permission set, validating it against tclass when the
// check selected classes.
func (c *assertTE) permSet(value string) ([]string, error) {
	value = trimOption(value)
	if value == "" {
		return nil, nil
	}
	perms := splitSet(value)
	if err := validatePerms(c.policy, perms, c.tclass); err != nil {
		return nil, configErrorf("%s: Invalid _internal_perms setting: %s", c.name, err)
	}
	return perms, nil
}

// Run executes the check.
func (c *assertTE) Run(out io.Writer) ([]string, error) {
	c.info("Checking TE allow rule assertion.")
	q := sego.NewTERuleQuery(c.policy)
	q.SetRuletypes(sego.Allow)
	// The criteria were validated when the check was configured; a query
	// error cannot happen here.
	if c.source != "" {
		if err := q.SetSource(c.source, true, false); err != nil {
			return nil, err
		}
	}
	if c.target != "" {
		if err := q.SetTarget(c.target, true, false); err != nil {
			return nil, err
		}
	}
	if len(c.tclass) > 0 {
		if err := q.SetClasses(c.tclass); err != nil {
			return nil, err
		}
	}
	if len(c.perms) > 0 {
		if err := q.SetPerms(c.perms); err != nil {
			return nil, err
		}
	}

	unseenSources := copySet(c.expectSource)
	unseenTargets := copySet(c.expectTarget)
	var failures []string

	c.info("Generating TE rule results from %s", c.policy.Path())
	rules := q.Results()
	sego.SortRules(rules)
	for _, rule := range rules {
		av := rule.(*sego.AVRule)
		srcs := namesOf(av.Source.Expand())
		tgts := namesOf(av.Target.Expand())

		unseenSources = setSubtract(unseenSources, srcs)
		unseenTargets = setSubtract(unseenTargets, tgts)
		if len(setSubtract(srcs, c.expectSource, c.exemptSource)) > 0 &&
			len(setSubtract(tgts, c.expectTarget, c.exemptTarget)) > 0 {
			logFail(out, rule.String())
			failures = append(failures, rule.String())
		}
	}

	for _, name := range sortedNames(unseenSources) {
		failure := fmt.Sprintf("Expected rule with source %q not found.", name)
		logFail(out, failure)
		failures = append(failures, failure)
	}
	for _, name := range sortedNames(unseenTargets) {
		failure := fmt.Sprintf("Expected rule with target %q not found.", name)
		logFail(out, failure)
		failures = append(failures, failure)
	}
	return failures, nil
}

// assertRBAC is the assert_rbac check.
type assertRBAC struct {
	checkBase

	source string
	target string

	exemptSource map[string]bool
	exemptTarget map[string]bool
	expectSource map[string]bool
	expectTarget map[string]bool
}

func newAssertRBAC(pol *sego.Policy, name string, config map[string]string, stderr io.Writer, verbose bool) (Check, error) {
	c := &assertRBAC{checkBase: newCheckBase(pol, name, "assert_rbac", stderr, verbose)}
	if err := c.validateOptions(config, "source", "target",
		"exempt_source", "exempt_target", "expect_source", "expect_target"); err != nil {
		return nil, err
	}

	var err error
	if c.source, err = c.single("source", config["source"]); err != nil {
		return nil, err
	}
	if c.target, err = c.single("target", config["target"]); err != nil {
		return nil, err
	}
	if c.exemptSource, err = c.roleSet("exempt_source", config["exempt_source"], false); err != nil {
		return nil, err
	}
	if c.exemptTarget, err = c.roleSet("exempt_target", config["exempt_target"], false); err != nil {
		return nil, err
	}
	if c.expectSource, err = c.roleSet("expect_source", config["expect_source"], true); err != nil {
		return nil, err
	}
	if c.expectTarget, err = c.roleSet("expect_target", config["expect_target"], true); err != nil {
		return nil, err
	}

	if c.source == "" && c.target == "" {
		return nil, configErrorf("At least one of source or target options must be set.")
	}
	return c, nil
}

func (c *assertRBAC) single(option, value string) (string, error) {
	value = trimOption(value)
	if value == "" {
		return "", nil
	}
	role, err := c.policy.RoleByName(value)
	if err != nil {
		return "", configErrorf("%s: Invalid _internal_%s setting: %s", c.name, option, err)
	}
	return role.Name, nil
}

func (c *assertRBAC) roleSet(option, value string, strict bool) (map[string]bool, error) {
	return parseSet(c.name, option, value, strict, c.stderr, c.verbose, func(name string) ([]string, error) {
		role, err := c.policy.RoleByName(name)
		if err != nil {
			return nil, err
		}
		return []string{role.Name}, nil
	})
}

// Run executes the check.
func (c *assertRBAC) Run(out io.Writer) ([]string, error) {
	c.info("Checking RBAC allow rule assertion.")
	q := sego.NewRBACRuleQuery(c.policy)
	q.SetRuletypes(sego.RuleRoleAllow)
	if c.source != "" {
		if err := q.SetSource(c.source, false); err != nil {
			return nil, err
		}
	}
	if c.target != "" {
		if err := q.SetTarget(c.target, false); err != nil {
			return nil, err
		}
	}

	unseenSources := copySet(c.expectSource)
	unseenTargets := copySet(c.expectTarget)
	var failures []string

	c.info("Generating RBAC rule results from %s", c.policy.Path())
	rules := q.Results()
	sego.SortRules(rules)
	for _, rule := range rules {
		allow := rule.(*sego.RoleAllowRule)
		srcs := map[string]bool{allow.Source.Name: true}
		tgts := map[string]bool{allow.Target.Name: true}

		unseenSources = setSubtract(unseenSources, srcs)
		unseenTargets = setSubtract(unseenTargets, tgts)
		if len(setSubtract(srcs, c.expectSource, c.exemptSource)) > 0 &&
			len(setSubtract(tgts, c.expectTarget, c.exemptTarget)) > 0 {
			logFail(out, rule.String())
			failures = append(failures, rule.String())
		}
	}

	for _, name := range sortedNames(unseenSources) {
		failure := fmt.Sprintf("Expected rule with source %q not found.", name)
		logFail(out, failure)
		failures = append(failures, failure)
	}
	for _, name := range sortedNames(unseenTargets) {
		failure := fmt.Sprintf("Expected rule with target %q not found.", name)
		logFail(out, failure)
		failures = append(failures, failure)
	}
	return failures, nil
}

// copySet returns a copy of a name set.
func copySet(set map[string]bool) map[string]bool {
	out := make(map[string]bool, len(set))
	for name := range set {
		out[name] = true
	}
	return out
}

// typeExpansion returns the expanded names of a type or attribute.
func typeExpansion(t *sego.Type) []string {
	names := make([]string, 0, len(t.Expand()))
	for _, member := range t.Expand() {
		names = append(names, member.Name)
	}
	return names
}

// lookupTypeOrAttr resolves a name to a type or attribute, returning its name.
func lookupTypeOrAttr(pol *sego.Policy) func(string) (string, error) {
	return func(name string) (string, error) {
		t, err := pol.TypeByName(name)
		if err != nil {
			return "", err
		}
		return t.Name, nil
	}
}

// trimOption trims an option value, treating an empty setting as unset.
func trimOption(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n') {
		value = value[1:]
	}
	for len(value) > 0 && (value[len(value)-1] == ' ' || value[len(value)-1] == '\t' || value[len(value)-1] == '\n') {
		value = value[:len(value)-1]
	}
	return value
}
