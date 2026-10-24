package checker

// The remaining checks: empty_typeattr, ro_execs and ro_kmods.

import (
	"fmt"
	"io"
	"sort"
	"strings"

	sego "github.com/elnx/sego"
)

// validatePerms checks that every permission exists in at least one of the
// selected classes, or in any class when none were selected.
func validatePerms(pol *sego.Policy, perms, tclass []string) error {
	invalid := make(map[string]bool, len(perms))
	for _, perm := range perms {
		invalid[perm] = true
	}
	var classes []*sego.Class
	if len(tclass) > 0 {
		for _, name := range tclass {
			c, err := pol.ClassByName(name)
			if err != nil {
				return err
			}
			classes = append(classes, c)
		}
	} else {
		classes = pol.Classes()
	}
	for _, class := range classes {
		for _, perm := range class.Perms() {
			delete(invalid, perm)
		}
		if len(invalid) == 0 {
			return nil
		}
	}
	var names []string
	for _, perm := range perms {
		if invalid[perm] {
			names = append(names, perm)
			delete(invalid, perm)
		}
	}
	if len(tclass) > 0 {
		return fmt.Errorf("Permission(s) do not exist in the specified classes: %s",
			joinStrings(names, ", "))
	}
	return fmt.Errorf("Permission(s) do not exist any class: %s", joinStrings(names, ", "))
}

func joinStrings(items []string, sep string) string {
	var out strings.Builder
	for i, item := range items {
		if i > 0 {
			out.WriteString(sep)
		}
		out.WriteString(item)
	}
	return out.String()
}

// emptyTypeAttr is the empty_typeattr check.
type emptyTypeAttr struct {
	checkBase

	attr      string
	missingOK bool
}

func newEmptyTypeAttr(pol *sego.Policy, name string, config map[string]string, stderr io.Writer, verbose bool) (Check, error) {
	c := &emptyTypeAttr{checkBase: newCheckBase(pol, name, "empty_typeattr", stderr, verbose)}
	if err := c.validateOptions(config, "attr", "missing_ok"); err != nil {
		return nil, err
	}
	c.missingOK = configBoolValue(config["missing_ok"])
	value := trimOption(config["attr"])
	if value == "" {
		return nil, configErrorf("%s: \"attr\" setting is missing.", c.name)
	}
	if _, err := pol.TypeAttributeByName(value); err != nil {
		if !c.missingOK {
			return nil, configErrorf("%s: attr setting error: %s", c.name, err)
		}
	}
	c.attr = value
	return c, nil
}

// Run executes the check.
func (c *emptyTypeAttr) Run(out io.Writer) ([]string, error) {
	c.info("Checking type attribute %s is empty.", c.attr)
	attr, err := c.policy.TypeAttributeByName(c.attr)
	if err != nil {
		logInfo(out, fmt.Sprintf("    %s does not exist.", c.attr))
		return nil, nil
	}

	fmt.Fprintf(out, "Member types of %s:\n", c.attr)
	var failures []string
	members := typeExpansion(attr)
	sort.Strings(members)
	for _, name := range members {
		logFail(out, name)
		failures = append(failures, name)
	}
	return failures, nil
}

// readOnlyExecutables is the ro_execs check.
type readOnlyExecutables struct {
	checkBase

	exemptWriteDomain map[string]bool
	exemptExecDomain  map[string]bool
	exemptFile        map[string]bool
}

func newReadOnlyExecutables(pol *sego.Policy, name string, config map[string]string, stderr io.Writer, verbose bool) (Check, error) {
	c := &readOnlyExecutables{checkBase: newCheckBase(pol, name, "ro_execs", stderr, verbose)}
	if err := c.validateOptions(config, "exempt_write_domain", "exempt_exec_domain", "exempt_file"); err != nil {
		return nil, err
	}
	var err error
	if c.exemptWriteDomain, err = c.exemptSet("exempt_write_domain", config["exempt_write_domain"]); err != nil {
		return nil, err
	}
	if c.exemptFile, err = c.exemptSet("exempt_file", config["exempt_file"]); err != nil {
		return nil, err
	}
	if c.exemptExecDomain, err = c.exemptSet("exempt_exec_domain", config["exempt_exec_domain"]); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *readOnlyExecutables) exemptSet(option, value string) (map[string]bool, error) {
	return parseSet(c.name, option, value, false, c.stderr, c.verbose, func(name string) ([]string, error) {
		t, err := c.policy.TypeByName(name)
		if err != nil {
			return nil, err
		}
		return typeExpansion(t), nil
	})
}

// Run executes the check.
func (c *readOnlyExecutables) Run(out io.Writer) ([]string, error) {
	c.info("Checking executables are read-only.")
	// The write query is configured before the executables are collected,
	// as in the reference tool: an invalid permission in it is reported
	// first.
	q := sego.NewTERuleQuery(c.policy)
	q.SetRuletypes(sego.Allow)
	if err := q.SetClasses([]string{"file"}); err != nil {
		return nil, err
	}
	if err := q.SetPerms([]string{"write", "append"}); err != nil {
		return nil, err
	}

	executables, err := c.collectExecutables()
	if err != nil {
		return nil, err
	}

	failures := make(map[string][]string)
	for _, execType := range execTypeOrder(executables) {
		if err := q.SetTarget(execType, true, false); err != nil {
			return nil, err
		}
		c.info("Generating TE rule results from %s", c.policy.Path())
		for _, rule := range q.Results() {
			av := rule.(*sego.AVRule)
			if len(setSubtract(namesOf(av.Source.Expand()), c.exemptWriteDomain)) > 0 {
				failures[execType] = append(failures[execType], rule.String())
			}
		}
	}

	failing := make([]string, 0, len(failures))
	for execType := range failures {
		failing = append(failing, execType)
	}
	sort.Strings(failing)
	for _, execType := range failing {
		fmt.Fprint(out, "\n------------\n\n")
		fmt.Fprintf(out, "Executable type %s is writable.\n\n", execType)
		fmt.Fprint(out, "Execute rules:\n")
		for _, rule := range executables[execType] {
			fmt.Fprintf(out, "    * %s\n", rule)
		}
		fmt.Fprint(out, "\nWrite rules:\n")
		for _, rule := range failures[execType] {
			logFail(out, rule)
		}
	}
	return failing, nil
}

// collectExecutables returns the executable file types and the execute rules
// that make them executable, keyed in discovery order.
func (c *readOnlyExecutables) collectExecutables() (map[string][]string, error) {
	q := sego.NewTERuleQuery(c.policy)
	q.SetRuletypes(sego.Allow)
	if err := q.SetClasses([]string{"file"}); err != nil {
		return nil, err
	}
	if err := q.SetPerms([]string{"execute", "execute_no_trans"}); err != nil {
		return nil, err
	}

	collected := make(map[string][]string)
	c.info("Generating TE rule results from %s", c.policy.Path())
	for _, rule := range q.Results() {
		av := rule.(*sego.AVRule)
		sources := setSubtract(namesOf(av.Source.Expand()), c.exemptExecDomain)
		targets := setSubtract(namesOf(av.Target.Expand()), c.exemptFile)
		if len(sources) == 0 || len(targets) == 0 {
			continue
		}
		for _, target := range sortedNames(targets) {
			collected[target] = append(collected[target], rule.String())
		}
	}
	sortExecutables(collected)
	return collected, nil
}

// sortExecutables sorts the rule lists of the collected types.
func sortExecutables(m map[string][]string) {
	for _, rules := range m {
		sort.Strings(rules)
	}
}

// execTypeOrder returns the executable types sorted by name; the reference
// prints the write findings by sorted type name.
func execTypeOrder(m map[string][]string) []string {
	return sortedNames(mapKeys(m))
}

func mapKeys[T any](m map[string]T) map[string]bool {
	out := make(map[string]bool, len(m))
	for name := range m {
		out[name] = true
	}
	return out
}

// readOnlyKernelModules is the ro_kmods check.
type readOnlyKernelModules struct {
	checkBase

	exemptWriteDomain map[string]bool
	exemptLoadDomain  map[string]bool
	exemptFile        map[string]bool
}

func newReadOnlyKernelModules(pol *sego.Policy, name string, config map[string]string, stderr io.Writer, verbose bool) (Check, error) {
	c := &readOnlyKernelModules{checkBase: newCheckBase(pol, name, "ro_kmods", stderr, verbose)}
	if err := c.validateOptions(config, "exempt_write_domain", "exempt_load_domain", "exempt_file"); err != nil {
		return nil, err
	}
	var err error
	if c.exemptWriteDomain, err = c.exemptSet("exempt_write_domain", config["exempt_write_domain"]); err != nil {
		return nil, err
	}
	if c.exemptFile, err = c.exemptSet("exempt_file", config["exempt_file"]); err != nil {
		return nil, err
	}
	if c.exemptLoadDomain, err = c.exemptSet("exempt_load_domain", config["exempt_load_domain"]); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *readOnlyKernelModules) exemptSet(option, value string) (map[string]bool, error) {
	return parseSet(c.name, option, value, false, c.stderr, c.verbose, func(name string) ([]string, error) {
		t, err := c.policy.TypeByName(name)
		if err != nil {
			return nil, err
		}
		return typeExpansion(t), nil
	})
}

// Run executes the check.
func (c *readOnlyKernelModules) Run(out io.Writer) ([]string, error) {
	c.info("Checking kernel modules are read-only.")
	// The write query is configured before the modules are collected, as in
	// the reference tool.
	q := sego.NewTERuleQuery(c.policy)
	q.SetRuletypes(sego.Allow)
	if err := q.SetClasses([]string{"file"}); err != nil {
		return nil, err
	}
	if err := q.SetPerms([]string{"write", "append"}); err != nil {
		return nil, err
	}

	kmods, err := c.collectKernelModules()
	if err != nil {
		return nil, err
	}

	failures := make(map[string][]string)
	for _, kmodType := range execTypeOrder(kmods) {
		if err := q.SetTarget(kmodType, true, false); err != nil {
			return nil, err
		}
		c.info("Generating TE rule results from %s", c.policy.Path())
		for _, rule := range q.Results() {
			av := rule.(*sego.AVRule)
			if len(setSubtract(namesOf(av.Source.Expand()), c.exemptWriteDomain)) > 0 {
				failures[kmodType] = append(failures[kmodType], rule.String())
			}
		}
	}

	failing := make([]string, 0, len(failures))
	for kmodType := range failures {
		failing = append(failing, kmodType)
	}
	sort.Strings(failing)
	for _, kmodType := range failing {
		fmt.Fprint(out, "\n------------\n\n")
		fmt.Fprintf(out, "Kernel module type %s is writable.\n\n", kmodType)
		fmt.Fprint(out, "Module load rules:\n")
		for _, rule := range kmods[kmodType] {
			fmt.Fprintf(out, "    * %s\n", rule)
		}
		fmt.Fprint(out, "\nWrite rules:\n")
		for _, rule := range failures[kmodType] {
			logFail(out, rule)
		}
	}
	return failing, nil
}

// collectKernelModules returns the kernel module types and the module_load
// rules that load them.
func (c *readOnlyKernelModules) collectKernelModules() (map[string][]string, error) {
	q := sego.NewTERuleQuery(c.policy)
	q.SetRuletypes(sego.Allow)
	if err := q.SetClasses([]string{"system"}); err != nil {
		return nil, err
	}
	if err := q.SetPerms([]string{"module_load"}); err != nil {
		return nil, err
	}

	collected := make(map[string][]string)
	c.info("Generating TE rule results from %s", c.policy.Path())
	for _, rule := range q.Results() {
		av := rule.(*sego.AVRule)
		sources := setSubtract(namesOf(av.Source.Expand()), c.exemptLoadDomain)
		targets := setSubtract(namesOf(av.Target.Expand()), c.exemptFile)
		// Remove self rules.
		targets = setSubtract(targets, sources)
		if len(sources) == 0 || len(targets) == 0 {
			continue
		}
		for _, target := range sortedNames(targets) {
			collected[target] = append(collected[target], rule.String())
		}
	}
	sortExecutables(collected)
	return collected, nil
}
