// Package checker implements the policy checks of setools' sechecker: a
// configuration-file driven set of checks over an SELinux binary policy.
//
// The configuration format is the reference tool's: one INI section per
// check, a check_type key naming the check, and the check's own options. The
// check modules, their options and their report formats mirror setools 4.8.
package checker

import (
	"fmt"
	"io"
	"sort"
	"strings"

	sego "github.com/elnx/sego"
)

// ConfigError is an invalid checker configuration. The command reports it on
// stdout and exits with status 2, like the reference tool's
// InvalidCheckerConfig family.
type ConfigError struct{ msg string }

func (e *ConfigError) Error() string { return e.msg }

func configErrorf(format string, args ...any) error {
	return &ConfigError{msg: fmt.Sprintf(format, args...)}
}

// Check is one configured check.
type Check interface {
	// Name returns the section name of the check.
	Name() string
	// Type returns the check_type of the check.
	Type() string
	// Desc returns the configured description, or "".
	Desc() string
	// Disable returns the configured disable reason, or "".
	Disable() string
	// Run executes the check, writes its findings to out and returns the
	// failures. The length of the result is the failure count.
	Run(out io.Writer) ([]string, error)
}

// Checker is the configured set of checks for one policy.
type Checker struct {
	Policy     *sego.Policy
	ConfigPath string
	Checks     []Check
}

// NewChecker parses the configuration file and builds its checks.
func NewChecker(pol *sego.Policy, configPath string, stderr io.Writer, verbose bool) (*Checker, error) {
	sections, err := parseConfig(configPath)
	if err != nil {
		return nil, configErrorf("Unable to parse checker config %s: %s", configPath, err)
	}

	checker := &Checker{Policy: pol, ConfigPath: configPath}
	for _, section := range sections {
		if section.name == defaultSection {
			// The DEFAULT section is not a check; its keys are inherited
			// by every section.
			continue
		}
		checkType, ok := section.values["check_type"]
		if !ok {
			return nil, configErrorf("%s: Missing check_type option.", section.name)
		}
		factory, ok := registry[checkType]
		if !ok {
			return nil, configErrorf("%s: Unknown policy check type: %s", section.name, checkType)
		}
		check, err := factory(pol, section.name, section.values, stderr, verbose)
		if err != nil {
			return nil, err
		}
		checker.Checks = append(checker.Checks, check)
	}
	if len(checker.Checks) == 0 {
		return nil, configErrorf("No checks found in %s.", configPath)
	}
	return checker, nil
}

// registry maps the check_type names to their constructors.
var registry = map[string]func(*sego.Policy, string, map[string]string, io.Writer, bool) (Check, error){
	"assert_te":      newAssertTE,
	"assert_rbac":    newAssertRBAC,
	"empty_typeattr": newEmptyTypeAttr,
	"ro_execs":       newReadOnlyExecutables,
	"ro_kmods":       newReadOnlyKernelModules,
}

// checkBase carries the common configuration of a check.
type checkBase struct {
	policy    *sego.Policy
	name      string
	checkType string
	desc      string
	disable   string
	stderr    io.Writer
	verbose   bool
}

func newCheckBase(pol *sego.Policy, name, checkType string, stderr io.Writer, verbose bool) checkBase {
	return checkBase{policy: pol, name: name, checkType: checkType, stderr: stderr, verbose: verbose}
}

// Name returns the section name.
func (b *checkBase) Name() string { return b.name }

// Type returns the check type.
func (b *checkBase) Type() string { return b.checkType }

// Desc returns the configured description.
func (b *checkBase) Desc() string { return b.desc }

// Disable returns the configured disable reason.
func (b *checkBase) Disable() string { return b.disable }

// validateOptions reports an option that the check does not know, and stores
// the global options. valid holds the check's own option names.
func (b *checkBase) validateOptions(config map[string]string, valid ...string) error {
	allowed := map[string]bool{"check_type": true, "desc": true, "disable": true}
	for _, name := range valid {
		allowed[name] = true
	}
	for name := range config {
		if !allowed[name] {
			return configErrorf("%s: Invalid option: %s", b.name, name)
		}
	}
	b.desc = config["desc"]
	b.disable = config["disable"]
	return nil
}

// logInfo writes an informational message to the check's report output.
func logInfo(out io.Writer, msg string) {
	fmt.Fprintln(out, msg)
}

// info logs an informational message for -v/--verbose, the way the reference's
// logging calls do.
func (b *checkBase) info(format string, args ...any) {
	if b.verbose {
		fmt.Fprintf(b.stderr, format+"\n", args...)
	}
}

// logFail writes a failure line. The reference tool prefixes failures with
// four spaces and a star; passing findings are not logged by any check.
func logFail(out io.Writer, msg string) {
	fmt.Fprintf(out, "    * %s\n", msg)
}

// splitSet splits a set option the way the reference does: on whitespace.
func splitSet(value string) []string {
	return strings.Fields(value)
}

// parseSet parses a set option, looking every item up with lookup. With
// strict unset, items that do not resolve are dropped. lookup returns the
// expanded names of the item.
func parseSet(checkname, option, value string, strict bool, stderr io.Writer, verbose bool,
	lookup func(string) ([]string, error)) (map[string]bool, error) {

	out := make(map[string]bool)
	if value == "" {
		return out, nil
	}
	for _, item := range splitSet(value) {
		names, err := lookup(item)
		if err != nil {
			if strict {
				msg := fmt.Sprintf("Invalid _internal_%s item: %s", option, err)
				fmt.Fprintln(stderr, msg)
				return nil, configErrorf("%s: %s", checkname, msg)
			}
			if verbose {
				fmt.Fprintf(stderr, "%s: Invalid _internal_%s item: %s\n", checkname, option, err)
			}
			continue
		}
		for _, name := range names {
			out[name] = true
		}
	}
	return out, nil
}

// sortedNames returns the names of a set, sorted.
func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// setSubtract returns the elements of a that are not in the others.
func setSubtract(a map[string]bool, others ...map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for name := range a {
		excluded := false
		for _, other := range others {
			if other[name] {
				excluded = true
				break
			}
		}
		if !excluded {
			out[name] = true
		}
	}
	return out
}

// namesOf returns the names of the types as a set.
func namesOf(types []*sego.Type) map[string]bool {
	out := make(map[string]bool, len(types))
	for _, t := range types {
		out[t.Name] = true
	}
	return out
}

// configBoolValue converts a configuration Boolean the way the reference's
// config_bool_value does: yes, true and 1 (case-insensitive) are true.
func configBoolValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1":
		return true
	}
	return false
}
