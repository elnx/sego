// Command sesearch searches an SELinux binary kernel policy for policy rules.
// It is the sego reimplementation of setools' sesearch and reproduces the
// reference tool's output, exit statuses and diagnostics.
//
// Usage errors (bad usage of the command line) are printed to stderr with the
// usage line, and exit with status 2. Runtime errors (a policy that cannot be
// opened, unknown symbols, malformed criteria) print only the error message, to
// stdout, and exit with status 1, exactly as the reference tool does.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/elnx/sego"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/sesearch
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes sesearch with argv (argv[0] is the program name) and returns
// the process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "sesearch"
	if len(argv) > 0 {
		if base := filepath.Base(argv[0]); base != "" && base != "." {
			prog = base
		}
	}
	p, ruleTypes := newParser(prog)

	raw, err := p.Parse(argv[1:])
	if err != nil {
		return p.Error(stderr, err)
	}
	if raw.VersionRequested() {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if raw.HelpRequested() {
		p.HelpTo(stdout)
		return 0
	}
	opts := &args{Args: raw}
	opts.collect(ruleTypes)
	if err := opts.validate(); err != nil {
		return p.Error(stderr, err)
	}

	out := bufio.NewWriter(stdout)
	err = search(opts, out, stderr)
	out.Flush()
	if err != nil {
		if opts.debug {
			// The reference tool re-raises the exception under --debug: it
			// exits 1 with a traceback on stderr instead of the message on
			// stdout.
			fmt.Fprintf(stderr, "%s%s\n", debug.Stack(), err)
			return 1
		}
		fmt.Fprintln(stdout, err)
		return 1
	}
	return 0
}

// search runs the requested queries and writes the matching rules, sorted, to
// out: TE rule searches first, then RBAC, then MLS.
func search(a *args, out, stderr io.Writer) error {
	pol, err := loadPolicy(a, stderr)
	if err != nil {
		return err
	}

	if len(a.tertypes) > 0 {
		q := sego.NewTERuleQuery(pol)
		q.SetRuletypes(a.tertypes...)
		if err := terCriteria(q, a); err != nil {
			return err
		}
		verbosef(a, stderr, "Generating TE rule results from %s", pol.Path())
		writeRules(out, q.Results())
	}

	if len(a.rbacrtypes) > 0 {
		q := sego.NewRBACRuleQuery(pol)
		q.SetRuletypes(a.rbacrtypes...)
		if err := rbacCriteria(q, a); err != nil {
			return err
		}
		verbosef(a, stderr, "Generating RBAC rule results from %s", pol.Path())
		writeRules(out, q.Results())
	}

	if len(a.mlsrtypes) > 0 {
		q := sego.NewMLSRuleQuery(pol)
		q.SetRuletypes(a.mlsrtypes...)
		if err := mlsCriteria(q, a); err != nil {
			return err
		}
		verbosef(a, stderr, "Generating MLS rule results from %s", pol.Path())
		writeRules(out, q.Results())
	}

	return nil
}

// loadPolicy opens the policy named on the command line, or the policy the
// reference tool would locate when none was named.
func loadPolicy(a *args, stderr io.Writer) (*sego.Policy, error) {
	path := a.policy
	if path == "" {
		verbosef(a, stderr, "Attempting to locate current running policy.")
		found, err := sego.FindPolicyPath()
		if err != nil {
			return nil, err
		}
		path = found
	}
	verbosef(a, stderr, "Opening SELinux policy %q", path)
	pol, err := sego.Open(path)
	if err != nil {
		return nil, err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", path)
	return pol, nil
}

// terCriteria sets the type enforcement criteria. The order matters: the
// reference tool resolves the criteria in this order, so it reports the first
// bad criterion in the same place.
func terCriteria(q *sego.TERuleQuery, a *args) error {
	// Criteria are resolved in the reference tool's order, which is the
	// reverse alphabetical order of its keyword arguments: target before
	// source, both before the class, permission, extended permission and
	// Boolean criteria. When more than one criterion is invalid, this is
	// the order the errors are reported in.
	if tgt := a.Value("target"); tgt != "" {
		if err := q.SetTarget(tgt, !a.Flag("target_direct"), a.Flag("target_regex")); err != nil {
			return err
		}
	}
	if src := a.Value("source"); src != "" {
		if err := q.SetSource(src, !a.Flag("source_direct"), a.Flag("source_regex")); err != nil {
			return err
		}
	}
	q.SetPermsEqual(a.Flag("perms_equal"))
	q.SetPermsSubset(a.Flag("perms_subset"))
	if def := a.Value("default"); def != "" {
		if err := q.SetDefault(def, a.Flag("default_regex")); err != nil {
			return err
		}
	}
	q.SetBooleanEqual(a.Flag("boolean_equal"))
	if tclass := a.Value("tclass"); tclass != "" {
		if err := setTClass(tclass, a.Flag("tclass_regex"), q.SetClasses, q.SetClassPattern); err != nil {
			return err
		}
	}
	if perms := a.Value("perms"); perms != "" {
		if err := q.SetPerms(strings.Split(perms, ",")); err != nil {
			return err
		}
	}
	if xperms := a.Value("xperms"); xperms != "" {
		set, err := sego.ParseXPermSet(xperms)
		if err != nil {
			return err
		}
		q.SetXPerms(set, a.Flag("xperms_equal"))
	}
	if cond := a.Value("boolean"); cond != "" {
		if a.Flag("boolean_regex") {
			if err := q.SetBooleanPattern(cond); err != nil {
				return err
			}
		} else {
			names := strings.Split(cond, ",")
			if !a.hasPolicy {
				// Old Boolean names are only translated when the policy was
				// located rather than named.
				for i, name := range names {
					names[i] = lookupBooleanNameSub(name)
				}
			}
			if err := q.SetBooleans(names); err != nil {
				return err
			}
		}
	}
	return nil
}

// rbacCriteria sets the role based access control criteria.
func rbacCriteria(q *sego.RBACRuleQuery, a *args) error {
	if tgt := a.Value("target"); tgt != "" {
		if err := q.SetTarget(tgt, a.Flag("target_regex")); err != nil {
			return err
		}
	}
	if src := a.Value("source"); src != "" {
		if err := q.SetSource(src, a.Flag("source_regex")); err != nil {
			return err
		}
	}
	if def := a.Value("default"); def != "" {
		if err := q.SetDefault(def, a.Flag("default_regex")); err != nil {
			return err
		}
	}
	if tclass := a.Value("tclass"); tclass != "" {
		return setTClass(tclass, a.Flag("tclass_regex"), q.SetClasses, q.SetClassPattern)
	}
	return nil
}

// mlsCriteria sets the MLS criteria.
func mlsCriteria(q *sego.MLSRuleQuery, a *args) error {
	if tgt := a.Value("target"); tgt != "" {
		if err := q.SetTarget(tgt, !a.Flag("target_direct"), a.Flag("target_regex")); err != nil {
			return err
		}
	}
	if src := a.Value("source"); src != "" {
		if err := q.SetSource(src, !a.Flag("source_direct"), a.Flag("source_regex")); err != nil {
			return err
		}
	}
	if def := a.Value("default"); def != "" {
		if err := q.SetRange(def); err != nil {
			return err
		}
	}
	if tclass := a.Value("tclass"); tclass != "" {
		return setTClass(tclass, a.Flag("tclass_regex"), q.SetClasses, q.SetClassPattern)
	}
	return nil
}

// setTClass applies the object class criterion: a regular expression, or a
// comma separated list of class names.
func setTClass(tclass string, regex bool, setClasses func([]string) error,
	setPattern func(string) error) error {

	if regex {
		return setPattern(tclass)
	}
	return setClasses(strings.Split(tclass, ","))
}

// writeRules prints the rules in the reference tool's order: sorted by their
// rendered statement.
func writeRules(out io.Writer, rules []sego.Rule) {
	sego.SortRules(rules)
	for _, rule := range rules {
		fmt.Fprintln(out, rule.String())
	}
}

// verbosef prints an informational message for -v/--verbose. The reference
// tool logs these through the logging module, which writes to stderr.
func verbosef(a *args, stderr io.Writer, format string, args ...any) {
	if a.verbose || a.debug {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}
