package main

// This file defines the sesearch command line. The parsing itself lives in
// the internal/argparse package, a hand-rolled reimplementation of the parts
// of Python's argparse that the tools exercise: the usage line, the grouped
// and wrapped --help output, the wording of every usage error and the split
// between usage errors (exit 2) and runtime errors (exit 1).

import (
	"github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
)

// Help prose. The option names, metavariables and argument groups mirror the
// reference CLI because they are its interface; the text describing them is
// this project's own (see NOTICE.md).
const (
	description = "Search the rules of an SELinux binary policy."
	epilog      = "TE, RBAC and MLS rule types may be combined in one search."
)

// Argument group headings, in the order argparse prints them.
const (
	groupTE      = "TE Rule Types"
	groupRBAC    = "RBAC Rule Types"
	groupMLS     = "MLS Rule Types"
	groupExpr    = "Expressions"
	groupOptions = "Search options"
)

// ruleTypeOption attaches a rule type to a flag option: the rule family and
// the rule type the flag selects.
type ruleTypeOption struct {
	dest     string
	family   string // "ter", "rbac" or "mls"
	ruleType sego.RuleType
}

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() ([]argparse.Option, []ruleTypeOption) {
	opts := []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being read and searched on stderr."},
		{Names: []string{"--debug"}, Dest: "debug", Help: "Print a stack trace when something fails."},

		{Names: []string{"-A"}, Dest: "A", Group: groupTE,
			Help: "Match allow and allowxperm rules."},
		{Names: []string{"--allow"}, Dest: "allow", Group: groupTE,
			Help: "Match allow rules."},
		{Names: []string{"--allowxperm"}, Dest: "allowxperm", Group: groupTE,
			Help: "Match allowxperm rules."},
		{Names: []string{"--auditallow"}, Dest: "auditallow", Group: groupTE,
			Help: "Match auditallow rules."},
		{Names: []string{"--auditallowxperm"}, Dest: "auditallowxperm", Group: groupTE,
			Help: "Match auditallowxperm rules."},
		{Names: []string{"--dontaudit"}, Dest: "dontaudit", Group: groupTE,
			Help: "Match dontaudit rules."},
		{Names: []string{"--dontauditxperm"}, Dest: "dontauditxperm", Group: groupTE,
			Help: "Match dontauditxperm rules."},
		{Names: []string{"-T", "--type_transition"}, Dest: "type_transition", Group: groupTE,
			Help: "Match type_transition rules."},
		{Names: []string{"--type_change"}, Dest: "type_change", Group: groupTE,
			Help: "Match type_change rules."},
		{Names: []string{"--type_member"}, Dest: "type_member", Group: groupTE,
			Help: "Match type_member rules."},

		{Names: []string{"--role_allow"}, Dest: "role_allow", Group: groupRBAC,
			Help: "Match role allow rules."},
		{Names: []string{"--role_transition"}, Dest: "role_transition", Group: groupRBAC,
			Help: "Match role_transition rules."},

		{Names: []string{"--range_transition"}, Dest: "range_transition", Group: groupMLS,
			Help: "Match range_transition rules."},

		{Names: []string{"-s", "--source"}, Metavar: "SOURCE", Dest: "source", Group: groupExpr,
			Help: "Rule source: a type or type attribute, or a role for RBAC searches."},
		{Names: []string{"-t", "--target"}, Metavar: "TARGET", Dest: "target", Group: groupExpr,
			Help: "Rule target: a type or type attribute, or a role for role allow rules."},
		{Names: []string{"-c", "--class"}, Metavar: "TCLASS", Dest: "tclass", Group: groupExpr,
			Help: "Object classes to match, comma separated."},
		{Names: []string{"-p", "--perms"}, Metavar: "PERMS", Dest: "perms", Group: groupExpr,
			Help: "Permissions to match, comma separated (TE rule searches)."},
		{Names: []string{"-x", "--xperms"}, Metavar: "XPERMS", Dest: "xperms", Group: groupExpr,
			Help: "Extended permissions to match, such as 0x5401 or 0x0000-0x00ff, comma separated (TE rule searches)."},
		{Names: []string{"-D", "--default"}, Metavar: "DEFAULT", Dest: "default", Group: groupExpr,
			Help: "Rule default: a type, a role or an MLS range, depending on the rule type."},
		{Names: []string{"-b", "--bool"}, Metavar: "BOOL", Dest: "boolean", Group: groupExpr,
			Help: "Booleans referenced by the rule's conditional, comma separated " +
				"(TE rule searches)."},

		{Names: []string{"-eb"}, Dest: "boolean_equal", Group: groupOptions,
			Help: "Match conditionals that reference exactly the listed Booleans."},
		{Names: []string{"-ep"}, Dest: "perms_equal", Group: groupOptions,
			Help: "Match only rules whose permissions are exactly the listed permissions."},
		{Names: []string{"-ex"}, Dest: "xperms_equal", Group: groupOptions,
			Help: "Match only rules whose extended permissions are exactly the listed permissions."},
		{Names: []string{"-Sp"}, Dest: "perms_subset", Group: groupOptions,
			Help: "Match rules that contain all the listed permissions."},
		{Names: []string{"-ds"}, Dest: "source_direct", Group: groupOptions,
			Help: "Match a source attribute directly instead of through its member types."},
		{Names: []string{"-dt"}, Dest: "target_direct", Group: groupOptions,
			Help: "Match a target attribute directly instead of through its member types."},
		{Names: []string{"-rs"}, Dest: "source_regex", Group: groupOptions,
			Help: "Match the source as a regular expression."},
		{Names: []string{"-rt"}, Dest: "target_regex", Group: groupOptions,
			Help: "Match the target as a regular expression."},
		{Names: []string{"-rc"}, Dest: "tclass_regex", Group: groupOptions,
			Help: "Match object classes as a regular expression."},
		{Names: []string{"-rd"}, Dest: "default_regex", Group: groupOptions,
			Help: "Match the default as a regular expression."},
		{Names: []string{"-rb"}, Dest: "boolean_regex", Group: groupOptions,
			Help: "Match the conditioned Booleans as a regular expression."},

		{Names: []string{"policy"}, Dest: "policy", Pos: true, Nargs: "?",
			Help: "Policy file to read; the running or installed policy is used when omitted."},
	}

	ruleTypes := []ruleTypeOption{
		{"allow", "ter", sego.Allow},
		{"allowxperm", "ter", sego.AllowXPerm},
		{"auditallow", "ter", sego.AuditAllow},
		{"auditallowxperm", "ter", sego.AuditAllowXPerm},
		{"dontaudit", "ter", sego.DontAudit},
		{"dontauditxperm", "ter", sego.DontAuditXPerm},
		{"type_transition", "ter", sego.TypeTransition},
		{"type_change", "ter", sego.TypeChange},
		{"type_member", "ter", sego.TypeMember},
		{"role_allow", "rbac", sego.RuleRoleAllow},
		{"role_transition", "rbac", sego.RuleRoleTransition},
		{"range_transition", "mls", sego.RuleRangeTransition},
	}
	return opts, ruleTypes
}

// args are the parsed command line.
type args struct {
	policy    string
	hasPolicy bool
	verbose   bool
	debug     bool

	tertypes   []sego.RuleType
	rbacrtypes []sego.RuleType
	mlsrtypes  []sego.RuleType

	*argparse.Args
}

// newParser returns a parser for the program named prog.
func newParser(prog string) (*argparse.Parser, []ruleTypeOption) {
	opts, ruleTypes := optionTable()
	return argparse.New(prog, description, epilog, opts), ruleTypes
}

// collect turns the parsed flags into the rule type lists. The rule types are
// collected from the flags in option table order, which does not matter for
// the search results: the queries keep them as a set and the output is sorted
// per family.
func (a *args) collect(ruleTypes []ruleTypeOption) {
	for _, rt := range ruleTypes {
		if !a.Flag(rt.dest) {
			continue
		}
		switch rt.family {
		case "ter":
			a.tertypes = append(a.tertypes, rt.ruleType)
		case "rbac":
			a.rbacrtypes = append(a.rbacrtypes, rt.ruleType)
		case "mls":
			a.mlsrtypes = append(a.mlsrtypes, rt.ruleType)
		}
	}
	if a.Flag("A") {
		// -A is --allow --allowxperm, as argparse extends the list after
		// parsing.
		a.tertypes = append(a.tertypes, sego.Allow, sego.AllowXPerm)
	}
	a.policy = a.Value("policy")
	a.hasPolicy = a.Value("policy") != ""
	a.verbose = a.Flag("verbose")
	a.debug = a.Flag("debug")
}

// validate applies the checks argparse performs after parsing.
func (a *args) validate() error {
	if len(a.tertypes) == 0 && len(a.rbacrtypes) == 0 && len(a.mlsrtypes) == 0 {
		return argparse.NewUsageError("No rule type was given; select at least one.")
	}
	if (a.Value("perms") != "" || a.Value("xperms") != "" || a.Value("boolean") != "") &&
		(len(a.rbacrtypes) > 0 || len(a.mlsrtypes) > 0) {
		return argparse.NewUsageError("-p/--perms, -x/--xperms and -b/--bool apply to " +
			"TE rule searches only.")
	}
	return nil
}
