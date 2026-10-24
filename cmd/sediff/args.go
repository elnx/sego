package main

// This file defines the sediff command line. The parsing itself lives in the
// internal/argparse package; the option names, metavariables and argument
// groups mirror the reference CLI because they are its interface, while the
// help texts are this project's own (see NOTICE.md).

import (
	"github.com/elnx/sego/internal/argparse"
)

const (
	description = "Report the semantic differences of two SELinux binary policies."
	epilog      = "If no differences are selected, all differences will be printed."
)

// Argument group headings, in the order argparse prints them.
const (
	groupComponent = "component differences"
	groupTE        = "type enforcement rule differences"
	groupRBAC      = "RBAC rule differences"
	groupMLS       = "MLS rule differences"
	groupConstrain = "Constraint differences"
	groupLabeling  = "labeling statement differences"
	groupOther     = "other differences"
)

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() []argparse.Option {
	return []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"POLICY1"}, Dest: "POLICY1", Pos: true,
			Help: "Path to the first SELinux policy to diff."},
		{Names: []string{"POLICY2"}, Dest: "POLICY2", Pos: true,
			Help: "Path to the second SELinux policy to diff."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"--stats"}, Dest: "stats",
			Help: "Show the difference counts only."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being compared on stderr."},
		{Names: []string{"--debug"}, Dest: "debug",
			Help: "Print a stack trace when something fails."},

		{Names: []string{"--common"}, Dest: "common", Group: groupComponent,
			Help: "Report common differences."},
		{Names: []string{"-c", "--class"}, Dest: "class", Group: groupComponent,
			Help: "Report class differences."},
		{Names: []string{"-t", "--type"}, Dest: "type", Group: groupComponent,
			Help: "Report type differences."},
		{Names: []string{"-a", "--attribute"}, Dest: "attribute", Group: groupComponent,
			Help: "Report type attribute differences."},
		{Names: []string{"-r", "--role"}, Dest: "role", Group: groupComponent,
			Help: "Report role differences."},
		{Names: []string{"-u", "--user"}, Dest: "user", Group: groupComponent,
			Help: "Report user differences."},
		{Names: []string{"-b", "--bool"}, Dest: "bool", Group: groupComponent,
			Help: "Report Boolean differences."},
		{Names: []string{"--sensitivity"}, Dest: "sensitivity", Group: groupComponent,
			Help: "Report MLS sensitivity differences."},
		{Names: []string{"--category"}, Dest: "category", Group: groupComponent,
			Help: "Report MLS category differences."},
		{Names: []string{"--level"}, Dest: "level", Group: groupComponent,
			Help: "Report MLS level definition differences."},

		{Names: []string{"-A"}, Dest: "A", Group: groupTE,
			Help: "Report allow and allowxperm rule differences."},
		{Names: []string{"--allow"}, Dest: "allow", Group: groupTE,
			Help: "Report allow rule differences."},
		{Names: []string{"--auditallow"}, Dest: "auditallow", Group: groupTE,
			Help: "Report auditallow rule differences."},
		{Names: []string{"--dontaudit"}, Dest: "dontaudit", Group: groupTE,
			Help: "Report dontaudit rule differences."},
		{Names: []string{"--allowxperm"}, Dest: "allowxperm", Group: groupTE,
			Help: "Report allowxperm rule differences."},
		{Names: []string{"--auditallowxperm"}, Dest: "auditallowxperm", Group: groupTE,
			Help: "Report auditallowxperm rule differences."},
		{Names: []string{"--dontauditxperm"}, Dest: "dontauditxperm", Group: groupTE,
			Help: "Report dontauditxperm rule differences."},
		{Names: []string{"-T", "--type_trans"}, Dest: "type_trans", Group: groupTE,
			Help: "Report type_transition rule differences."},
		{Names: []string{"--type_change"}, Dest: "type_change", Group: groupTE,
			Help: "Report type_change rule differences."},
		{Names: []string{"--type_member"}, Dest: "type_member", Group: groupTE,
			Help: "Report type_member rule differences."},

		{Names: []string{"--role_allow"}, Dest: "role_allow", Group: groupRBAC,
			Help: "Report role allow rule differences."},
		{Names: []string{"--role_trans"}, Dest: "role_trans", Group: groupRBAC,
			Help: "Report role_transition rule differences."},

		{Names: []string{"--range_trans"}, Dest: "range_trans", Group: groupMLS,
			Help: "Report range_transition rule differences."},

		{Names: []string{"--constrain"}, Dest: "constrain", Group: groupConstrain,
			Help: "Report constrain differences."},
		{Names: []string{"--mlsconstrain"}, Dest: "mlsconstrain", Group: groupConstrain,
			Help: "Report mlsconstrain differences."},
		{Names: []string{"--validatetrans"}, Dest: "validatetrans", Group: groupConstrain,
			Help: "Report validatetrans differences."},
		{Names: []string{"--mlsvalidatetrans"}, Dest: "mlsvalidatetrans", Group: groupConstrain,
			Help: "Report mlsvalidatetrans differences."},

		{Names: []string{"--ibendportcon"}, Dest: "ibendportcon", Group: groupLabeling,
			Help: "Report ibendportcon differences."},
		{Names: []string{"--ibpkeycon"}, Dest: "ibpkeycon", Group: groupLabeling,
			Help: "Report ibpkeycon differences."},
		{Names: []string{"--initialsid"}, Dest: "initialsid", Group: groupLabeling,
			Help: "Report initial SID differences."},
		{Names: []string{"--fs_use"}, Dest: "fs_use", Group: groupLabeling,
			Help: "Report fs_use_* differences."},
		{Names: []string{"--genfscon"}, Dest: "genfscon", Group: groupLabeling,
			Help: "Report genfscon differences."},
		{Names: []string{"--netifcon"}, Dest: "netifcon", Group: groupLabeling,
			Help: "Report netifcon differences."},
		{Names: []string{"--nodecon"}, Dest: "nodecon", Group: groupLabeling,
			Help: "Report nodecon differences."},
		{Names: []string{"--portcon"}, Dest: "portcon", Group: groupLabeling,
			Help: "Report portcon differences."},

		{Names: []string{"--default"}, Dest: "default", Group: groupOther,
			Help: "Report default_* differences."},
		{Names: []string{"--property"}, Dest: "property", Group: groupOther,
			Help: "Report policy property differences (handle_unknown, version, MLS)."},
		{Names: []string{"--polcap"}, Dest: "polcap", Group: groupOther,
			Help: "Report policy capability differences."},
		{Names: []string{"--typebounds"}, Dest: "typebounds", Group: groupOther,
			Help: "Report typebounds differences."},
	}
}
