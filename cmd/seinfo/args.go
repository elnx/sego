package main

// This file defines the seinfo command line. The parsing itself lives in the
// internal/argparse package; the option names, metavariables and argument
// groups mirror the reference CLI because they are its interface, while the
// help texts are this project's own (see NOTICE.md).

import (
	"github.com/elnx/sego/internal/argparse"
)

const (
	description = "Report the components of an SELinux binary policy."
	epilog      = ""
)

// Argument group headings, in the order argparse prints them.
const (
	groupComponent = "Component Queries"
	groupSELinux   = "SELinux-specific Queries"
	groupXen       = "Xen-specific Queries"
)

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text. The component
// queries are nargs='?' options: bare, they select every component; with a
// value, they filter by name.
func optionTable() []argparse.Option {
	return []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"policy"}, Dest: "policy", Pos: true, Nargs: "?",
			Help: "Policy file to read; the running or installed policy is used when omitted."},
		{Names: []string{"-x", "--expand"}, Dest: "expand",
			Help: "Show statements for the selected components instead of their names."},
		{Names: []string{"--flat"}, Dest: "flat",
			Help: "List the items only, without section headers."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being read on stderr."},
		{Names: []string{"--debug"}, Dest: "debug",
			Help: "Print a stack trace when something fails."},

		{Names: []string{"-a", "--attribute"}, Dest: "typeattrquery", Metavar: "ATTR",
			Nargs: "?", Group: groupComponent, Help: "List type attributes."},
		{Names: []string{"-b", "--bool"}, Dest: "boolquery", Metavar: "BOOL",
			Nargs: "?", Group: groupComponent, Help: "List conditional Booleans."},
		{Names: []string{"-c", "--class"}, Dest: "classquery", Metavar: "CLASS",
			Nargs: "?", Group: groupComponent, Help: "List object classes."},
		{Names: []string{"-r", "--role"}, Dest: "rolequery", Metavar: "ROLE",
			Nargs: "?", Group: groupComponent, Help: "List roles."},
		{Names: []string{"-t", "--type"}, Dest: "typequery", Metavar: "TYPE",
			Nargs: "?", Group: groupComponent, Help: "List types."},
		{Names: []string{"-u", "--user"}, Dest: "userquery", Metavar: "USER",
			Nargs: "?", Group: groupComponent, Help: "List users."},
		{Names: []string{"--category"}, Dest: "mlscatsquery", Metavar: "CAT",
			Nargs: "?", Group: groupComponent, Help: "List MLS categories."},
		{Names: []string{"--common"}, Dest: "commonquery", Metavar: "COMMON",
			Nargs: "?", Group: groupComponent, Help: "List common permission sets."},
		{Names: []string{"--constrain"}, Dest: "constraintquery", Metavar: "CLASS",
			Nargs: "?", Group: groupComponent, Help: "List constrain statements."},
		{Names: []string{"--default"}, Dest: "defaultquery", Metavar: "CLASS",
			Nargs: "?", Group: groupComponent, Help: "List default_* statements."},
		{Names: []string{"--permissive"}, Dest: "permissivequery", Metavar: "TYPE",
			Nargs: "?", Group: groupComponent, Help: "List permissive types."},
		{Names: []string{"--polcap"}, Dest: "polcapquery", Metavar: "NAME",
			Nargs: "?", Group: groupComponent, Help: "List policy capabilities."},
		{Names: []string{"--role_types"}, Dest: "roletypesquery", Metavar: "TYPE",
			Group: groupComponent, Help: "List the roles whose type set contains the given type."},
		{Names: []string{"--sensitivity"}, Dest: "mlssensquery", Metavar: "SENS",
			Nargs: "?", Group: groupComponent, Help: "List MLS sensitivities."},
		{Names: []string{"--typebounds"}, Dest: "typeboundsquery", Metavar: "BOUND_TYPE",
			Nargs: "?", Group: groupComponent, Help: "List typebounds statements."},
		{Names: []string{"--validatetrans"}, Dest: "validatetransquery", Metavar: "CLASS",
			Nargs: "?", Group: groupComponent, Help: "List validatetrans statements."},
		{Names: []string{"--all"}, Dest: "all",
			Group: groupComponent,
			Help:  "List every component. On a Xen policy, the Xen components are listed too"},

		{Names: []string{"--fs_use"}, Dest: "fsusequery", Metavar: "FS_TYPE",
			Nargs: "?", Group: groupSELinux, Help: "List fs_use statements."},
		{Names: []string{"--genfscon"}, Dest: "genfsconquery", Metavar: "FS_TYPE",
			Nargs: "?", Group: groupSELinux, Help: "List genfscon statements."},
		{Names: []string{"--ibpkeycon"}, Dest: "ibpkeyconquery", Metavar: "PKEY[-PKEY]",
			Nargs: "?", Group: groupSELinux, Help: "List ibpkeycon statements."},
		{Names: []string{"--ibendportcon"}, Dest: "ibendportconquery", Metavar: "NAME",
			Nargs: "?", Group: groupSELinux, Help: "List ibendportcon statements."},
		{Names: []string{"--initialsid"}, Dest: "initialsidquery", Metavar: "NAME",
			Nargs: "?", Group: groupSELinux, Help: "List initial SIDs and their contexts."},
		{Names: []string{"--netifcon"}, Dest: "netifconquery", Metavar: "DEVICE",
			Nargs: "?", Group: groupSELinux, Help: "List netifcon statements."},
		{Names: []string{"--nodecon"}, Dest: "nodeconquery", Metavar: "ADDR",
			Nargs: "?", Group: groupSELinux, Help: "List nodecon statements."},
		{Names: []string{"--portcon"}, Dest: "portconquery", Metavar: "PORTNUM[-PORTNUM]",
			Nargs: "?", Group: groupSELinux, Help: "List portcon statements."},

		{Names: []string{"--devicetreecon"}, Dest: "devicetreeconquery", Metavar: "PATH",
			Nargs: "?", Group: groupXen, Help: "List devicetreecon statements."},
		{Names: []string{"--iomemcon"}, Dest: "iomemconquery", Metavar: "ADDR[-ADDR]",
			Nargs: "?", Group: groupXen, Help: "List iomemcon statements."},
		{Names: []string{"--ioportcon"}, Dest: "ioportconquery", Metavar: "PORTNUM[-PORTNUM]",
			Nargs: "?", Group: groupXen, Help: "List ioportcon statements."},
		{Names: []string{"--pcidevicecon"}, Dest: "pcideviceconquery", Metavar: "DEVICE",
			Nargs: "?", Group: groupXen, Help: "List pcidevicecon statements."},
		{Names: []string{"--pirqcon"}, Dest: "pirqconquery", Metavar: "IRQ",
			Nargs: "?", Group: groupXen, Help: "List pirqcon statements."},
	}
}
