package main

// This file defines the sechecker command line. The parsing itself lives in
// the internal/argparse package; the option names, metavariables and argument
// groups mirror the reference CLI because they are its interface, while the
// help texts are this project's own (see NOTICE.md).

import (
	"github.com/elnx/sego/internal/argparse"
)

const (
	description = "Run the configured policy checks against an SELinux binary policy."
	epilog      = ""
)

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() []argparse.Option {
	return []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"config"}, Dest: "config", Pos: true,
			Help: "Path to the checker configuration file."},
		{Names: []string{"policy"}, Dest: "policy", Pos: true, Nargs: "?",
			Help: "Policy file to check; the running or installed policy is used when omitted."},
		{Names: []string{"-o", "--output_file"}, Metavar: "OUTPUT_FILE", Dest: "output_file",
			Help: "Path to write the check report to."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being checked on stderr."},
		{Names: []string{"--debug"}, Dest: "debug",
			Help: "Print a stack trace when something fails."},
	}
}
