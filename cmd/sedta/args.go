package main

// This file defines the sedta command line. The parsing itself lives in the
// internal/argparse package; the option names, metavariables and argument
// groups mirror the reference CLI because they are its interface, while the
// help texts are this project's own (see NOTICE.md).

import (
	"github.com/elnx/sego/internal/argparse"
)

const (
	description = "Analyze the domain transitions of an SELinux binary policy."
	epilog      = "If no analysis is selected, all forward transitions out of the source will be printed."
)

// Argument group headings, in the order argparse prints them.
const (
	groupAlgorithm = "Analysis algorithm"
	groupOptions   = "Analysis options"
)

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() []argparse.Option {
	return []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"-p", "--policy"}, Metavar: "POLICY", Dest: "policy",
			Help: "Policy file to analyze; the running or installed policy is used when omitted."},
		{Names: []string{"-s", "--source"}, Metavar: "SOURCE", Dest: "source", Required: true,
			Help: "Source type of the analysis."},
		{Names: []string{"-t", "--target"}, Metavar: "TARGET", Dest: "target",
			Help: "Target type of the analysis."},
		{Names: []string{"--full"}, Dest: "full",
			Help: "Print rule lists for transitions."},
		{Names: []string{"--stats"}, Dest: "stats",
			Help: "Display statistics at the end of the analysis."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being analyzed on stderr."},
		{Names: []string{"--debug"}, Dest: "debug",
			Help: "Print a stack trace when something fails."},

		{Names: []string{"-S", "--shortest_path"}, Dest: "shortest_path",
			Group: groupAlgorithm, Help: "Calculate all shortest paths."},
		{Names: []string{"-A", "--all_paths"}, Metavar: "MAX_STEPS", Dest: "all_paths",
			Int: true, Group: groupAlgorithm,
			Help: "Calculate all paths, with the specified maximum path length. (Expensive)"},

		{Names: []string{"-r", "--reverse"}, Dest: "reverse",
			Group: groupOptions, Help: "Perform a reverse DTA."},
		{Names: []string{"-l", "--limit_trans"}, Metavar: "LIMIT_TRANS", Dest: "limit_trans",
			Int: true, Group: groupOptions,
			Help: "Limit the number of transitions that are printed; the default is unlimited."},
		{Names: []string{"-o", "--output_file"}, Metavar: "OUTPUT_FILE", Dest: "output_file",
			Group: groupOptions, Help: "Output file for graphical results, PNG format."},

		{Names: []string{"exclude"}, Dest: "exclude", Pos: true, Nargs: "*",
			Help: "List of excluded types in the analysis."},
	}
}
