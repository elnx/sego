package main

// This file defines the seinfoflow command line. The parsing itself lives in
// the internal/argparse package; the option names, metavariables and argument
// groups mirror the reference CLI because they are its interface, while the
// help texts are this project's own (see NOTICE.md).

import (
	"github.com/elnx/sego/internal/argparse"
)

const (
	description = "Analyze the information flows of an SELinux binary policy."
	epilog      = "If no analysis is selected, all information flow out of the source will be printed."
)

// Argument group headings, in the order argparse prints them.
const (
	groupSettings  = "Analysis settings"
	groupAlgorithm = "Analysis algorithm"
	groupOptions   = "Analysis options"
)

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() []argparse.Option {
	return []argparse.Option{
		{Names: []string{"-h", "--help"}, Dest: "help",
			Help: "Show this help message and exit."},
		{Names: []string{"--full"}, Dest: "full",
			Help: "Print full rule lists for information flows."},
		{Names: []string{"--version"}, Dest: "version", Version: true,
			Help: "Show the version and exit."},
		{Names: []string{"--stats"}, Dest: "stats",
			Help: "Display statistics at the end of the analysis."},
		{Names: []string{"-v", "--verbose"}, Dest: "verbose",
			Help: "Report what is being analyzed on stderr."},
		{Names: []string{"--debug"}, Dest: "debug",
			Help: "Print a stack trace when something fails."},

		{Names: []string{"-p", "--policy"}, Metavar: "POLICY", Dest: "policy",
			Group: groupSettings,
			Help:  "Policy file to analyze; the running or installed policy is used when omitted."},
		{Names: []string{"-m", "--map"}, Metavar: "MAP", Dest: "map",
			Group: groupSettings, Help: "Path to an alternative permission map file."},
		{Names: []string{"-s", "--source"}, Metavar: "SOURCE", Dest: "source",
			Required: true, Group: groupSettings,
			Help: "Source type of the analysis."},
		{Names: []string{"-t", "--target"}, Metavar: "TARGET", Dest: "target",
			Group: groupSettings, Help: "Target type of the analysis."},

		{Names: []string{"-S", "--shortest_path"}, Dest: "shortest_path",
			Group: groupAlgorithm, Help: "Calculate all shortest paths."},
		{Names: []string{"-A", "--all_paths"}, Metavar: "MAX_STEPS", Dest: "all_paths",
			Int: true, Group: groupAlgorithm,
			Help: "Calculate all paths, with the specified maximum path length. (Expensive)"},

		{Names: []string{"-r", "--reverse"}, Dest: "reverse", Group: groupOptions,
			Help: "Display information flows into the source type. No effect if a target type is specified."},
		{Names: []string{"-w", "--min_weight"}, Metavar: "MIN_WEIGHT", Dest: "min_weight",
			Int: true, Default: "3", Group: groupOptions,
			Help: "Minimum permission weight. The default is 3."},
		{Names: []string{"-l", "--limit_flows"}, Metavar: "LIMIT_FLOWS", Dest: "limit_flows",
			Int: true, Group: groupOptions,
			Help: "Limit the number of flows that are printed; the default is unlimited."},
		{Names: []string{"-b", "--booleans"}, Metavar: "BOOLEANS", Dest: "booleans",
			Group: groupOptions,
			Help:  "Specify the Boolean values to use: default, or \"foo:true,bar:false\"."},
		{Names: []string{"-o", "--output_file"}, Metavar: "OUTPUT_FILE", Dest: "output_file",
			Group: groupOptions, Help: "Output file for graphical results, PNG format."},

		{Names: []string{"exclude"}, Dest: "exclude", Pos: true, Nargs: "*",
			Help: "List of excluded types in the analysis."},
	}
}
