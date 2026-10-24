// Command seinfoflow analyzes the information flows of an SELinux binary
// kernel policy: the direct flows into or out of a type, or the flows between
// two types. It is the sego reimplementation of setools' seinfoflow and
// reproduces the reference tool's output, exit statuses and diagnostics.
//
// Usage errors (bad usage of the command line, an inconsistent analysis
// selection) are printed to stderr with the usage line, and exit with status
// 2. Runtime errors (a policy or permission map that cannot be opened, an
// unknown type, an invalid weight) print only the error message, to stdout,
// and exit with status 1, exactly as the reference tool does.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
	"github.com/elnx/sego/internal/graphout"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/seinfoflow
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes seinfoflow with argv (argv[0] is the program name) and returns
// the process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "seinfoflow"
	if len(argv) > 0 {
		if base := filepath.Base(argv[0]); base != "" && base != "." {
			prog = base
		}
	}
	p := argparse.New(prog, description, epilog, optionTable())

	a, err := p.Parse(argv[1:])
	if err != nil {
		return p.Error(stderr, err)
	}
	if a.VersionRequested() {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if a.HelpRequested() {
		p.HelpTo(stdout)
		return 0
	}

	// A path analysis needs the target; a target is meaningless without one.
	// As in the reference, a path length of zero counts as "no algorithm".
	target := a.Value("target")
	pathMode := a.Flag("shortest_path") || a.Int("all_paths") != 0
	if target == "" && pathMode {
		return p.Error(stderr, argparse.NewUsageError(
			"The target type must be specified to determine a path."))
	}
	if target != "" && !pathMode {
		return p.Error(stderr, argparse.NewUsageError(
			"A target type is not used for flows in/out of a type."))
	}
	if a.Int("limit_flows") < 0 {
		return p.Error(stderr, argparse.NewUsageError(
			"Limit on information flows cannot be negative."))
	}

	states, useBooleans, err := parseBooleans(a.Value("booleans"))
	if err != nil {
		return p.Error(stderr, err)
	}

	out := bufio.NewWriter(stdout)
	err = infoflow(a, out, stderr, states, useBooleans)
	out.Flush()
	if err != nil {
		if a.Flag("debug") {
			// The reference tool re-raises the exception under --debug: it
			// exits 1 with a traceback on stderr instead of the message on
			// stdout.
			fmt.Fprintf(stderr, "%s%s\n", debug.Stack(), err)
			return 1
		}
		fmt.Fprintln(out, err)
		out.Flush()
		return 1
	}
	return 0
}

// parseBooleans parses the -b value: nil when the option was not given (both
// conditional branches count), an empty map for "default", and a name to
// state map otherwise.
func parseBooleans(value string) (map[string]bool, bool, error) {
	switch value {
	case "":
		return nil, false, nil
	case "default":
		return map[string]bool{}, true, nil
	}
	states := make(map[string]bool)
	for pair := range strings.SplitSeq(value, ",") {
		key, val, found := strings.Cut(pair, ":")
		if !found {
			return nil, false, argparse.NewUsageError(
				"Expected boolean format foo:true,bar:false")
		}
		switch strings.ToLower(val) {
		case "true":
			states[key] = true
		case "false":
			states[key] = false
		default:
			return nil, false, argparse.NewUsageError(
				"Conditional value must be true or false.")
		}
	}
	return states, true, nil
}

// infoflow loads the policy and permission map, runs the selected analysis and
// prints the results.
func infoflow(a *argparse.Args, out, stderr io.Writer, states map[string]bool, useBooleans bool) error {
	path := a.Value("policy")
	if path == "" {
		verbosef(a, stderr, "Attempting to locate current running policy.")
		found, err := sego.FindPolicyPath()
		if err != nil {
			return err
		}
		path = found
	}
	verbosef(a, stderr, "Opening SELinux policy %q", path)
	pol, err := sego.Open(path)
	if err != nil {
		return err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", path)
	mapPath := a.Value("map")
	if mapPath == "" {
		mapPath = "perm_map"
	}
	verbosef(a, stderr, "Opening permission map %q", mapPath)
	permMap, err := sego.NewPermissionMap(a.Value("map"))
	if err != nil {
		return err
	}
	verbosef(a, stderr, "Successfully opened permission map %q", mapPath)

	source := a.Value("source")
	target := a.Value("target")
	limit := a.Int("limit_flows")
	if _, err := pol.LookupType(source); err != nil {
		return err
	}
	if target != "" {
		if _, err := pol.LookupType(target); err != nil {
			return err
		}
	}

	g, err := sego.NewInfoFlowAnalysis(pol, permMap, a.Int("min_weight"),
		a.List("exclude"), states, useBooleans)
	if err != nil {
		return err
	}
	g.SetLogger(verboseLogger(a, stderr))

	count := 0
	if a.Flag("shortest_path") || a.Int("all_paths") != 0 {
		var paths [][]sego.InfoFlowStep
		if a.Flag("shortest_path") {
			paths = g.ShortestPaths(source, target)
		} else {
			maxSteps := a.Int("all_paths")
			if maxSteps < 1 {
				return fmt.Errorf("Information flow max depth must be positive.")
			}
			paths = g.AllPaths(source, target, maxSteps)
		}

		if output := a.Value("output_file"); output != "" {
			return writeGraph(output, g.GraphicalEdges(source, target,
				map[bool]string{true: "shortest", false: "all"}[a.Flag("shortest_path")],
				a.Int("all_paths")))
		}

		for _, steps := range paths {
			count++
			fmt.Fprintf(out, "Flow %d:\n", count)
			for i, step := range steps {
				if a.Flag("full") {
					fmt.Fprintf(out, "  Step %d: %s\n\n", i+1, step.Full())
				} else {
					fmt.Fprintf(out, "  Step %d: %s\n", i+1, step.Short())
				}
			}
			if limit > 0 && count >= limit {
				break
			}
		}
		fmt.Fprintf(out, "\n%d information flow(s) found.\n", count)
	} else {
		var flows []sego.InfoFlowStep
		if a.Flag("reverse") {
			flows = g.FlowsIn(source)
		} else {
			flows = g.FlowsOut(source)
		}

		if output := a.Value("output_file"); output != "" {
			mode := "out"
			if a.Flag("reverse") {
				mode = "in"
			}
			return writeGraph(output, g.GraphicalEdges(source, "", mode, 0))
		}

		for _, step := range flows {
			count++
			if a.Flag("full") {
				fmt.Fprintf(out, "Flow %d: %s\n\n", count, step.Full())
			} else {
				fmt.Fprintf(out, "Flow %d: %s\n", count, step.Short())
			}
			if limit > 0 && count >= limit {
				break
			}
		}
		fmt.Fprintf(out, "\n%d information flow(s) found.\n", count)
	}

	if a.Flag("stats") {
		fmt.Fprint(out, "\nGraph statistics:\n")
		fmt.Fprintln(out, g.Stats())
	}
	return nil
}

// verbosef prints an informational message for -v/--verbose. The reference
// tool logs these through the logging module, which writes to stderr.
func verbosef(a *argparse.Args, stderr io.Writer, format string, args ...any) {
	if a.Flag("verbose") || a.Flag("debug") {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}

// verboseLogger returns the analysis log sink, or nil when -v is not set.
func verboseLogger(a *argparse.Args, stderr io.Writer) func(string, ...any) {
	if !a.Flag("verbose") && !a.Flag("debug") {
		return nil
	}
	return func(format string, args ...any) {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}

// writeGraph renders the result graph as a PNG image.
func writeGraph(path string, edges []sego.GraphEdge) error {
	nodes := make([]string, 0, len(edges)*2)
	plain := make([][2]string, 0, len(edges))
	for _, e := range edges {
		nodes = append(nodes, e.Source(), e.Target())
		plain = append(plain, [2]string{e.Source(), e.Target()})
	}
	return graphout.WritePNG(path, nodes, plain)
}
