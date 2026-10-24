// Command sedta analyzes the domain transitions of an SELinux binary kernel
// policy: the transitions into, out of, or between domains. It is the sego
// reimplementation of setools' sedta and reproduces the reference tool's
// output, exit statuses and diagnostics.
//
// Usage errors (bad usage of the command line) are printed to stderr with the
// usage line, and exit with status 2. Runtime errors (a policy that cannot be
// opened, an unknown type, an invalid depth) print only the error message, to
// stdout, and exit with status 1, exactly as the reference tool does.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
	"github.com/elnx/sego/internal/graphout"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/sedta
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes sedta with argv (argv[0] is the program name) and returns the
// process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "sedta"
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

	// The analysis selection and the target must agree on whether a path is
	// wanted. As in the reference tool, a path length of zero counts as "no
	// algorithm selected".
	target := a.Value("target")
	pathMode := a.Flag("shortest_path") || a.Int("all_paths") != 0
	if target == "" && pathMode {
		return p.Error(stderr, argparse.NewUsageError(
			"The target type must be specified to determine a path."))
	}
	if target != "" && !pathMode {
		return p.Error(stderr, argparse.NewUsageError(
			"An algorithm must be specified to determine a path."))
	}

	out := bufio.NewWriter(stdout)
	err = sedta(a, out, stderr)
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

// sedta loads the policy, runs the selected analysis and prints the results.
func sedta(a *argparse.Args, out, stderr io.Writer) error {
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

	g, err := sego.NewDomainTransitionAnalysis(pol, a.List("exclude"))
	if err != nil {
		return err
	}
	g.SetLogger(verboseLogger(a, stderr))

	source := a.Value("source")
	target := a.Value("target")
	limit := a.Int("limit_trans")
	// The reference resolves the source and target through its type lookup,
	// which reports unknown names.
	if _, err := pol.LookupType(source); err != nil {
		return err
	}
	if target != "" {
		if _, err := pol.LookupType(target); err != nil {
			return err
		}
	}

	count := 0
	if a.Flag("shortest_path") || a.Int("all_paths") != 0 {
		// Only the path modes honor the reverse option; the single
		// transition mode selects its direction with its mode instead.
		g.SetReverse(a.Flag("reverse"))
		var paths [][]sego.DomainTransition
		if a.Flag("shortest_path") {
			paths = g.ShortestPaths(source, target)
		} else {
			maxSteps := a.Int("all_paths")
			if maxSteps < 1 {
				return fmt.Errorf("Domain transition max depth must be positive.")
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
			fmt.Fprintf(out, "Domain transition path %d:\n", count)
			for i, step := range steps {
				if a.Flag("full") {
					fmt.Fprintf(out, "Step %d: %s\n\n", i+1, step.Full())
				} else {
					fmt.Fprintf(out, "Step %d: %s\n", i+1, step.Short())
				}
			}
			if limit > 0 && count >= limit {
				break
			}
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "\n%d domain transition path(s) found.\n", count)
	} else {
		var transitions []sego.DomainTransition
		if a.Flag("reverse") {
			transitions = g.TransitionsIn(source)
		} else {
			transitions = g.TransitionsOut(source)
		}

		if output := a.Value("output_file"); output != "" {
			mode := "out"
			if a.Flag("reverse") {
				mode = "in"
			}
			return writeGraph(output, g.GraphicalEdges(source, "", mode, 0))
		}

		for _, step := range transitions {
			count++
			if a.Flag("full") {
				fmt.Fprintf(out, "Transition %d: %s\n\n", count, step.Full())
			} else {
				fmt.Fprintf(out, "Transition %d: %s\n", count, step.Short())
			}
			if limit > 0 && count >= limit {
				break
			}
		}
		fmt.Fprintf(out, "\n%d domain transition(s) found.\n", count)
	}

	if a.Flag("stats") {
		fmt.Fprint(out, "\nGraph statistics:\n")
		fmt.Fprintln(out, g.Stats())
	}
	return nil
}
