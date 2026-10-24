// Command sechecker runs the checks of a checker configuration file against
// an SELinux binary kernel policy. It is the sego reimplementation of
// setools' sechecker and reproduces the reference tool's report, exit statuses
// and diagnostics.
//
// A checker configuration error prints its message on stdout and exits with
// status 2; any other error (including a policy that cannot be opened) prints
// its message on stdout and exits with status 3; a run with failing checks
// exits with status 1, and a clean run with status 0.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/checker"
	"github.com/elnx/sego/internal/argparse"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/sechecker
var version = "dev"

// sectionSep separates the report sections.
const sectionSep = "---------------------------------------------------------\n\n"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes sechecker with argv (argv[0] is the program name) and returns
// the process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "sechecker"
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

	failures, err := runChecks(a, stdout, stderr)
	if err != nil {
		var configErr *checker.ConfigError
		if errors.As(err, &configErr) {
			// A configuration error is reported before any output is
			// written.
			fmt.Fprintln(stdout, err)
			return 2
		}
		if a.Flag("debug") {
			fmt.Fprintf(stderr, "%s%s\n", debug.Stack(), err)
			return 3
		}
		fmt.Fprintln(stdout, err)
		return 3
	}
	if failures > 0 {
		return 1
	}
	return 0
}

// runChecks loads the policy, parses the configuration, runs the checks and
// writes the report. It returns the number of failures.
func runChecks(a *argparse.Args, stdout, stderr io.Writer) (int, error) {
	path := a.Value("policy")
	if path == "" {
		verbosef(a, stderr, "Attempting to locate current running policy.")
		found, err := sego.FindPolicyPath()
		if err != nil {
			return 0, err
		}
		path = found
	}
	verbosef(a, stderr, "Opening SELinux policy %q", path)
	pol, err := sego.Open(path)
	if err != nil {
		return 0, err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", path)

	verbosef(a, stderr, "Opening policy checker config %s.", a.Value("config"))
	verbosef(a, stderr, "Validating configuration settings.")
	c, err := checker.NewChecker(pol, a.Value("config"), stderr, a.Flag("verbose") || a.Flag("debug"))
	if err != nil {
		return 0, err
	}
	verbosef(a, stderr, "Successfully opened policy checker config %s.", a.Value("config"))

	out := bufio.NewWriter(stdout)
	defer out.Flush()
	if output := a.Value("output_file"); output != "" {
		f, err := os.Create(output)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		failures := writeReport(w, c, pol, stderr, a)
		if err := w.Flush(); err != nil {
			return 0, err
		}
		return failures, nil
	}
	return writeReport(out, c, pol, stderr, a), nil
}

// writeReport runs every check and writes the report, returning the number of
// failures.
func writeReport(out io.Writer, c *checker.Checker, pol *sego.Policy, stderr io.Writer, a *argparse.Args) int {
	failures := 0

	fmt.Fprint(out, sectionSep)
	fmt.Fprintf(out, "Policy check configuration: %s\n", c.ConfigPath)
	fmt.Fprintf(out, "Policy being checked: %s\n", pol.Path())
	fmt.Fprintf(out, "Start time: %s\n\n", timestamp())

	var summary []summaryEntry
	for _, check := range c.Checks {
		checkFailures := 0

		fmt.Fprint(out, sectionSep)
		fmt.Fprintf(out, "Check name: %s\n\n", check.Name())
		if check.Desc() != "" {
			fmt.Fprintf(out, "Description: %s\n\n", check.Desc())
		}
		if check.Disable() != "" {
			fmt.Fprintf(out, "Check DISABLED.  Reason: %s\n\n", check.Disable())
			summary = append(summary, summaryEntry{check.Name(), "DISABLED (" + check.Disable() + ")"})
			continue
		}

		checkFailuresList, runErr := check.Run(out)
		if runErr != nil {
			// The reference skips the blank line it writes after a
			// successful run when the check raises.
			fmt.Fprintf(out, "Unexpected error: %s.  Failing check.\n\n", runErr)
			checkFailures++
		} else {
			checkFailures += len(checkFailuresList)
			fmt.Fprint(out, "\n")
		}

		if checkFailures > 0 {
			fmt.Fprint(out, "Check FAILED\n\n")
			summary = append(summary, summaryEntry{check.Name(),
				fmt.Sprintf("FAILED (%d failures)", checkFailures)})
		} else {
			fmt.Fprint(out, "Check PASSED\n\n")
			summary = append(summary, summaryEntry{check.Name(), "PASSED"})
		}
		failures += checkFailures
	}

	fmt.Fprint(out, sectionSep)
	fmt.Fprint(out, "Result Summary:\n\n")
	for _, entry := range summary {
		fmt.Fprintf(out, "%-39s %s\n", entry.name, entry.result)
	}
	fmt.Fprintf(out, "\n%d failure(s) found.\n\n", failures)
	fmt.Fprintf(out, "Policy check configuration: %s\n", c.ConfigPath)
	fmt.Fprintf(out, "Policy being checked: %s\n", pol.Path())
	fmt.Fprintf(out, "End time: %s\n", timestamp())
	verbosef(a, stderr, "%d failures found in %d checks.", failures, len(c.Checks))
	return failures
}

// summaryEntry is one line of the result summary.
type summaryEntry struct {
	name   string
	result string
}

// verbosef prints an informational message for -v/--verbose. The reference
// tool logs these through the logging module, which writes to stderr.
func verbosef(a *argparse.Args, stderr io.Writer, format string, args ...any) {
	if a.Flag("verbose") || a.Flag("debug") {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}

// timestamp renders the current UTC time the way Python's
// datetime.now(timezone.utc) prints it.
func timestamp() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05.000000+00:00")
}
