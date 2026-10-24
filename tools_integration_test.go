// Package sego_test holds the end to end tests of the commands.
package sego_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The tool query matrix and the recorded reference output. See
// testdata/tools.txt for the format and testdata/gen_tools_expected.sh for how
// the goldens were produced.
const (
	toolsMatrixFile  = "testdata/tools.txt"
	toolsExpectedDir = "testdata/expected_tools"
)

// toolCase is one case of the tool query matrix.
type toolCase struct {
	tool   string
	name   string
	argv   []string
	status int
}

// TestToolQueries replays testdata/tools.txt: each command is run with its
// arguments and its stdout and exit status are compared with the recorded
// reference output.
func TestToolQueries(t *testing.T) {
	data, err := os.ReadFile(toolsMatrixFile)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not present, so the tool matrix has not been generated yet", toolsMatrixFile)
	}
	if err != nil {
		t.Fatalf("reading %s: %v", toolsMatrixFile, err)
	}
	cases := parseToolCases(t, string(data))
	if len(cases) == 0 {
		t.Skipf("%s contains no cases", toolsMatrixFile)
	}

	bins := buildTools(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(toolsExpectedDir, tc.name+".txt"))
			if err != nil {
				t.Fatalf("reading the expected output of case %s: %v", tc.name, err)
			}

			var stdout, stderr bytes.Buffer
			cmd := exec.Command(bins[tc.tool], tc.argv...)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			status := 0
			if err := cmd.Run(); err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("running %s: %v", bins[tc.tool], err)
				}
				status = exitErr.ExitCode()
			}

			command := tc.tool + " " + strings.Join(tc.argv, " ")
			if status != tc.status {
				t.Errorf("%s\nexit status = %d, want %d\nstderr:\n%s",
					command, status, tc.status, indent(stderr.String()))
			}
			got := stdout.Bytes()
			if tc.tool == "sechecker" {
				// The report carries the run's timestamps; the recorded
				// goldens omit them.
				got = stripRunTimes(got)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s\nstdout does not match %s\n%s",
					command, filepath.Join(toolsExpectedDir, tc.name+".txt"), diffLines(want, got))
			}
		})
	}
}

// stripRunTimes removes the start and end time lines of a sechecker report.
func stripRunTimes(out []byte) []byte {
	var kept [][]byte
	for line := range bytes.SplitSeq(out, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("Start time: ")) ||
			bytes.HasPrefix(line, []byte("End time: ")) {
			continue
		}
		kept = append(kept, line)
	}
	return bytes.Join(kept, []byte("\n"))
}

// toolNamePattern matches the matrix's tool names.
var toolNamePattern = regexp.MustCompile(`^[a-z]+$`)

// parseToolCases reads the tab separated tool matrix: the tool, the case name,
// the command line arguments and, when it is not zero, the expected exit
// status.
func parseToolCases(t *testing.T, data string) []toolCase {
	t.Helper()
	var cases []toolCase
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 || len(fields) > 4 {
			t.Fatalf("%s:%d: need tool, case name, arguments and an optional exit status, got %d fields",
				toolsMatrixFile, i+1, len(fields))
		}
		tc := toolCase{tool: fields[0], name: fields[1], argv: strings.Fields(fields[2])}
		if len(fields) == 4 && strings.TrimSpace(fields[3]) != "" {
			status, err := strconv.Atoi(strings.TrimSpace(fields[3]))
			if err != nil {
				t.Fatalf("%s:%d: expected exit status %q: %v", toolsMatrixFile, i+1, fields[3], err)
			}
			tc.status = status
		}
		if !toolNamePattern.MatchString(tc.tool) {
			t.Fatalf("%s:%d: tool name %q is not in [a-z]+", toolsMatrixFile, i+1, tc.tool)
		}
		if !caseNamePattern.MatchString(tc.name) {
			t.Fatalf("%s:%d: case name %q is not in [A-Za-z0-9_.-]+", toolsMatrixFile, i+1, tc.name)
		}
		if len(tc.argv) == 0 {
			t.Fatalf("%s:%d: case %s has no arguments", toolsMatrixFile, i+1, tc.name)
		}
		cases = append(cases, tc)
	}
	return cases
}

// TestParseToolCases covers the tool matrix format.
func TestParseToolCases(t *testing.T) {
	const matrix = `# a comment line

seinfo	seinfo_all	testdata/policies/sego_test-v32.pol --all
sedta	sedta_bad	testdata/policies/sego_test-v32.pol -s nosuch	1
`
	got := parseToolCases(t, matrix)
	want := []toolCase{
		{tool: "seinfo", name: "seinfo_all",
			argv: []string{"testdata/policies/sego_test-v32.pol", "--all"}},
		{tool: "sedta", name: "sedta_bad",
			argv: []string{"testdata/policies/sego_test-v32.pol", "-s", "nosuch"}, status: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d cases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].tool != want[i].tool || got[i].name != want[i].name ||
			got[i].status != want[i].status || strings.Join(got[i].argv, " ") != strings.Join(want[i].argv, " ") {
			t.Errorf("case %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// buildTools builds every command under test into a temporary directory, so
// that the test never writes into the working tree.
func buildTools(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	tools := map[string]string{
		"seinfo": "", "sediff": "", "sedta": "", "seinfoflow": "", "sechecker": "",
	}
	for tool := range tools {
		bin := filepath.Join(dir, tool)
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/"+tool)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build -o %s ./cmd/%s: %v\n%s", bin, tool, err, out)
		}
		tools[tool] = bin
	}
	return tools
}
