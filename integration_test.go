// Package sego_test holds the end to end test of the sesearch command.
package sego_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The query matrix and the recorded reference output. See testdata/queries.txt
// for the format and testdata/gen_expected.sh for how the fixtures and the
// expected output were produced.
const (
	queriesFile = "testdata/queries.txt"
	expectedDir = "testdata/expected"
)

// caseNamePattern is the naming rule of the matrix: the case name is also the
// file name stem of the expected output, so it must not escape the directory.
var caseNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// TestSesearchQueries replays testdata/queries.txt: the same command line is
// run against the same policy fixture and its stdout and exit status are
// compared with the recorded reference output.
func TestSesearchQueries(t *testing.T) {
	data, err := os.ReadFile(queriesFile)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not present, so the query matrix has not been generated yet", queriesFile)
	}
	if err != nil {
		t.Fatalf("reading %s: %v", queriesFile, err)
	}

	cases := parseQueries(t, string(data))
	if len(cases) == 0 {
		t.Skipf("%s contains no cases", queriesFile)
	}
	for _, tc := range cases {
		if _, err := os.Stat(tc.policy); err != nil {
			t.Fatalf("%s: the policy fixture of case %s is missing: %v (regenerate the fixtures with make fixtures)",
				queriesFile, tc.name, err)
		}
	}

	bin := buildSesearch(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(expectedDir, tc.name+".txt"))
			if err != nil {
				t.Fatalf("reading the expected output of case %s: %v "+
					"(every case needs a file, empty when nothing matches)", tc.name, err)
			}

			var stdout, stderr bytes.Buffer
			cmd := exec.Command(bin, append(append([]string{}, tc.argv...), tc.policy)...)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			status := 0
			if err := cmd.Run(); err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("running %s: %v", bin, err)
				}
				status = exitErr.ExitCode()
			}

			command := "sesearch " + strings.Join(tc.argv, " ") + " " + tc.policy
			if status != tc.status {
				t.Errorf("%s\nexit status = %d, want %d\nstderr:\n%s",
					command, status, tc.status, indent(stderr.String()))
			}
			if !bytes.Equal(stdout.Bytes(), want) {
				t.Errorf("%s\nstdout does not match %s\n%s",
					command, filepath.Join(expectedDir, tc.name+".txt"), diffLines(want, stdout.Bytes()))
			}
		})
	}
}

// query is one case of the query matrix.
type query struct {
	name   string
	policy string
	argv   []string
	status int // expected exit status
}

// parseQueries reads the tab separated query matrix: the case name, the policy
// fixture relative to the repository root, the command line arguments and,
// when it is not zero, the expected exit status.
func parseQueries(t *testing.T, data string) []query {
	t.Helper()
	var cases []query
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		// An earlier revision of the matrix carried a stray empty field
		// between the case name and the fixture; accept it.
		if len(fields) > 1 && fields[1] == "" {
			fields = append(fields[:1], fields[2:]...)
		}
		if len(fields) < 3 {
			t.Fatalf("%s:%d: need a case name, a policy and arguments, got %d fields",
				queriesFile, i+1, len(fields))
		}

		tc := query{name: fields[0], policy: fields[1], argv: strings.Fields(fields[2])}
		if len(fields) > 3 && strings.TrimSpace(fields[3]) != "" {
			status, err := strconv.Atoi(strings.TrimSpace(fields[3]))
			if err != nil {
				t.Fatalf("%s:%d: expected exit status %q: %v", queriesFile, i+1, fields[3], err)
			}
			tc.status = status
		}

		if !caseNamePattern.MatchString(tc.name) {
			t.Fatalf("%s:%d: case name %q is not in [A-Za-z0-9_.-]+", queriesFile, i+1, tc.name)
		}
		if tc.policy == "" || len(tc.argv) == 0 {
			t.Fatalf("%s:%d: case %s needs a policy and arguments", queriesFile, i+1, tc.name)
		}
		cases = append(cases, tc)
	}
	return cases
}

// TestParseQueries covers the query matrix format, including the stray empty
// field an earlier revision of the file carried after the case name.
func TestParseQueries(t *testing.T) {
	const matrix = `# a comment line

allow_all	testdata/policies/sego_test-v32.pol	--allow
no_ruletype	testdata/policies/sego_test-v32.pol	-s app_t	2
stray_field		testdata/policies/sego_test-v32.pol	-T
`
	got := parseQueries(t, matrix)
	want := []query{
		{name: "allow_all", policy: "testdata/policies/sego_test-v32.pol", argv: []string{"--allow"}},
		{name: "no_ruletype", policy: "testdata/policies/sego_test-v32.pol",
			argv: []string{"-s", "app_t"}, status: 2},
		{name: "stray_field", policy: "testdata/policies/sego_test-v32.pol", argv: []string{"-T"}},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d cases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].name != want[i].name || got[i].policy != want[i].policy ||
			got[i].status != want[i].status || !slices.Equal(got[i].argv, want[i].argv) {
			t.Errorf("case %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestDiffLines checks that a mismatch is reported with the differing lines.
func TestDiffLines(t *testing.T) {
	diff := diffLines([]byte("one\ntwo\nthree\n"), []byte("one\nTWO\nthree\n"))
	for _, want := range []string{"first difference on line 2", "- two", "+ TWO"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff does not mention %q:\n%s", want, diff)
		}
	}
	if diff := diffLines([]byte("same\n"), []byte("same\n")); strings.Contains(diff, "difference") {
		t.Errorf("identical output reported as different:\n%s", diff)
	}
}

// buildSesearch builds the command under test into a temporary directory, so
// that the test never writes into the working tree.
func buildSesearch(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sesearch")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/sesearch")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -o %s ./cmd/sesearch: %v\n%s", bin, err, out)
	}
	return bin
}

// diffLines describes the first difference between the expected and the actual
// output, in a diff-like form.
func diffLines(want, got []byte) string {
	wantLines, gotLines := splitLines(want), splitLines(got)

	first := -1
	for i := 0; i < max(len(wantLines), len(gotLines)); i++ {
		if lineAt(wantLines, i) != lineAt(gotLines, i) {
			first = i
			break
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- expected: %d lines, %d bytes\n", len(wantLines), len(want))
	fmt.Fprintf(&b, "+++ actual:   %d lines, %d bytes\n", len(gotLines), len(got))
	if first < 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "first difference on line %d (- expected, + actual):\n", first+1)
	for i := max(first-2, 0); i < min(first+3, max(len(wantLines), len(gotLines))); i++ {
		wantLine, gotLine := lineAt(wantLines, i), lineAt(gotLines, i)
		if wantLine == gotLine {
			fmt.Fprintf(&b, "  %s\n", wantLine)
			continue
		}
		fmt.Fprintf(&b, "- %s\n+ %s\n", wantLine, gotLine)
	}
	return b.String()
}

// splitLines splits command output into lines, dropping the newline of the
// last line so that the two outputs line up.
func splitLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lineAt returns a line, or the empty string beyond the end of the output.
func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return ""
	}
	return lines[i]
}

// indent indents multi line output, so that it stays readable inside a test
// failure message.
func indent(s string) string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return ""
	}
	return "    " + strings.ReplaceAll(s, "\n", "\n    ") + "\n"
}
