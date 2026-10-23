package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/elnx/sego"
)

// The usage output is part of the tool's interface: it has to match the
// setools 4.8 CLI. The expected text below was verified byte for byte against
// `python3 /path/to/setools/sesearch --help` (setools 4.8) with COLUMNS=80.
const goldenUsage = `usage: sesearch [-h] [--version] [-v] [--debug] [-A] [--allow] [--allowxperm]
                [--auditallow] [--auditallowxperm] [--dontaudit]
                [--dontauditxperm] [-T] [--type_change] [--type_member]
                [--role_allow] [--role_transition] [--range_transition]
                [-s SOURCE] [-t TARGET] [-c TCLASS] [-p PERMS] [-x XPERMS]
                [-D DEFAULT] [-b BOOL] [-eb] [-ep] [-ex] [-Sp] [-ds] [-dt]
                [-rs] [-rt] [-rc] [-rd] [-rb]
                [policy]
`

// goldenHelp is the full help text, verified the same way.
const goldenHelp = `usage: sesearch [-h] [--version] [-v] [--debug] [-A] [--allow] [--allowxperm]
                [--auditallow] [--auditallowxperm] [--dontaudit]
                [--dontauditxperm] [-T] [--type_change] [--type_member]
                [--role_allow] [--role_transition] [--range_transition]
                [-s SOURCE] [-t TARGET] [-c TCLASS] [-p PERMS] [-x XPERMS]
                [-D DEFAULT] [-b BOOL] [-eb] [-ep] [-ex] [-Sp] [-ds] [-dt]
                [-rs] [-rt] [-rc] [-rd] [-rb]
                [policy]

SELinux policy rule search tool.

positional arguments:
  policy                Path to the SELinux policy to search.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Print extra informational messages
  --debug               Enable debugging.

TE Rule Types:
  -A                    Search allow and allowxperm rules.
  --allow               Search allow rules.
  --allowxperm          Search allowxperm rules.
  --auditallow          Search auditallow rules.
  --auditallowxperm     Search auditallowxperm rules.
  --dontaudit           Search dontaudit rules.
  --dontauditxperm      Search dontauditxperm rules.
  -T, --type_transition
                        Search type_transition rules.
  --type_change         Search type_change rules.
  --type_member         Search type_member rules.

RBAC Rule Types:
  --role_allow          Search role allow rules.
  --role_transition     Search role_transition rules.

MLS Rule Types:
  --range_transition    Search range_transition rules.

Expressions:
  -s SOURCE, --source SOURCE
                        Source type/role of the TE/RBAC rule.
  -t TARGET, --target TARGET
                        Target type/role of the TE/RBAC rule.
  -c TCLASS, --class TCLASS
                        Comma separated list of object classes
  -p PERMS, --perms PERMS
                        Comma separated list of permissions. (TE rule searches
                        only.)
  -x XPERMS, --xperms XPERMS
                        Comma separated list of extended permissions. (TE rule
                        searches only.)
  -D DEFAULT, --default DEFAULT
                        Default of the rule. (type/role/range transition
                        rules)
  -b BOOL, --bool BOOL  Comma separated list of Booleans in the conditional
                        expression. (TE rule searches only.)

Search options:
  -eb                   Match Boolean list exactly instead of matching any
                        listed Boolean.
  -ep                   Match permission set exactly instead of matching any
                        listed permission.
  -ex                   Match extended permission set exactly instead of
                        matching any listed permission.
  -Sp                   Match rules where the listed permissions are a subset
                        of the rule permissions.
  -ds                   Match source attributes directly instead of matching
                        member types/roles.
  -dt                   Match target attributes directly instead of matching
                        member types/roles.
  -rs                   Use regular expression matching for the source
                        type/role.
  -rt                   Use regular expression matching for the target
                        type/role.
  -rc                   Use regular expression matching for the object class.
  -rd                   Use regular expression matching for the default
                        type/role.
  -rb                   Use regular expression matching for Booleans.

TE/MLS rule searches cannot be mixed with RBAC rule searches.
`

// runSesearch runs the tool with a fixed program name and reports its exit
// status and output.
func runSesearch(argv ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	status := run(append([]string{"sesearch"}, argv...), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func TestUsage(t *testing.T) {
	p := newParser("sesearch")
	if got := p.usage(); got != goldenUsage {
		t.Errorf("usage = %q, want %q", got, goldenUsage)
	}
}

func TestHelp(t *testing.T) {
	status, stdout, stderr := runSesearch("--help")
	if status != 0 {
		t.Errorf("exit status = %d, want 0 (stderr: %s)", status, stderr)
	}
	if stdout != goldenHelp {
		t.Errorf("help output does not match the reference:\n%s", lineDiff(goldenHelp, stdout))
	}
}

// lineDiff points at the first line where the help text differs from the
// reference, which is easier to read than two 80 line strings.
func lineDiff(want, got string) string {
	wantLines := strings.Split(strings.TrimSuffix(want, "\n"), "\n")
	gotLines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	for i := 0; i < max(len(wantLines), len(gotLines)); i++ {
		var wantLine, gotLine string
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine != gotLine {
			return "line " + strconv.Itoa(i+1) + " differs:\n- " + wantLine + "\n+ " + gotLine
		}
	}
	return "the outputs are identical"
}

func TestVersion(t *testing.T) {
	status, stdout, stderr := runSesearch("--version")
	if status != 0 {
		t.Errorf("exit status = %d, want 0 (stderr: %s)", status, stderr)
	}
	if want := version + "\n"; stdout != want {
		t.Errorf("version output = %q, want %q", stdout, want)
	}
}

// TestUsageErrors checks the errors the parser reports on stderr with the
// usage line and exit status 2, exactly like the reference tool.
func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string // the error line, after the usage block
	}{
		{"no arguments", nil,
			"sesearch: error: At least one rule type must be specified."},
		{"policy only", []string{"policy.pol"},
			"sesearch: error: At least one rule type must be specified."},
		{"expressions without a rule type", []string{"-s", "app_t", "-c", "file"},
			"sesearch: error: At least one rule type must be specified."},
		{"perms with rbac rules", []string{"--role_allow", "-p", "read"},
			"sesearch: error: -p/--perms, -x/--xperms, and -b/--bool options are " +
				"only supported with TE rule searches."},
		{"xperms with mls rules", []string{"--range_transition", "-x", "0x1234"},
			"sesearch: error: -p/--perms, -x/--xperms, and -b/--bool options are " +
				"only supported with TE rule searches."},
		{"bool with rbac rules", []string{"--role_allow", "-b", "c_alpha"},
			"sesearch: error: -p/--perms, -x/--xperms, and -b/--bool options are " +
				"only supported with TE rule searches."},
		{"unambiguous abbreviation needs a value", []string{"--allow", "--s"},
			"sesearch: error: argument -s/--source: expected one argument"},
		{"ambiguous long option", []string{"--allow", "--a"},
			"sesearch: error: ambiguous option: --a could match --allow, --allowxperm, " +
				"--auditallow, --auditallowxperm"},
		{"ambiguous short option", []string{"--allow", "-e"},
			"sesearch: error: ambiguous option: -e could match -eb, -ep, -ex"},
		{"unknown option", []string{"--allow", "-q"},
			"sesearch: error: unrecognized arguments: -q"},
		{"unknown long option", []string{"--allow", "--bogus"},
			"sesearch: error: unrecognized arguments: --bogus"},
		{"second positional", []string{"--allow", "one.pol", "two.pol"},
			"sesearch: error: unrecognized arguments: two.pol"},
		{"missing value", []string{"--allow", "-s"},
			"sesearch: error: argument -s/--source: expected one argument"},
		{"value looks like an option", []string{"--allow", "-s", "--dontaudit"},
			"sesearch: error: argument -s/--source: expected one argument"},
		{"value for a flag", []string{"--allow", "-A=1"},
			"sesearch: error: argument -A: ignored explicit argument '1'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, stdout, stderr := runSesearch(tt.argv...)
			if status != 2 {
				t.Errorf("exit status = %d, want 2", status)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if want := goldenUsage + tt.want + "\n"; stderr != want {
				t.Errorf("stderr = %q, want %q", stderr, want)
			}
		})
	}
}

// TestOptionParsing covers the option forms argparse accepts.
func TestOptionParsing(t *testing.T) {
	tests := []struct {
		name  string
		argv  []string
		check func(t *testing.T, a *args)
	}{
		{"rule types", []string{"--allow", "--dontaudit"},
			func(t *testing.T, a *args) {
				if want := []sego.RuleType{sego.Allow, sego.DontAudit}; !equalRuleTypes(a.tertypes, want) {
					t.Errorf("tertypes = %v, want %v", a.tertypes, want)
				}
			}},
		{"-A is allow and allowxperm", []string{"-A"},
			func(t *testing.T, a *args) {
				if want := []sego.RuleType{sego.Allow, sego.AllowXPerm}; !equalRuleTypes(a.tertypes, want) {
					t.Errorf("tertypes = %v, want %v", a.tertypes, want)
				}
			}},
		{"rbac and mls rule types", []string{"--role_allow", "--role_transition", "--range_transition"},
			func(t *testing.T, a *args) {
				if len(a.rbacrtypes) != 2 || len(a.mlsrtypes) != 1 {
					t.Errorf("rbacrtypes = %v, mlsrtypes = %v", a.rbacrtypes, a.mlsrtypes)
				}
			}},
		{"separated value", []string{"--allow", "-s", "app_t"},
			func(t *testing.T, a *args) {
				if got := a.value("source"); got != "app_t" {
					t.Errorf("source = %q, want %q", got, "app_t")
				}
			}},
		{"attached short value", []string{"--allow", "-sapp_t"},
			func(t *testing.T, a *args) {
				if got := a.value("source"); got != "app_t" {
					t.Errorf("source = %q, want %q", got, "app_t")
				}
			}},
		{"equals value", []string{"--allow", "--source=app_t"},
			func(t *testing.T, a *args) {
				if got := a.value("source"); got != "app_t" {
					t.Errorf("source = %q, want %q", got, "app_t")
				}
			}},
		{"abbreviated option", []string{"--allow", "--sou", "app_t"},
			func(t *testing.T, a *args) {
				if got := a.value("source"); got != "app_t" {
					t.Errorf("source = %q, want %q", got, "app_t")
				}
			}},
		{"flags and regex", []string{"--allow", "-Sp", "-rc", "-ds", "-dt", "-eb", "-ep", "-ex", "-rb", "-rs", "-rt", "-rd"},
			func(t *testing.T, a *args) {
				for _, dest := range []string{"perms_subset", "tclass_regex", "source_direct", "target_direct",
					"boolean_equal", "perms_equal", "xperms_equal", "boolean_regex", "source_regex",
					"target_regex", "default_regex"} {
					if !a.flag(dest) {
						t.Errorf("%s was not set", dest)
					}
				}
			}},
		{"policy positional", []string{"--allow", "policy.pol", "--dontaudit"},
			func(t *testing.T, a *args) {
				if a.policy != "policy.pol" || !a.hasPolicy {
					t.Errorf("policy = %q, hasPolicy = %v", a.policy, a.hasPolicy)
				}
			}},
		{"no policy", []string{"--allow"},
			func(t *testing.T, a *args) {
				if a.hasPolicy {
					t.Errorf("hasPolicy = true for %q", a.policy)
				}
			}},
		{"verbose and debug", []string{"--allow", "-v", "--debug"},
			func(t *testing.T, a *args) {
				if !a.verbose || !a.debug {
					t.Errorf("verbose = %v, debug = %v", a.verbose, a.debug)
				}
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newParser("sesearch").parse(tt.argv)
			if err != nil {
				t.Fatalf("parse(%v): %v", tt.argv, err)
			}
			tt.check(t, a)
		})
	}
}

func equalRuleTypes(got, want []sego.RuleType) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestRuntimeErrorGoesToStdout checks that a query error prints the message on
// stdout and exits 1, while the usage errors above go to stderr with status 2.
func TestRuntimeErrorGoesToStdout(t *testing.T) {
	const policy = "../../policy/testdata/terulequery_v30.pol"
	if _, err := os.Stat(policy); err != nil {
		t.Skipf("the policy fixture is missing: %v", err)
	}

	status, stdout, stderr := runSesearch("--allow", "-s", "nosuch", policy)
	if status != 1 {
		t.Errorf("exit status = %d, want 1", status)
	}
	if want := "nosuch is not a valid type attribute\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
}

// TestBooleanNameSubstitution covers the Boolean name translation the tool
// applies when it locates the policy itself, using the environment override so
// that no installed policy is needed.
func TestBooleanNameSubstitution(t *testing.T) {
	tests := []struct {
		name string
		file string
		// want is the translation of "old_bool".
		want string
	}{
		{"plain", "old_bool new_bool\n", "new_bool"},
		{"whitespace and comments", "# a comment\n\n  old_bool \t new_bool  \n", "new_bool"},
		{"other names", "other_bool new_bool\n", "old_bool"},
		{"replacement is a path", "old_bool /some/file\n", "old_bool"},
		{"missing entry", "", "old_bool"},
		{"first field only", "old_bool\n", "old_bool"},
		{"inline comment", "old_bool new_bool # renamed\n", "new_bool"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "booleans.subs_dist")
			if err := os.WriteFile(path, []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(booleanSubsDistEnv, path)
			if got := lookupBooleanNameSub("old_bool"); got != tt.want {
				t.Errorf("lookupBooleanNameSub(old_bool) = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBooleanNameSubstitutionMissingFile checks that a missing file leaves
// names alone, which is also what happens without an SELinux policy installed.
func TestBooleanNameSubstitutionMissingFile(t *testing.T) {
	t.Setenv(booleanSubsDistEnv, filepath.Join(t.TempDir(), "does-not-exist"))
	if got := lookupBooleanNameSub("old_bool"); got != "old_bool" {
		t.Errorf("lookupBooleanNameSub(old_bool) = %q, want %q", got, "old_bool")
	}
}

// TestBooleanSubsDistPath checks the default location, which follows
// SELINUXTYPE like libselinux does.
func TestBooleanSubsDistPath(t *testing.T) {
	t.Setenv(booleanSubsDistEnv, "")
	t.Setenv("SELINUXTYPE", "")
	if got, want := booleanSubsDistPath(), "/etc/selinux/targeted/booleans.subs_dist"; got != want {
		t.Errorf("booleanSubsDistPath() = %q, want %q", got, want)
	}
	t.Setenv("SELINUXTYPE", "mls")
	if got, want := booleanSubsDistPath(), "/etc/selinux/mls/booleans.subs_dist"; got != want {
		t.Errorf("booleanSubsDistPath() = %q, want %q", got, want)
	}
}

// TestHelpWidth checks that the help text is wrapped to the terminal width,
// the way argparse does.
func TestHelpWidth(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	p := newParser("sesearch")
	help := p.help()
	for line := range strings.SplitSeq(strings.TrimSuffix(help, "\n"), "\n") {
		if len(line) > 58 {
			t.Errorf("line %q is longer than the requested width", line)
		}
	}
	if help == goldenHelp {
		t.Error("the help text did not change with the terminal width")
	}
}
