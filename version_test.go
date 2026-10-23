package sego_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/elnx/sego"
)

// TestPolicyVersionEquivalence checks that the same policy source compiled at
// different policy versions decodes to the same rules. The compressed
// filename-transition encoding (version 33) and the neveraudit map (version 35)
// change the file layout but not the rules the tools report.
func TestPolicyVersionEquivalence(t *testing.T) {
	groups := fixtureGroups(t)
	if len(groups) == 0 {
		t.Skip("no multi-version policies in testdata/policies")
	}
	for name, paths := range groups {
		if len(paths) < 2 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			want := ruleStatements(t, paths[0])
			for _, path := range paths[1:] {
				got := ruleStatements(t, path)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s reports %d rules, %s reports %d; first difference: %s",
						filepath.Base(path), len(got), filepath.Base(paths[0]), len(want),
						firstDifference(want, got))
				}
			}
		})
	}
}

// ruleStatements returns every rendered rule of the policy, sorted.
func ruleStatements(t *testing.T, path string) []string {
	t.Helper()
	p, err := sego.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	var rules []sego.Rule
	rules = append(rules, p.TERules()...)
	rules = append(rules, p.RBACRules()...)
	rules = append(rules, p.MLSRules()...)
	sego.SortRules(rules)
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.String())
	}
	return out
}

// fixtureGroups maps a fixture name to its compiled policy files, ordered by
// policy version.
func fixtureGroups(t *testing.T) map[string][]string {
	t.Helper()
	paths, err := filepath.Glob("testdata/policies/*.pol")
	if err != nil {
		t.Fatal(err)
	}
	groups := make(map[string][]string)
	for _, path := range paths {
		base := strings.TrimSuffix(filepath.Base(path), ".pol")
		name, _, found := strings.Cut(base, "-v")
		if !found {
			continue
		}
		groups[name] = append(groups[name], path)
	}
	for _, group := range groups {
		slices.Sort(group)
	}
	return groups
}

func firstDifference(want, got []string) string {
	for i := range want {
		if i >= len(got) {
			return "missing in " + filepath.Base(got[len(got)-1]) + ": " + want[i]
		}
		if want[i] != got[i] {
			return want[i] + " != " + got[i]
		}
	}
	if len(got) > len(want) {
		return "extra rule: " + got[len(want)]
	}
	return "none"
}
