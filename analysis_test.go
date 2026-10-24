package sego

// Tests of the permission map and the flow analysis against the committed
// policy fixtures.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestPermissionMapLoad checks the permission map parser and the flow rules.
func TestPermissionMapLoad(t *testing.T) {
	const content = `# a small map
2
class file 3
read r 5
write w 10
append b 2
class process 1
fork n 4
`
	path := filepath.Join(t.TempDir(), "perm_map")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewPermissionMap(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := m.classes["file"]["read"]; got == nil || got.Direction != FlowRead || got.Weight != 5 {
		t.Errorf("file:read = %+v", got)
	}
	// The n direction contributes no flow.
	if got := m.classes["process"]["fork"]; got == nil || got.Direction != FlowNone {
		t.Errorf("process:fork = %+v", got)
	}

	// Invalid direction and weight are rejected with the file position.
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("1\nclass file 1\nread x 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPermissionMap(bad); err == nil {
		t.Error("invalid direction was accepted")
	}

	// The embedded default map loads and maps the common classes.
	def, err := NewPermissionMap("")
	if err != nil {
		t.Fatalf("default map: %v", err)
	}
	if def.classes["file"]["read"] == nil || def.classes["file"]["write"] == nil {
		t.Error("the default map does not map file reads and writes")
	}
}

// TestRuleWeight checks the per-direction weight of an allow rule.
func TestRuleWeight(t *testing.T) {
	pol := openFixture(t, "testdata/policies/sego_test-v32.pol")
	m, err := NewPermissionMap("")
	if err != nil {
		t.Fatal(err)
	}
	m.MapPolicy(pol)

	// allow app_t data_t:file { read write }: file read is a read flow and
	// file write a write flow, both at weight 10 in the default map.
	q := NewTERuleQuery(pol)
	q.SetRuletypes(Allow)
	if err := q.SetSource("app_t", true, false); err != nil {
		t.Fatal(err)
	}
	if err := q.SetTarget("data_t", true, false); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, rule := range q.Results() {
		av := rule.(*AVRule)
		if av.Source.Name != "app_t" || av.Target.Name != "data_t" || av.Class.Name != "file" {
			continue
		}
		found = true
		read, write := m.RuleWeight(av)
		if read == 0 || write == 0 {
			t.Errorf("weight of %s = read %d, write %d, want both non-zero", rule, read, write)
		}
	}
	if !found {
		t.Fatal("the app_t data_t:file allow rule was not found")
	}
}

// openFixture opens a policy fixture relative to the repository root.
func openFixture(t *testing.T, path string) *Policy {
	t.Helper()
	pol, err := Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	return pol
}

// TestDTA checks the domain transition graph and its traversal order on the
// dta fixture.
func TestDTA(t *testing.T) {
	pol := openFixture(t, "testdata/policies/sego_dta-v32.pol")
	g, err := NewDomainTransitionAnalysis(pol, nil)
	if err != nil {
		t.Fatal(err)
	}

	var out []string
	for _, step := range g.TransitionsOut("a_t") {
		out = append(out, step.Source+"->"+step.Target)
	}
	if want := []string{"a_t->plain_t", "a_t->b_t"}; !slices.Equal(out, want) {
		t.Errorf("transitions out = %v, want %v", out, want)
	}

	var in []string
	for _, step := range g.TransitionsIn("b_t") {
		in = append(in, step.Source+"->"+step.Target)
	}
	if want := []string{"a_t->b_t", "plain_t->b_t"}; !slices.Equal(in, want) {
		t.Errorf("transitions in = %v, want %v", in, want)
	}

	// The shortest a_t -> c_t path runs through b_t; a_t -> c_t itself is
	// not a valid transition (no shared entrypoint).
	paths := g.ShortestPaths("a_t", "c_t")
	if len(paths) != 1 || len(paths[0]) != 2 {
		t.Fatalf("shortest paths = %v, want one two-step path", paths)
	}
	if paths[0][0].Target != "b_t" || paths[0][1].Target != "c_t" {
		t.Errorf("shortest path = %v -> %v -> %v",
			paths[0][0].Source, paths[0][1].Source, paths[0][1].Target)
	}

	// The cutoff excludes the three-step path through plain_t.
	if all := g.AllPaths("a_t", "c_t", 2); len(all) != 1 {
		t.Errorf("all paths with max depth 2 = %d, want 1", len(all))
	}
	if all := g.AllPaths("a_t", "c_t", 3); len(all) != 2 {
		t.Errorf("all paths with max depth 3 = %d, want 2", len(all))
	}

	// Excluding an entrypoint removes the transitions that require it.
	gx, err := NewDomainTransitionAnalysis(pol, []string{"ep1_t"})
	if err != nil {
		t.Fatal(err)
	}
	if steps := gx.TransitionsOut("a_t"); len(steps) != 1 || steps[0].Target != "plain_t" {
		t.Errorf("transitions out with ep1_t excluded = %v", steps)
	}
}

// TestInfoFlow checks the flow graph, the weight floor and the Boolean
// evaluation on the main fixture.
func TestInfoFlow(t *testing.T) {
	pol := openFixture(t, "testdata/policies/sego_test-v32.pol")
	m, err := NewPermissionMap("")
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewInfoFlowAnalysis(pol, m, 3, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var flows []string
	for _, step := range g.FlowsOut("app_t") {
		flows = append(flows, step.Source+"->"+step.Target)
	}
	if want := []string{"app_t->data_t", "app_t->log_t"}; !slices.Equal(flows, want) {
		t.Errorf("flows out of app_t = %v, want %v", flows, want)
	}

	// A write rule on an attribute flows into each member of the attribute:
	// the plain_t special_attr write rule is a flow into config_t.
	var into []string
	for _, step := range g.FlowsIn("config_t") {
		into = append(into, step.Source+"->"+step.Target)
	}
	if want := []string{"plain_t->config_t"}; !slices.Equal(into, want) {
		t.Errorf("flows into config_t = %v, want %v", into, want)
	}

	// A flow step lists the rules that established it.
	step := g.FlowsOut("app_t")[0]
	if len(step.Rules) == 0 {
		t.Error("the flow step carries no rules")
	}

	// Setting c_alpha false disables the conditional rules it guards; the
	// conditional app_t log_t read rule is one of them.
	states := map[string]bool{"c_alpha": false}
	g2, err := NewInfoFlowAnalysis(pol, m, 1, nil, states, true)
	if err != nil {
		t.Fatal(err)
	}
	var conditional bool
	for _, step := range g2.FlowsOut("app_t") {
		for _, rule := range step.Rules {
			if av, ok := rule.(*AVRule); ok && av.Conditional != nil {
				if !g2.ruleEnabled(av) {
					t.Errorf("disabled rule %s reported as enabled", rule)
				}
				conditional = true
			}
		}
	}
	if !conditional {
		t.Error("no conditional flow rule was exercised")
	}
}

// TestDiff checks the policy difference engine on two fixtures.
func TestDiff(t *testing.T) {
	left := openFixture(t, "testdata/policies/sego_diff_a-v32.pol")
	right := openFixture(t, "testdata/policies/sego_diff_b-v32.pol")
	d := DiffPolicies(left, right)

	if len(left.Types()) != len(right.Types()) {
		t.Fatalf("the fixtures should not add or remove types")
	}
	if len(d.AddedTypes) != 0 || len(d.RemovedTypes) != 0 {
		t.Errorf("added %v, removed %v", d.AddedTypes, d.RemovedTypes)
	}

	var classModified bool
	for _, m := range d.ModifiedClasses {
		if m.Name == "file" {
			classModified = true
			if !slices.Contains(m.RemovedPerms, "append") {
				t.Errorf("class file removed perms = %v, want append", m.RemovedPerms)
			}
		}
	}
	if !classModified {
		t.Error("the modified file class was not reported")
	}

	// The permissive flag moved from log_t to plain_t.
	modified := make(map[string]ModifiedType)
	for _, m := range d.ModifiedTypes {
		modified[m.Name] = m
	}
	if m, ok := modified["plain_t"]; !ok || !m.PermissiveModified || m.Permissive {
		t.Errorf("plain_t = %+v, want added permissive", m)
	}
	if m, ok := modified["log_t"]; !ok || !m.PermissiveModified || !m.Permissive {
		t.Errorf("log_t = %+v, want removed permissive", m)
	}

	// The default_user and default_range statements changed.
	var sawRange, sawUser bool
	for _, m := range d.ModifiedDefaults {
		switch m.Kind {
		case "default_range":
			sawRange = true
			if m.AddedDefault != "source" || m.RemovedDefault != "target" ||
				m.AddedDefaultRange != "high" || m.RemovedDefaultRange != "low" {
				t.Errorf("default_range = %+v", m)
			}
		case "default_user":
			sawUser = true
			if m.AddedDefault != "target" || m.RemovedDefault != "source" {
				t.Errorf("default_user = %+v", m)
			}
		}
	}
	if !sawRange || !sawUser {
		t.Errorf("modified defaults = %+v, want default_user and default_range", d.ModifiedDefaults)
	}

	// The role transition default changed.
	if len(d.ModifiedRoleTransitions) != 1 {
		t.Errorf("modified role transitions = %+v, want one", d.ModifiedRoleTransitions)
	}

	// An identical pair has no differences at all.
	self := DiffPolicies(left, left)
	if len(self.AddedTypes) != 0 || len(self.RemovedTypes) != 0 ||
		len(self.ModifiedTypes) != 0 || len(self.AddedClasses) != 0 ||
		len(self.ModifiedClasses) != 0 || len(self.ModifiedDefaults) != 0 ||
		len(self.Allows.Added) != 0 || len(self.Allows.Modified) != 0 {
		t.Errorf("self diff is not empty: %+v", self)
	}
}

// TestConditionalEvaluate checks the Boolean expression evaluator.
func TestConditionalEvaluate(t *testing.T) {
	pol := openFixture(t, "testdata/policies/sego_test-v32.pol")
	// Find the conditional block over c_alpha and c_beta; the stored order
	// of the blocks is not the source order.
	var cond *Conditional
	for _, c := range pol.DB().Conditions {
		candidate := pol.conditional(c)
		if candidate.String() == "! c_beta && c_alpha" {
			cond = candidate
			break
		}
	}
	if cond == nil {
		t.Fatal("the ! c_beta && c_alpha conditional block was not found")
	}
	cases := []struct {
		states map[string]bool
		want   bool
	}{
		{nil, true}, // defaults: c_alpha true, c_beta false
		{map[string]bool{"c_alpha": false}, false},
		{map[string]bool{"c_beta": true}, false},
		{map[string]bool{"c_alpha": true, "c_beta": false}, true},
	}
	for _, tc := range cases {
		if got := cond.Evaluate(tc.states); got != tc.want {
			t.Errorf("Evaluate(%v) = %v, want %v", tc.states, got, tc.want)
		}
	}
}
