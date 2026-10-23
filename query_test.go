package sego

import (
	"reflect"
	"testing"
)

// The expectations in this file are taken from the setools test suite
// (tests/library/test_terulequery.py, test_rbacrulequery.py and
// test_mlsrulequery.py), which is the reference for query semantics. The
// policies were compiled from the matching setools test sources with
// checkpolicy.

func loadPolicy(t *testing.T, name string) *Policy {
	t.Helper()
	p, err := Open("policy/testdata/" + name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	return p
}

func checkStatements(t *testing.T, got []Rule, want []string) {
	t.Helper()
	sortRules(got)
	have := []string{}
	for _, r := range got {
		have = append(have, r.String())
	}
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("results mismatch:\n got %d rules:\n%s\n want %d rules:\n%s",
			len(have), joinLines(have), len(want), joinLines(want))
	}
}

func sortRules(rules []Rule) { SortRules(rules) }

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += "  " + l + "\n"
	}
	if out == "" {
		return "  <none>\n"
	}
	return out
}

func TestTERuleQueryUnset(t *testing.T) {
	p := loadPolicy(t, "terulequery_v30.pol")
	q := NewTERuleQuery(p)
	got := q.Results()
	if len(got) != len(p.TERules()) {
		t.Errorf("query with no criteria returned %d rules, policy has %d",
			len(got), len(p.TERules()))
	}
}

func TestTERuleQuery(t *testing.T) {
	p := loadPolicy(t, "terulequery_v30.pol")

	tests := []struct {
		name  string
		setup func(*TERuleQuery) error
		want  []string
	}{
		{
			name:  "source direct",
			setup: func(q *TERuleQuery) error { return q.SetSource("test1a", false, false) },
			want:  []string{"allow test1a test1t:infoflow hi_w;"},
		},
		{
			name:  "source indirect",
			setup: func(q *TERuleQuery) error { return q.SetSource("test2s", true, false) },
			want:  []string{"allow test2a test2t:infoflow hi_w;"},
		},
		{
			name:  "source direct regex",
			setup: func(q *TERuleQuery) error { return q.SetSource("test3a.*", false, true) },
			want:  []string{"allow test3aS test3t:infoflow low_r;"},
		},
		{
			name:  "source indirect regex",
			setup: func(q *TERuleQuery) error { return q.SetSource("test4(s|t)", true, true) },
			want: []string{
				"allow test4a1 test4a1:infoflow hi_w;",
				"allow test4a2 test4a2:infoflow low_r;",
			},
		},
		{
			name:  "target direct",
			setup: func(q *TERuleQuery) error { return q.SetTarget("test5a", false, false) },
			want:  []string{"allow test5s test5a:infoflow hi_w;"},
		},
		{
			name:  "target indirect",
			setup: func(q *TERuleQuery) error { return q.SetTarget("test6t", true, false) },
			want: []string{
				"allow test6s test6a:infoflow hi_w;",
				"allow test6s test6t:infoflow low_r;",
			},
		},
		{
			name:  "target direct regex",
			setup: func(q *TERuleQuery) error { return q.SetTarget("test7a.*", false, true) },
			want:  []string{"allow test7s test7aPASS:infoflow low_r;"},
		},
		{
			name:  "target indirect regex",
			setup: func(q *TERuleQuery) error { return q.SetTarget("test8(s|t)", true, true) },
			want: []string{
				"allow test8a1 test8a1:infoflow hi_w;",
				"allow test8a2 test8a2:infoflow low_r;",
			},
		},
		{
			name:  "class list",
			setup: func(q *TERuleQuery) error { return q.SetClasses([]string{"infoflow3", "infoflow4"}) },
			want: []string{
				"allow test10 test10:infoflow3 null;",
				"allow test10 test10:infoflow4 hi_w;",
			},
		},
		{
			name:  "class regex",
			setup: func(q *TERuleQuery) error { return q.SetClassPattern("infoflow(5|6)") },
			want: []string{
				"allow test11 test11:infoflow5 low_w;",
				"allow test11 test11:infoflow6 med_r;",
			},
		},
		{
			name:  "perms",
			setup: func(q *TERuleQuery) error { return q.SetPerms([]string{"super_r"}) },
			want: []string{
				"allow test12a test12a:infoflow7 super_r;",
				"allow test12b test12b:infoflow7 { super_none super_r };",
			},
		},
		{
			name: "perms equal",
			setup: func(q *TERuleQuery) error {
				if err := q.SetPerms([]string{"super_w", "super_none", "super_both"}); err != nil {
					return err
				}
				q.SetPermsEqual(true)
				return nil
			},
			want: []string{"allow test13c test13c:infoflow7 { super_both super_none super_w };"},
		},
		{
			name: "perms subset",
			setup: func(q *TERuleQuery) error {
				if err := q.SetPerms([]string{"super_none", "super_both"}); err != nil {
					return err
				}
				q.SetPermsSubset(true)
				return nil
			},
			want: []string{
				"allow test13c test13c:infoflow7 { super_both super_none super_w };",
				"allow test13d test13d:infoflow7 { super_both super_none super_unmapped super_w };",
			},
		},
		{
			name: "ruletypes",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AuditAllow, DontAudit)
				return nil
			},
			want: []string{
				"auditallow test14 test14:infoflow7 super_both;",
				"dontaudit test14 test14:infoflow7 super_unmapped;",
			},
		},
		{
			name:  "default direct",
			setup: func(q *TERuleQuery) error { return q.SetDefault("test100d", false) },
			want:  []string{"type_transition test100 test100:infoflow7 test100d;"},
		},
		{
			name:  "default regex",
			setup: func(q *TERuleQuery) error { return q.SetDefault("test101.", true) },
			want: []string{
				"type_transition test101 test101d:infoflow7 test101e;",
				"type_transition test101 test101e:infoflow7 test101d;",
			},
		},
		{
			name:  "boolean",
			setup: func(q *TERuleQuery) error { return q.SetBooleans([]string{"test200"}) },
			want: []string{
				"allow test200t1 test200t1:infoflow7 super_w; [ test200 ]:True",
				"allow test200t2 test200t2:infoflow7 super_w; [ test200a && test200 ]:True",
			},
		},
		{
			name: "boolean equal",
			setup: func(q *TERuleQuery) error {
				if err := q.SetBooleans([]string{"test201a", "test201b"}); err != nil {
					return err
				}
				q.SetBooleanEqual(true)
				return nil
			},
			want: []string{
				"allow test201t1 test201t1:infoflow7 super_unmapped; [ test201b && test201a ]:True",
			},
		},
		{
			name:  "boolean regex",
			setup: func(q *TERuleQuery) error { return q.SetBooleanPattern("test202(a|b)") },
			want: []string{
				"allow test202t1 test202t1:infoflow7 super_none; [ test202a ]:True",
				"allow test202t2 test202t2:infoflow7 super_unmapped; [ test202b || test202c ]:True",
			},
		},
		{
			name:  "attribute source indirect",
			setup: func(q *TERuleQuery) error { return q.SetSource("test300b", true, false) },
			want: []string{
				"allow test300a test300target:infoflow7 hi_w;",
				"allow test300b test300target:infoflow7 super_w;",
				"allow test300t1 test300t1:infoflow7 hi_r;",
				"allow test300t2 test300t2:infoflow7 med_w;",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewTERuleQuery(p)
			if err := tc.setup(q); err != nil {
				t.Fatalf("setup: %v", err)
			}
			checkStatements(t, q.Results(), tc.want)
		})
	}
}

// TestTERuleQueryXpermPermission checks how standard permission criteria
// interact with extended permission rules: a permission that names an extended
// permission kind matches every rule of that kind, while other permissions
// never match extended permission rules or type rules.
func TestTERuleQueryXpermPermission(t *testing.T) {
	p := loadPolicy(t, "terulequery2_v30.pol")

	q := NewTERuleQuery(p)
	q.SetRuletypes(AllowXPerm)
	if err := q.SetPerms([]string{"ioctl"}); err != nil {
		t.Fatalf("SetPerms: %v", err)
	}
	rules := q.Results()
	if len(rules) == 0 {
		t.Fatal("no rules matched the ioctl criteria")
	}
	for _, r := range rules {
		x, ok := r.(*AVRuleXperm)
		if !ok {
			t.Fatalf("non-extended rule matched: %s", r)
		}
		if x.XPermType != "ioctl" {
			t.Errorf("rule of kind %s matched the ioctl criteria: %s", x.XPermType, r)
		}
	}

	q = NewTERuleQuery(p)
	q.SetRuletypes(AllowXPerm)
	if err := q.SetPerms([]string{"hi_w"}); err != nil {
		t.Fatalf("SetPerms: %v", err)
	}
	if rules := q.Results(); len(rules) != 0 {
		t.Errorf("standard permission matched %d extended permission rules", len(rules))
	}

	q = NewTERuleQuery(p)
	q.SetRuletypes(TypeTransition)
	if err := q.SetPerms([]string{"hi_w"}); err != nil {
		t.Fatalf("SetPerms: %v", err)
	}
	if rules := q.Results(); len(rules) != 0 {
		t.Errorf("permission criteria matched %d type rules", len(rules))
	}
}

func TestRBACRuleQuery(t *testing.T) {
	p := loadPolicy(t, "rbacrulequery_v30.pol")

	tests := []struct {
		name  string
		setup func(*RBACRuleQuery) error
		want  []string
	}{
		{
			name:  "source direct",
			setup: func(q *RBACRuleQuery) error { return q.SetSource("test1s", false) },
			want: []string{
				"allow test1s test1t;",
				"role_transition test1s system:infoflow test1t;",
			},
		},
		{
			name:  "source regex",
			setup: func(q *RBACRuleQuery) error { return q.SetSource("test2s(1|2)", true) },
			want:  []string{"allow test2s1 test2t;"},
		},
		{
			name:  "target role",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("test10t", false) },
			want:  []string{"allow test10s test10t;"},
		},
		{
			name:  "target regex",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("test11t(1|3)", true) },
			want:  []string{"allow test11s test11t1;"},
		},
		{
			name:  "target type",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("test12t", false) },
			want:  []string{"role_transition test12s test12t:infoflow test12d;"},
		},
		{
			name:  "class list",
			setup: func(q *RBACRuleQuery) error { return q.SetClasses([]string{"infoflow3", "infoflow4"}) },
			want: []string{
				"role_transition test21 system:infoflow3 test21d3;",
				"role_transition test21 system:infoflow4 test21d2;",
			},
		},
		{
			name:  "class regex",
			setup: func(q *RBACRuleQuery) error { return q.SetClassPattern("infoflow(5|6)") },
			want: []string{
				"role_transition test22 system:infoflow5 test22d2;",
				"role_transition test22 system:infoflow6 test22d3;",
			},
		},
		{
			name:  "default direct",
			setup: func(q *RBACRuleQuery) error { return q.SetDefault("test30d", false) },
			want:  []string{"role_transition test30s system:infoflow test30d;"},
		},
		{
			name:  "default regex",
			setup: func(q *RBACRuleQuery) error { return q.SetDefault("test31d(2|3)", true) },
			want: []string{
				"role_transition test31s system:infoflow7 test31d3;",
				"role_transition test31s system:process test31d2;",
			},
		},
		{
			name: "ruletype",
			setup: func(q *RBACRuleQuery) error {
				q.SetRuletypes(RuleRoleAllow)
				return nil
			},
			want: []string{
				"allow test10s test10t;",
				"allow test11s test11t1;",
				"allow test12s test12d;",
				"allow test1s test1t;",
				"allow test2s1 test2t;",
				"allow test30s test30d;",
				"allow test31s test31d1;",
				"allow test31s test31d2;",
				"allow test31s test31d3;",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewRBACRuleQuery(p)
			if err := tc.setup(q); err != nil {
				t.Fatalf("setup: %v", err)
			}
			checkStatements(t, q.Results(), tc.want)
		})
	}
}

func TestMLSRuleQuery(t *testing.T) {
	p := loadPolicy(t, "mlsrulequery_v30.pol")

	tests := []struct {
		name  string
		setup func(*MLSRuleQuery) error
		want  []string
	}{
		{
			name:  "source",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("test1s", false, false) },
			want:  []string{"range_transition test1s test1t:infoflow s0;"},
		},
		{
			name:  "source regex",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("test3(s|aS)", true, true) },
			want: []string{
				"range_transition test3s test3t:infoflow s1;",
				"range_transition test3s test3t:infoflow2 s2;",
			},
		},
		{
			name:  "source attribute",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("test5b", true, false) },
			want: []string{
				"range_transition test5t1 test5target:infoflow s1;",
				"range_transition test5t2 test5target:infoflow7 s2;",
			},
		},
		{
			name:  "target",
			setup: func(q *MLSRuleQuery) error { return q.SetTarget("test10t", false, false) },
			want: []string{
				"range_transition test10s test10t:infoflow s0;",
				"range_transition test10s test10t:infoflow2 s1;",
			},
		},
		{
			name:  "class list",
			setup: func(q *MLSRuleQuery) error { return q.SetClasses([]string{"infoflow3", "infoflow4"}) },
			want: []string{
				"range_transition test21 test21:infoflow3 s2;",
				"range_transition test21 test21:infoflow4 s1;",
			},
		},
		{
			name:  "range exact",
			setup: func(q *MLSRuleQuery) error { return q.SetRange("s40:c1 - s40:c0.c4") },
			want:  []string{"range_transition test40 test40:infoflow s40:c1 - s40:c0.c4;"},
		},
		{
			name:  "range exact rejects other categories",
			setup: func(q *MLSRuleQuery) error { return q.SetRange("s41:c1 - s41:c0.c4") },
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewMLSRuleQuery(p)
			if err := tc.setup(q); err != nil {
				t.Fatalf("setup: %v", err)
			}
			checkStatements(t, q.Results(), tc.want)
		})
	}
}

// TestTERuleQueryXperm exercises extended permission queries. The expectations
// come from the setools test suite's TestTERuleQueryXperm.
func TestTERuleQueryXperm(t *testing.T) {
	p := loadPolicy(t, "terulequery2_v30.pol")

	tests := []struct {
		name  string
		setup func(*TERuleQuery) error
		want  []string
	}{
		{
			name: "source direct",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("test1a", false, false)
			},
			want: []string{"allowxperm test1a test1t:infoflow ioctl 0xebe0-0xebff;"},
		},
		{
			name: "source indirect",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("test2s", true, false)
			},
			want: []string{"allowxperm test2a test2t:infoflow ioctl { 0x5411 0x5451 };"},
		},
		{
			name: "source indirect regex",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("test4(s|t)", true, true)
			},
			want: []string{
				"allowxperm test4a1 test4a1:infoflow ioctl 0x9999;",
				"allowxperm test4a2 test4a2:infoflow ioctl 0x1111;",
			},
		},
		{
			name: "target indirect",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetTarget("test6t", true, false)
			},
			want: []string{
				"allowxperm test6s test6a:infoflow ioctl 0x9999;",
				"allowxperm test6s test6t:infoflow ioctl 0x1111;",
			},
		},
		{
			name: "class list",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetClasses([]string{"infoflow3", "infoflow4"})
			},
			want: []string{
				"allowxperm test10 test10:infoflow3 ioctl 0x0000;",
				"allowxperm test10 test10:infoflow4 ioctl 0x9999;",
			},
		},
		{
			name: "nlmsg rule",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("test102a", false, false)
			},
			want: []string{"allowxperm test102a test102t:infoflow8 nlmsg 0x0001-0x00f1;"},
		},
		{
			name: "xperm overlap",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				x, err := ParseXPermSet("0x9011-0x9013")
				if err != nil {
					return err
				}
				q.SetXPerms(x, false)
				return nil
			},
			want: []string{
				"allowxperm test101a test101a:infoflow7 ioctl 0x9011;",
				"allowxperm test101b test101b:infoflow7 ioctl 0x9011-0x9012;",
				"allowxperm test101c test101c:infoflow7 ioctl 0x9011-0x9013;",
				"allowxperm test101d test101d:infoflow7 ioctl 0x9011-0x9014;",
			},
		},
		{
			name: "xperm exact",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				x, err := ParseXPermSet("0x9011-0x9013")
				if err != nil {
					return err
				}
				q.SetXPerms(x, true)
				return nil
			},
			want: []string{"allowxperm test101c test101c:infoflow7 ioctl 0x9011-0x9013;"},
		},
		{
			name: "ruletypes",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AuditAllowXPerm, DontAuditXPerm)
				return nil
			},
			want: []string{
				"auditallowxperm test14 test14:infoflow7 ioctl 0x1234;",
				"dontauditxperm test14 test14:infoflow7 ioctl 0x4321;",
			},
		},
		{
			name: "neverallow rules are absent from the binary policy",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(NeverAllow, NeverAllowXPerm)
				return q.SetPerms([]string{"ioctl"})
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewTERuleQuery(p)
			if err := tc.setup(q); err != nil {
				t.Fatalf("setup: %v", err)
			}
			checkStatements(t, q.Results(), tc.want)
		})
	}
}

// TestMLSRuleQueryRangeFlags covers the range comparison modes. The
// expectations come from the setools test suite's range overlap, subset,
// superset and proper cases.
func TestMLSRuleQueryRangeFlags(t *testing.T) {
	p := loadPolicy(t, "mlsrulequery_v30.pol")

	tests := []struct {
		name   string
		text   string
		mode   RangeMatchMode
		proper bool
		want   []string
	}{
		{
			name: "overlap equal",
			text: "s41:c1 - s41:c0.c4", mode: RangeOverlap,
			want: []string{"range_transition test41 test41:infoflow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap criteria inside",
			text: "s41:c1,c2 - s41:c0.c3", mode: RangeOverlap,
			want: []string{"range_transition test41 test41:infoflow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap criteria covers",
			text: "s41 - s41:c0.c4", mode: RangeOverlap,
			want: []string{"range_transition test41 test41:infoflow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap low end",
			text: "s41 - s41:c1,c2", mode: RangeOverlap,
			want: []string{"range_transition test41 test41:infoflow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap high end",
			text: "s41:c1,c2 - s41:c0.c4", mode: RangeOverlap,
			want: []string{"range_transition test41 test41:infoflow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "superset",
			text: "s43 - s43:c0.c4", mode: RangeSuperset,
			want: []string{"range_transition test43 test43:infoflow s43:c1 - s43:c1.c3;"},
		},
		{
			name: "superset equal",
			text: "s43:c1 - s43:c1.c3", mode: RangeSuperset,
			want: []string{"range_transition test43 test43:infoflow s43:c1 - s43:c1.c3;"},
		},
		{
			name: "proper subset",
			text: "s44:c1,c2", mode: RangeSubset, proper: true,
			want: []string{"range_transition test44 test44:infoflow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper subset equal",
			text: "s44:c1 - s44:c1.c3", mode: RangeSubset, proper: true,
			want: nil,
		},
		{
			name: "proper subset equal low",
			text: "s44:c1 - s44:c1.c2", mode: RangeSubset, proper: true,
			want: []string{"range_transition test44 test44:infoflow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper subset equal high",
			text: "s44:c1,c2 - s44:c1.c3", mode: RangeSubset, proper: true,
			want: []string{"range_transition test44 test44:infoflow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper superset",
			text: "s45 - s45:c0.c4", mode: RangeSuperset, proper: true,
			want: []string{"range_transition test45 test45:infoflow s45:c1 - s45:c1.c3;"},
		},
		{
			name: "proper superset equal",
			text: "s45:c1 - s45:c1.c3", mode: RangeSuperset, proper: true,
			want: nil,
		},
		{
			name: "proper superset equal low",
			text: "s45:c1 - s45:c1.c4", mode: RangeSuperset, proper: true,
			want: []string{"range_transition test45 test45:infoflow s45:c1 - s45:c1.c3;"},
		},
		{
			name: "proper superset equal high",
			text: "s45 - s45:c1.c3", mode: RangeSuperset, proper: true,
			want: []string{"range_transition test45 test45:infoflow s45:c1 - s45:c1.c3;"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := NewMLSRuleQuery(p)
			if err := q.SetRange(tc.text); err != nil {
				t.Fatalf("SetRange: %v", err)
			}
			q.SetRangeMatchMode(tc.mode, tc.proper)
			checkStatements(t, q.Results(), tc.want)
		})
	}
}

// TestNonMLSPolicy checks that a policy compiled without MLS still parses and
// answers type enforcement queries. The kernel policy stores the range of every
// context even without MLS, so this exercises the empty level encoding.
func TestNonMLSPolicy(t *testing.T) {
	p := loadPolicy(t, "non_mls_v32.pol")
	if p.MLS() {
		t.Error("MLS reported enabled")
	}
	q := NewTERuleQuery(p)
	if err := q.SetSource("system", false, false); err != nil {
		t.Fatal(err)
	}
	checkStatements(t, q.Results(), []string{"allow system system:infoflow hi_w;"})
	if rules := p.MLSRules(); len(rules) != 0 {
		t.Errorf("non-MLS policy has %d range transition rules", len(rules))
	}
}
