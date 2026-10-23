package sego

import (
	"reflect"
	"strings"
	"testing"
)

// The policies loaded here are compiled from the hand written sources in
// policy/testdata/src/ by policy/testdata/gen.sh. The scenarios and their
// expected outcomes mirror the setools test suite's type enforcement, RBAC and
// MLS rule query tests, which are the reference for query semantics, but every
// symbol and fixture is our own.

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
	p := loadPolicy(t, "te_semantics-v30.pol")
	q := NewTERuleQuery(p)
	got := q.Results()
	if len(got) != len(p.TERules()) {
		t.Errorf("query with no criteria returned %d rules, policy has %d",
			len(got), len(p.TERules()))
	}
}

func TestTERuleQuery(t *testing.T) {
	p := loadPolicy(t, "te_semantics-v30.pol")

	tests := []struct {
		name  string
		setup func(*TERuleQuery) error
		want  []string
	}{
		{
			name:  "source direct",
			setup: func(q *TERuleQuery) error { return q.SetSource("src_direct", false, false) },
			want:  []string{"allow src_direct tgt_direct:flow read_high;"},
		},
		{
			name:  "source indirect",
			setup: func(q *TERuleQuery) error { return q.SetSource("src_indirect_member", true, false) },
			want:  []string{"allow src_indirect tgt_indirect:flow read_high;"},
		},
		{
			name:  "source direct regex",
			setup: func(q *TERuleQuery) error { return q.SetSource("src_re_a_.*", false, true) },
			want:  []string{"allow src_re_a_ok tgt_re:flow write_low;"},
		},
		{
			name:  "source indirect regex",
			setup: func(q *TERuleQuery) error { return q.SetSource("pair_(s|t)_member", true, true) },
			want: []string{
				"allow attr_pair_s attr_pair_s:flow read_high;",
				"allow attr_pair_t attr_pair_t:flow write_low;",
			},
		},
		{
			name:  "target direct",
			setup: func(q *TERuleQuery) error { return q.SetTarget("tgt_direct_attr", false, false) },
			want:  []string{"allow src_for_tgt_direct tgt_direct_attr:flow read_high;"},
		},
		{
			name:  "target indirect",
			setup: func(q *TERuleQuery) error { return q.SetTarget("tgt_indirect_member", true, false) },
			want: []string{
				"allow src_for_tgt_indirect tgt_indirect_attr:flow read_high;",
				"allow src_for_tgt_indirect tgt_indirect_member:flow write_low;",
			},
		},
		{
			name:  "target direct regex",
			setup: func(q *TERuleQuery) error { return q.SetTarget("tgt_re_a_.*", false, true) },
			want:  []string{"allow src_for_tgt_re tgt_re_a_ok:flow write_low;"},
		},
		{
			name:  "target indirect regex",
			setup: func(q *TERuleQuery) error { return q.SetTarget("tgtpair_(s|t)_member", true, true) },
			want: []string{
				"allow src_for_tgt_pair tgt_pair_s:flow read_high;",
				"allow src_for_tgt_pair tgt_pair_t:flow write_low;",
			},
		},
		{
			name:  "class list",
			setup: func(q *TERuleQuery) error { return q.SetClasses([]string{"c_alpha", "c_beta"}) },
			want: []string{
				"allow class_list_t class_list_t:c_alpha noop;",
				"allow class_list_t class_list_t:c_beta read_high;",
			},
		},
		{
			name:  "class regex",
			setup: func(q *TERuleQuery) error { return q.SetClassPattern("c_gamma(1|2)") },
			want: []string{
				"allow class_re_t class_re_t:c_gamma1 write_low;",
				"allow class_re_t class_re_t:c_gamma2 read_med;",
			},
		},
		{
			name:  "perms",
			setup: func(q *TERuleQuery) error { return q.SetPerms([]string{"grant_read"}) },
			want: []string{
				"allow perm_any_pair perm_any_pair:flow_extra { grant_none grant_read };",
				"allow perm_any_single perm_any_single:flow_extra grant_read;",
			},
		},
		{
			name: "perms equal",
			setup: func(q *TERuleQuery) error {
				if err := q.SetPerms([]string{"grant_all", "grant_none", "grant_both"}); err != nil {
					return err
				}
				q.SetPermsEqual(true)
				return nil
			},
			want: []string{"allow perm_eq_three perm_eq_three:flow_extra { grant_all grant_both grant_none };"},
		},
		{
			name: "perms subset",
			setup: func(q *TERuleQuery) error {
				if err := q.SetPerms([]string{"grant_none", "grant_both"}); err != nil {
					return err
				}
				q.SetPermsSubset(true)
				return nil
			},
			want: []string{
				"allow perm_eq_four perm_eq_four:flow_extra { grant_all grant_both grant_extra grant_none };",
				"allow perm_eq_three perm_eq_three:flow_extra { grant_all grant_both grant_none };",
			},
		},
		{
			name: "ruletypes",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AuditAllow, DontAudit)
				return nil
			},
			want: []string{
				"auditallow ruletype_t ruletype_t:flow_extra grant_both;",
				"dontaudit bool_d_t1 bool_d_t1:flow_extra grant_extra; [ c_eight ]:True",
				"dontaudit ruletype_t ruletype_t:flow_extra grant_extra;",
			},
		},
		{
			name:  "default direct",
			setup: func(q *TERuleQuery) error { return q.SetDefault("trans_default", false) },
			want:  []string{"type_transition trans_src trans_src:flow_extra trans_default;"},
		},
		{
			name:  "default regex",
			setup: func(q *TERuleQuery) error { return q.SetDefault("trans_pair_[de]", true) },
			want: []string{
				"type_transition trans_pair_src trans_pair_d:flow_extra trans_pair_e;",
				"type_transition trans_pair_src trans_pair_e:flow_extra trans_pair_d;",
			},
		},
		{
			name:  "boolean",
			setup: func(q *TERuleQuery) error { return q.SetBooleans([]string{"c_one"}) },
			want: []string{
				"allow bool_a_t1 bool_a_t1:flow_extra grant_all; [ c_one ]:True",
				"allow bool_a_t2 bool_a_t2:flow_extra grant_all; [ c_two && c_one ]:True",
			},
		},
		{
			name: "boolean equal",
			setup: func(q *TERuleQuery) error {
				if err := q.SetBooleans([]string{"c_three", "c_four"}); err != nil {
					return err
				}
				q.SetBooleanEqual(true)
				return nil
			},
			want: []string{
				"allow bool_b_t1 bool_b_t1:flow_extra grant_extra; [ c_four && c_three ]:True",
			},
		},
		{
			name:  "boolean regex",
			setup: func(q *TERuleQuery) error { return q.SetBooleanPattern("c_(five|six)") },
			want: []string{
				"allow bool_c_t1 bool_c_t1:flow_extra grant_none; [ c_five ]:True",
				"allow bool_c_t2 bool_c_t2:flow_extra grant_extra; [ c_six || c_seven ]:True",
			},
		},
		{
			name:  "attribute source indirect",
			setup: func(q *TERuleQuery) error { return q.SetSource("attr_overlap_b", true, false) },
			want: []string{
				"allow attr_overlap_a overlap_target:flow_extra read_high;",
				"allow attr_overlap_b overlap_target:flow_extra grant_all;",
				"allow in_both in_both:flow_extra write_high;",
				"allow only_b only_b:flow_extra read_med;",
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
	p := loadPolicy(t, "xperm-v30.pol")

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
	if err := q.SetPerms([]string{"read_high"}); err != nil {
		t.Fatalf("SetPerms: %v", err)
	}
	if rules := q.Results(); len(rules) != 0 {
		t.Errorf("standard permission matched %d extended permission rules", len(rules))
	}

	q = NewTERuleQuery(p)
	q.SetRuletypes(TypeTransition)
	if err := q.SetPerms([]string{"read_high"}); err != nil {
		t.Fatalf("SetPerms: %v", err)
	}
	if rules := q.Results(); len(rules) != 0 {
		t.Errorf("permission criteria matched %d type rules", len(rules))
	}
}

func TestRBACRuleQuery(t *testing.T) {
	p := loadPolicy(t, "rbac-v30.pol")

	tests := []struct {
		name  string
		setup func(*RBACRuleQuery) error
		want  []string
	}{
		{
			name:  "source direct",
			setup: func(q *RBACRuleQuery) error { return q.SetSource("role_out_d", false) },
			want: []string{
				"allow role_out_d role_in_d;",
				"role_transition role_out_d system:flow role_in_d;",
			},
		},
		{
			name:  "source regex",
			setup: func(q *RBACRuleQuery) error { return q.SetSource("role_re_[ab]", true) },
			want:  []string{"allow role_re_a role_re_t;"},
		},
		{
			name:  "target role",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("role_in_t", false) },
			want:  []string{"allow role_out_t role_in_t;"},
		},
		{
			name:  "target regex",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("role_tre_[ab]", true) },
			want:  []string{"allow role_tre_s role_tre_a;"},
		},
		{
			name:  "target type",
			setup: func(q *RBACRuleQuery) error { return q.SetTarget("type_typt", false) },
			want:  []string{"role_transition role_typt_s type_typt:flow role_typt_d;"},
		},
		{
			name:  "class list",
			setup: func(q *RBACRuleQuery) error { return q.SetClasses([]string{"c_alpha", "c_beta"}) },
			want: []string{
				"role_transition role_cls system:c_alpha role_cls_d3;",
				"role_transition role_cls system:c_beta role_cls_d2;",
			},
		},
		{
			name:  "class regex",
			setup: func(q *RBACRuleQuery) error { return q.SetClassPattern("c_gamma(1|2)") },
			want: []string{
				"role_transition role_crx system:c_gamma1 role_crx_d2;",
				"role_transition role_crx system:c_gamma2 role_crx_d3;",
			},
		},
		{
			name:  "default direct",
			setup: func(q *RBACRuleQuery) error { return q.SetDefault("role_def_d", false) },
			want:  []string{"role_transition role_def_s system:flow role_def_d;"},
		},
		{
			name:  "default regex",
			setup: func(q *RBACRuleQuery) error { return q.SetDefault("role_defr_[23]", true) },
			want: []string{
				"role_transition role_defr_s system:flow_extra role_defr_3;",
				"role_transition role_defr_s system:process role_defr_2;",
			},
		},
		{
			name: "ruletype",
			setup: func(q *RBACRuleQuery) error {
				q.SetRuletypes(RuleRoleAllow)
				return nil
			},
			want: []string{
				"allow role_def_s role_def_d;",
				"allow role_defr_s role_defr_1;",
				"allow role_defr_s role_defr_2;",
				"allow role_defr_s role_defr_3;",
				"allow role_out_d role_in_d;",
				"allow role_out_t role_in_t;",
				"allow role_re_a role_re_t;",
				"allow role_tre_s role_tre_a;",
				"allow role_typt_s role_typt_d;",
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
	p := loadPolicy(t, "mls_ranges-v30.pol")

	tests := []struct {
		name  string
		setup func(*MLSRuleQuery) error
		want  []string
	}{
		{
			name:  "source",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("mls_src", false, false) },
			want:  []string{"range_transition mls_src mls_tgt:flow s0;"},
		},
		{
			name:  "source regex",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("src_re_(plain|a)", true, true) },
			want: []string{
				"range_transition src_re_plain src_re_tgt:flow s1;",
				"range_transition src_re_plain src_re_tgt:flow_extra s2;",
			},
		},
		{
			name:  "source attribute",
			setup: func(q *MLSRuleQuery) error { return q.SetSource("src_attr_b", true, false) },
			want: []string{
				"range_transition mls_in_both mls_attr_tgt:flow s1;",
				"range_transition mls_only_b mls_attr_tgt:flow_extra s2;",
			},
		},
		{
			name:  "target",
			setup: func(q *MLSRuleQuery) error { return q.SetTarget("mls_tgt2", false, false) },
			want: []string{
				"range_transition src_for_tgt mls_tgt2:flow s0;",
				"range_transition src_for_tgt mls_tgt2:flow_extra s1;",
			},
		},
		{
			name:  "class list",
			setup: func(q *MLSRuleQuery) error { return q.SetClasses([]string{"c_alpha", "c_beta"}) },
			want: []string{
				"range_transition mls_cls mls_cls:c_alpha s2;",
				"range_transition mls_cls mls_cls:c_beta s1;",
			},
		},
		{
			name:  "range exact",
			setup: func(q *MLSRuleQuery) error { return q.SetRange("s40:c1 - s40:c0.c4") },
			want:  []string{"range_transition range_exact range_exact:flow s40:c1 - s40:c0.c4;"},
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

// TestTERuleQueryXperm exercises extended permission queries.
func TestTERuleQueryXperm(t *testing.T) {
	p := loadPolicy(t, "xperm-v30.pol")

	tests := []struct {
		name  string
		setup func(*TERuleQuery) error
		want  []string
	}{
		{
			name: "source direct",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("src_xperm", false, false)
			},
			want: []string{"allowxperm src_xperm tgt_xperm_direct:flow ioctl 0xebe0-0xebff;"},
		},
		{
			name: "source indirect",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("src_xperm_ind", true, false)
			},
			want: []string{"allowxperm attr_xperm_ind tgt_xperm_ind:flow ioctl { 0x5411 0x5451 };"},
		},
		{
			name: "source indirect regex",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("px_(s|t)_member", true, true)
			},
			want: []string{
				"allowxperm attr_px_s attr_px_s:flow ioctl 0x9999;",
				"allowxperm attr_px_t attr_px_t:flow ioctl 0x1111;",
			},
		},
		{
			name: "target indirect",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetTarget("tgt_xperm_member", true, false)
			},
			want: []string{
				"allowxperm src_xperm_tgt attr_xperm_tgt:flow ioctl 0x9999;",
				"allowxperm src_xperm_tgt tgt_xperm_member:flow ioctl 0x1111;",
			},
		},
		{
			name: "class list",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetClasses([]string{"c_alpha", "c_beta"})
			},
			want: []string{
				"allowxperm class_list_t class_list_t:c_alpha ioctl 0x0000;",
				"allowxperm class_list_t class_list_t:c_beta ioctl 0x9999;",
			},
		},
		{
			name: "nlmsg rule",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AllowXPerm)
				return q.SetSource("src_nlmsg", false, false)
			},
			want: []string{"allowxperm src_nlmsg tgt_nlmsg:nl_iface nlmsg 0x0001-0x00f1;"},
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
				"allowxperm xperm_range_a xperm_range_a:flow_extra ioctl 0x9011;",
				"allowxperm xperm_range_b xperm_range_b:flow_extra ioctl 0x9011-0x9012;",
				"allowxperm xperm_range_c xperm_range_c:flow_extra ioctl 0x9011-0x9013;",
				"allowxperm xperm_range_d xperm_range_d:flow_extra ioctl 0x9011-0x9014;",
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
			want: []string{"allowxperm xperm_range_c xperm_range_c:flow_extra ioctl 0x9011-0x9013;"},
		},
		{
			name: "ruletypes",
			setup: func(q *TERuleQuery) error {
				q.SetRuletypes(AuditAllowXPerm, DontAuditXPerm)
				return nil
			},
			want: []string{
				"auditallowxperm ruletype_x_t ruletype_x_t:flow_extra ioctl 0x1234;",
				"dontauditxperm ruletype_x_t ruletype_x_t:flow_extra ioctl 0x4321;",
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

// TestMLSRuleQueryRangeFlags covers the range comparison modes: overlap,
// subset, superset and the proper variants.
func TestMLSRuleQueryRangeFlags(t *testing.T) {
	p := loadPolicy(t, "mls_ranges-v30.pol")

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
			want: []string{"range_transition range_overlap range_overlap:flow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap criteria inside",
			text: "s41:c1,c2 - s41:c0.c3", mode: RangeOverlap,
			want: []string{"range_transition range_overlap range_overlap:flow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap criteria covers",
			text: "s41 - s41:c0.c4", mode: RangeOverlap,
			want: []string{"range_transition range_overlap range_overlap:flow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap low end",
			text: "s41 - s41:c1,c2", mode: RangeOverlap,
			want: []string{"range_transition range_overlap range_overlap:flow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "overlap high end",
			text: "s41:c1,c2 - s41:c0.c4", mode: RangeOverlap,
			want: []string{"range_transition range_overlap range_overlap:flow s41:c1 - s41:c1.c3;"},
		},
		{
			name: "superset",
			text: "s43 - s43:c0.c4", mode: RangeSuperset,
			want: []string{"range_transition range_superset range_superset:flow s43:c1 - s43:c1.c3;"},
		},
		{
			name: "superset equal",
			text: "s43:c1 - s43:c1.c3", mode: RangeSuperset,
			want: []string{"range_transition range_superset range_superset:flow s43:c1 - s43:c1.c3;"},
		},
		{
			name: "proper subset",
			text: "s44:c1,c2", mode: RangeSubset, proper: true,
			want: []string{"range_transition range_proper_subset range_proper_subset:flow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper subset equal",
			text: "s44:c1 - s44:c1.c3", mode: RangeSubset, proper: true,
			want: nil,
		},
		{
			name: "proper subset equal low",
			text: "s44:c1 - s44:c1.c2", mode: RangeSubset, proper: true,
			want: []string{"range_transition range_proper_subset range_proper_subset:flow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper subset equal high",
			text: "s44:c1,c2 - s44:c1.c3", mode: RangeSubset, proper: true,
			want: []string{"range_transition range_proper_subset range_proper_subset:flow s44:c1 - s44:c1.c3;"},
		},
		{
			name: "proper superset",
			text: "s45 - s45:c0.c4", mode: RangeSuperset, proper: true,
			want: []string{"range_transition range_proper_super range_proper_super:flow s45:c1 - s45:c1.c3;"},
		},
		{
			name: "proper superset equal",
			text: "s45:c1 - s45:c1.c3", mode: RangeSuperset, proper: true,
			want: nil,
		},
		{
			name: "proper superset equal low",
			text: "s45:c1 - s45:c1.c4", mode: RangeSuperset, proper: true,
			want: []string{"range_transition range_proper_super range_proper_super:flow s45:c1 - s45:c1.c3;"},
		},
		{
			name: "proper superset equal high",
			text: "s45 - s45:c1.c3", mode: RangeSuperset, proper: true,
			want: []string{"range_transition range_proper_super range_proper_super:flow s45:c1 - s45:c1.c3;"},
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
	p := loadPolicy(t, "non_mls-v32.pol")
	if p.MLS() {
		t.Error("MLS reported enabled")
	}
	q := NewTERuleQuery(p)
	if err := q.SetSource("system", false, false); err != nil {
		t.Fatal(err)
	}
	checkStatements(t, q.Results(), []string{"allow system system:flow read_high;"})
	if rules := p.MLSRules(); len(rules) != 0 {
		t.Errorf("non-MLS policy has %d range transition rules", len(rules))
	}

	// A range criterion needs MLS symbols, so it cannot be resolved at all
	// when the policy was compiled without MLS.
	mls := NewMLSRuleQuery(p)
	if err := mls.SetRange("s0"); err == nil {
		t.Error("SetRange accepted a range for a policy without MLS")
	} else if !strings.Contains(err.Error(), "MLS") {
		t.Errorf("SetRange error = %v, want it to mention MLS", err)
	}
}
