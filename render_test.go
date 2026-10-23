package sego

import (
	"strings"
	"testing"

	"github.com/elnx/sego/policy"
)

func TestXPermSetFormat(t *testing.T) {
	tests := []struct {
		text   string
		want   string
		ranges int
	}{
		{"0x8910", "0x8910", 1},
		{"0x0000-0x00ff", "0x0000-0x00ff", 1},
		{"0x0000-0x00ff,0x8910", "0x0000-0x00ff 0x8910", 2},
		{"0x30-0x40,0x08", "0x0008 0x0030-0x0040", 2},
		{"0x40-0x30", "0x0030-0x0040", 1}, // reversed ranges are normalised
		{"0x10,0x10,0x11", "0x0010-0x0011", 1},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			set, err := ParseXPermSet(tc.text)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := set.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
			if got := set.Ranges(); got != tc.ranges {
				t.Errorf("Ranges() = %d, want %d", got, tc.ranges)
			}
		})
	}
}

func TestXPermSetErrors(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"zz", "invalid literal for int() with base 16: 'zz'"},
		{"0x12345", "0x12345 is not a valid ioctl."},
		{"0x1-0x2-0x3", "Unable to parse \"0x1-0x2-0x3\" for xperms."},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			_, err := ParseXPermSet(tc.text)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestXPermSetOperations(t *testing.T) {
	a := NewXPermSet(0x10, 0x11, 0x12)
	b := NewXPermSet(0x12, 0x13)
	c := NewXPermSet(0x12, 0x11, 0x10)
	if !a.Intersects(b) {
		t.Error("expected a to intersect b")
	}
	if a.Equal(b) {
		t.Error("expected a != b")
	}
	if !a.Equal(c) {
		t.Error("expected a == c regardless of order")
	}
	if !a.Contains(0x11) || a.Contains(0x13) {
		t.Error("Contains is wrong")
	}
}

func TestAVRuleXpermRendering(t *testing.T) {
	p := loadPolicy(t, "xperm-v30.pol")
	class := p.Classes()[0]

	tests := []struct {
		name string
		rule *AVRuleXperm
		want string
	}{
		{
			name: "single value",
			rule: &AVRuleXperm{Ruletype: AllowXPerm, Source: p.Types()[0], Target: p.Types()[0],
				Class: class, XPermType: "ioctl", Perms: NewXPermSet(0x1234)},
			want: "allowxperm " + p.Types()[0].Name + " " + p.Types()[0].Name + ":" + class.Name +
				" ioctl 0x1234;",
		},
		{
			name: "single run",
			rule: &AVRuleXperm{Ruletype: AllowXPerm, Source: p.Types()[0], Target: p.Types()[0],
				Class: class, XPermType: "ioctl", Perms: NewXPermSet(0x00, 0x01, 0x02)},
			want: "allowxperm " + p.Types()[0].Name + " " + p.Types()[0].Name + ":" + class.Name +
				" ioctl 0x0000-0x0002;",
		},
		{
			name: "two runs",
			rule: &AVRuleXperm{Ruletype: AllowXPerm, Source: p.Types()[0], Target: p.Types()[0],
				Class: class, XPermType: "ioctl", Perms: NewXPermSet(0x00, 0x01, 0x10)},
			want: "allowxperm " + p.Types()[0].Name + " " + p.Types()[0].Name + ":" + class.Name +
				" ioctl { 0x0000-0x0001 0x0010 };",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}

	// Extended permission rules never render the conditional suffix, which
	// matches setools.
	rule := &AVRuleXperm{Ruletype: AllowXPerm, Source: p.Types()[0], Target: p.Types()[0],
		Class: class, XPermType: "ioctl", Perms: NewXPermSet(0x1234)}
	rule.Conditional = &Conditional{policy: p}
	if got := rule.String(); strings.Contains(got, "[") {
		t.Errorf("extended permission rule rendered a conditional: %q", got)
	}
}

func TestFileNameTERuleRendering(t *testing.T) {
	p := loadPolicy(t, "xperm-v30.pol")
	rule := &FileNameTERule{
		Source:   p.Types()[0],
		Target:   p.Types()[1],
		Class:    p.Classes()[0],
		Default:  p.Types()[2],
		Filename: "shadow",
	}
	want := "type_transition " + p.Types()[0].Name + " " + p.Types()[1].Name + ":" +
		p.Classes()[0].Name + " " + p.Types()[2].Name + " shadow;"
	if got := rule.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestConditionalRendering covers the postfix to infix conversion, including
// setools' right-operand-first ordering and its precedence bookkeeping.
func TestConditionalRendering(t *testing.T) {
	p := loadPolicy(t, "te_semantics-v30.pol")
	boolValue := func(name string) uint32 {
		b, err := p.BooleanByName(name)
		if err != nil {
			t.Fatal(err)
		}
		return b.Value
	}
	tests := []struct {
		name  string
		exprs []policy.CondExpr
		want  string
	}{
		{
			name: "single boolean",
			exprs: []policy.CondExpr{
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
			},
			want: "c_one",
		},
		{
			name: "and",
			exprs: []policy.CondExpr{
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
				{ExprType: policy.CondBool, Boolean: boolValue("c_two")},
				{ExprType: policy.CondAnd},
			},
			want: "c_two && c_one",
		},
		{
			name: "or",
			exprs: []policy.CondExpr{
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
				{ExprType: policy.CondBool, Boolean: boolValue("c_two")},
				{ExprType: policy.CondOr},
			},
			want: "c_two || c_one",
		},
		{
			name: "not",
			exprs: []policy.CondExpr{
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
				{ExprType: policy.CondNot},
			},
			want: "! c_one",
		},
		{
			name: "nested",
			exprs: []policy.CondExpr{
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
				{ExprType: policy.CondBool, Boolean: boolValue("c_two")},
				{ExprType: policy.CondOr},
				{ExprType: policy.CondBool, Boolean: boolValue("c_one")},
				{ExprType: policy.CondAnd},
			},
			// setools renders the right operand first and tracks the
			// previous operator's precedence, so this is the expected
			// (if surprising) output.
			want: "( c_one && c_two || c_one )",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := p.conditional(&policy.Condition{Exprs: tc.exprs})
			if got := c.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLevelAndRangeRendering(t *testing.T) {
	p := loadPolicy(t, "mls_ranges-v30.pol")
	tests := []struct {
		text string
		want string
	}{
		{"s0", "s0"},
		{"s1:c0", "s1:c0"},
		{"s1:c0.c3", "s1:c0.c3"},
		{"s1:c0,c2", "s1:c0,c2"},
		{"s1:c0.c2,c3", "s1:c0.c3"},
		{"s1:c0 - s3:c1.c3", "s1:c0 - s3:c1.c3"},
		{"s1 - s3", "s1 - s3"},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			rng, err := p.ParseRange(tc.text)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := rng.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseRangeErrors(t *testing.T) {
	p := loadPolicy(t, "mls_ranges-v30.pol")
	if _, err := p.ParseRange("nosuch"); err == nil {
		t.Error("expected an error for an unknown sensitivity")
	}
	if _, err := p.ParseRange("s3 - s1"); err == nil {
		t.Error("expected an error for a high level below the low level")
	}
	if _, err := p.ParseRange("s0:nosuchcat"); err == nil {
		t.Error("expected an error for an unknown category")
	}
}

func TestMatchIndirect(t *testing.T) {
	p := loadPolicy(t, "te_semantics-v30.pol")
	attr, err := p.TypeByName("src_indirect") // attribute with member src_indirect_member
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.TypeByName("src_indirect_member")
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.TypeByName("tgt_indirect")
	if err != nil {
		t.Fatal(err)
	}
	if len(attr.Expand()) == 0 {
		t.Fatal("attribute src_indirect has no members")
	}
	if !matchIndirect(plain, attr, true, nil) {
		t.Error("indirect match should find the member type")
	}
	if matchIndirect(plain, attr, false, nil) {
		t.Error("direct match must not expand attributes")
	}
	if matchIndirect(other, attr, true, nil) {
		t.Error("unrelated type must not match")
	}
	if !matchIndirect(attr, plain, true, nil) {
		t.Error("an attribute operand should match a member type criterion")
	}
}
