package sego

import (
	"fmt"
	"slices"
	"strings"

	"github.com/elnx/sego/policy"
)

// Sensitivity is an MLS sensitivity.
type Sensitivity struct {
	policy *Policy
	Name   string
	Value  uint32
}

func (s *Sensitivity) String() string { return s.Name }

// Category is an MLS category.
type Category struct {
	policy *Policy
	Name   string
	Value  uint32
}

func (c *Category) String() string { return c.Name }

// Level is an MLS level: a sensitivity plus a set of categories. Levels loaded
// from a policy carry a sensitivity value and category values; levels parsed
// from user input resolve their symbols.
type Level struct {
	policy *Policy

	sens     uint32
	cats     []uint32
	sensSym  *Sensitivity
	catSyms  []*Category
	fromText bool
}

// Sens returns the sensitivity of the level.
func (l *Level) Sens() uint32 { return l.sens }

// String renders the level in policy notation, collapsing runs of consecutive
// categories into ranges: "s0:c0.c3,c7".
func (l *Level) String() string {
	var b strings.Builder
	if l.sensSym != nil {
		b.WriteString(l.sensSym.Name)
	} else {
		b.WriteString(l.policy.sensName(l.sens))
	}
	vals := l.categoryValues()
	if len(vals) == 0 {
		return b.String()
	}
	var groups []string
	for i := 0; i < len(vals); {
		j := i
		for j+1 < len(vals) && vals[j+1] == vals[j]+1 {
			j++
		}
		if j > i {
			groups = append(groups, l.policy.catName(vals[i])+"."+l.policy.catName(vals[j]))
		} else {
			groups = append(groups, l.policy.catName(vals[i]))
		}
		i = j + 1
	}
	b.WriteByte(':')
	b.WriteString(strings.Join(groups, ","))
	return b.String()
}

func (l *Level) categoryValues() []uint32 {
	if l.fromText {
		vals := make([]uint32, 0, len(l.catSyms))
		for _, c := range l.catSyms {
			vals = append(vals, c.Value)
		}
		slices.Sort(vals)
		return vals
	}
	return slices.Sorted(slices.Values(l.cats))
}

// Range is an MLS range: a low and a high level.
type Range struct {
	policy *Policy
	Low    *Level
	High   *Level
}

// String renders the range as setools does: the single level when both ends
// are equal, otherwise "low - high".
func (r *Range) String() string {
	if r.Low.sameLevel(r.High) {
		return r.Low.String()
	}
	return fmt.Sprintf("%s - %s", r.Low, r.High)
}

func (l *Level) sameLevel(other *Level) bool {
	if l == nil || other == nil {
		return l == other
	}
	a, b := l.categoryValues(), other.categoryValues()
	if l.sensitivity() != other.sensitivity() || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (l *Level) sensitivity() uint32 {
	if l.sensSym != nil {
		return l.sensSym.Value
	}
	return l.sens
}

func (p *Policy) sensName(v uint32) string {
	for _, s := range p.sens {
		if s.Value == v {
			return s.Name
		}
	}
	return fmt.Sprintf("<unknown sensitivity %d>", v)
}

func (p *Policy) catName(v uint32) string {
	for _, c := range p.cats {
		if c.Value == v {
			return c.Name
		}
	}
	return fmt.Sprintf("<unknown category %d>", v)
}

func (p *Policy) rangeValue(r policy.Range) *Range {
	return &Range{
		policy: p,
		Low:    &Level{policy: p, sens: r.Low.Sens, cats: r.Low.Cats},
		High:   &Level{policy: p, sens: r.High.Sens, cats: r.High.Cats},
	}
}

// ParseRange parses an MLS range in policy notation: "s0", "s0:c0.c3", or
// "s0:c0 - s3:c1.c7". Sensitivity and category names are resolved against the
// policy, and the diagnostics match setools'.
func (p *Policy) ParseRange(text string) (*Range, error) {
	parts := strings.Split(text, "-")
	low, err := p.parseLevel(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid range (%w).", text, err)
	}
	if len(parts) < 2 {
		return &Range{policy: p, Low: low, High: low}, nil
	}
	high, err := p.parseLevel(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid range (%w).", text, err)
	}
	if high.sensitivity() < low.sensitivity() {
		return nil, fmt.Errorf("%s is not a valid range (%s is not dominated by %s)", text, low, high)
	}
	return &Range{policy: p, Low: low, High: high}, nil
}

// parseLevel resolves one level of a range.
func (p *Policy) parseLevel(text string) (*Level, error) {
	sensName, catText, _ := strings.Cut(text, ":")
	sens, err := p.SensitivityByName(sensName)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid level (%s is not a valid sensitivity)", text, sensName)
	}
	lvl := &Level{policy: p, sensSym: sens, fromText: true}
	if catText == "" {
		return lvl, nil
	}
	for group := range strings.SplitSeq(catText, ",") {
		low, high, isRange := strings.Cut(group, ".")
		first, err := p.CategoryByName(low)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid level (%s is not a valid category)", text, group)
		}
		if !isRange {
			lvl.catSyms = append(lvl.catSyms, first)
			continue
		}
		if strings.Contains(high, ".") {
			return nil, fmt.Errorf("%s is not a valid level (level parsing error)", text)
		}
		last, err := p.CategoryByName(high)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid level (%s is not a valid category range)", text, group)
		}
		// A reversed range contributes only its endpoints, as in setools.
		if last.Value < first.Value {
			lvl.catSyms = append(lvl.catSyms, first, last)
			continue
		}
		for v := first.Value; v <= last.Value; v++ {
			cat, ok := p.categoryValue(v)
			if !ok {
				return nil, fmt.Errorf("%s is not a valid level (category %s is not a valid category range)", text, group)
			}
			lvl.catSyms = append(lvl.catSyms, cat)
		}
	}
	// The categories must be part of the sensitivity's level declaration.
	declared := p.declaredCategories(sens.Value)
	var invalid []string
	for _, cat := range lvl.catSyms {
		if !declared[cat.Value] {
			invalid = append(invalid, cat.Name)
		}
	}
	if len(invalid) > 0 {
		slices.Sort(invalid)
		return nil, fmt.Errorf("%s is not a valid level (category %s is not associated with sensitivity %s)",
			text, strings.Join(invalid, ", "), sens.Name)
	}
	return lvl, nil
}

// declaredCategories returns the category values declared for a sensitivity.
func (p *Policy) declaredCategories(sens uint32) map[uint32]bool {
	out := make(map[uint32]bool)
	for _, lvl := range p.levels {
		if lvl.sens == sens {
			for _, cat := range lvl.cats {
				out[cat] = true
			}
			break
		}
	}
	return out
}

func (p *Policy) categoryValue(v uint32) (*Category, bool) {
	for _, c := range p.cats {
		if c.Value == v {
			return c, true
		}
	}
	return nil, false
}
