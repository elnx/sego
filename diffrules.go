package sego

// Rule differences of the policy diff: the AV families with their expanded
// permutation cells, the extended permission families, the type_* families,
// and the RBAC and MLS rule families.

import (
	"fmt"
	"sort"
	"strings"
)

// diffRules computes the rule differences.
func diffRules(d *PolicyDiff, left, right *Policy) {
	diffAV(d, left, right)
	diffAVXperm(d, left, right)
	diffTE(d, left, right)
	diffRBAC(d, left, right)
	diffMLS(d, left, right)
}

// avCell is one expanded AV rule cell: the permissions each policy grants.
type avCell struct {
	left, right map[string]bool
	leftRule    Rule
	rightRule   Rule
}

// diffAV computes the allow, auditallow and dontaudit differences.
func diffAV(d *PolicyDiff, left, right *Policy) {
	for _, fam := range []struct {
		ruletype RuleType
		diff     *AVRuleDiff
	}{
		{Allow, &d.Allows},
		{AuditAllow, &d.Auditallows},
		{DontAudit, &d.Dontaudits},
	} {
		cells := avExpand(left, right, fam.ruletype)
		avRemoveRedundant(cells)
		classifyAV(fam.diff, cells)
	}
}

// avExpand builds the permutation cells of one AV rule family.
func avExpand(left, right *Policy, ruletype RuleType) map[avKey]*avCell {
	cells := make(map[avKey]*avCell)
	avExpandSide(cells, left, ruletype, true)
	avExpandSide(cells, right, ruletype, false)
	return cells
}

// avKey identifies one expanded AV rule cell.
type avKey struct{ cond, block, src, tgt, class string }

// avExpandSide adds the rules of one policy to the cells.
func avExpandSide(cells map[avKey]*avCell, p *Policy, ruletype RuleType, isLeft bool) {
	for _, rule := range p.TERules() {
		av, ok := rule.(*AVRule)
		if !ok || av.Kind() != ruletype {
			continue
		}
		cond := unconditional
		block := "True"
		if av.Conditional != nil {
			cond = av.Conditional.String()
			block = pyBool(av.ConditionalBlock)
		}
		for _, s := range av.Source.Expand() {
			for _, t := range av.Target.Expand() {
				key := avKey{cond: cond, block: block, src: s.Name, tgt: t.Name, class: av.Class.Name}
				cell := cells[key]
				if cell == nil {
					cell = &avCell{left: make(map[string]bool), right: make(map[string]bool)}
					cells[key] = cell
				}
				perms := &cell.left
				orig := &cell.leftRule
				if !isLeft {
					perms = &cell.right
					orig = &cell.rightRule
				}
				for _, perm := range av.Perms {
					(*perms)[perm] = true
				}
				if *orig == nil {
					*orig = av
				}
			}
		}
	}
}

// unconditional is the conditional key of rules outside any conditional block.
const unconditional = "<<unconditional>>"

// avRemoveRedundant subtracts the unconditionally granted permissions from the
// conditional cells of the same (source, target, class), per policy.
func avRemoveRedundant(cells map[avKey]*avCell) {
	type plain struct{ src, tgt, class string }
	uncond := make(map[plain]map[string]bool)
	for key, cell := range cells {
		if key.cond != unconditional {
			continue
		}
		p := plain{key.src, key.tgt, key.class}
		merge := uncond[p]
		if merge == nil {
			merge = make(map[string]bool)
			uncond[p] = merge
		}
		for perm := range cell.left {
			merge[perm] = true
		}
		for perm := range cell.right {
			merge[perm] = true
		}
	}
	if len(uncond) == 0 {
		return
	}
	for key, cell := range cells {
		if key.cond == unconditional {
			continue
		}
		for perm := range uncond[plain{key.src, key.tgt, key.class}] {
			delete(cell.left, perm)
			delete(cell.right, perm)
		}
	}
}

// classifyAV sorts the cells into added, removed and modified rules.
func classifyAV(diff *AVRuleDiff, cells map[avKey]*avCell) {
	for key, cell := range cells {
		switch {
		case len(cell.left) == 0 && len(cell.right) == 0:
			// Nothing granted on either side after the redundancy
			// subtraction.
		case len(cell.right) == 0:
			diff.Removed = append(diff.Removed, deriveAV(cell.leftRule, key, permSetNames(cell.left)))
		case len(cell.left) == 0:
			diff.Added = append(diff.Added, deriveAV(cell.rightRule, key, permSetNames(cell.right)))
		default:
			common, added, removed := splitPerms(cell.left, cell.right)
			if len(added) == 0 && len(removed) == 0 {
				continue
			}
			diff.Modified = append(diff.Modified, ModifiedAVRule{
				Statement:    deriveAV(cell.leftRule, key, permSetNames(cell.left)),
				Ruletype:     cell.leftRule.Kind().String(),
				Source:       key.src,
				Target:       key.tgt,
				Class:        key.class,
				Conditional:  condOf(cell.leftRule),
				MatchedPerms: common,
				AddedPerms:   added,
				RemovedPerms: removed,
			})
		}
	}
}

// deriveAV renders one rule of a cell as a policy statement.
func deriveAV(orig Rule, key avKey, perms []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s:%s %s", orig.Kind(), key.src, key.tgt, key.class,
		formatPerms(perms, ";"))
	if c := condOf(orig); c != "" {
		fmt.Fprintf(&b, " [ %s ]:%s", c, pyBool(blockOf(orig)))
	}
	return b.String()
}

// condOf returns the conditional expression of a rule, or "".
func condOf(rule Rule) string {
	switch r := rule.(type) {
	case *AVRule:
		if r.Conditional != nil {
			return r.Conditional.String()
		}
	case *TERule:
		if r.Conditional != nil {
			return r.Conditional.String()
		}
	}
	return ""
}

// blockOf reports the conditional block of a rule.
func blockOf(rule Rule) bool {
	switch r := rule.(type) {
	case *AVRule:
		return r.ConditionalBlock
	case *TERule:
		return r.ConditionalBlock
	}
	return false
}

func permSetNames(perms map[string]bool) []string {
	out := make([]string, 0, len(perms))
	for name := range perms {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// splitPerms splits the permissions of two cells into common, right-only and
// left-only sets.
func splitPerms(left, right map[string]bool) (common, added, removed []string) {
	for perm := range left {
		if right[perm] {
			common = append(common, perm)
		} else {
			removed = append(removed, perm)
		}
	}
	for perm := range right {
		if !left[perm] {
			added = append(added, perm)
		}
	}
	sort.Strings(common)
	sort.Strings(added)
	sort.Strings(removed)
	return common, added, removed
}

// diffAVXperm computes the extended permission rule differences.
func diffAVXperm(d *PolicyDiff, left, right *Policy) {
	for _, fam := range []struct {
		ruletype RuleType
		diff     *AVXpermDiff
	}{
		{AllowXPerm, &d.Allowxperms},
		{AuditAllowXPerm, &d.Auditallowxperms},
		{DontAuditXPerm, &d.Dontauditxperms},
	} {
		type xkey struct{ cond, block, src, tgt, class, xperm string }
		type xcell struct {
			left, right *XPermSet
			leftRule    Rule
			rightRule   Rule
		}
		cells := make(map[xkey]*xcell)
		for _, p := range []*Policy{left, right} {
			isLeft := p == left
			for _, rule := range p.TERules() {
				av, ok := rule.(*AVRuleXperm)
				if !ok || av.Kind() != fam.ruletype {
					continue
				}
				cond := unconditional
				block := "True"
				if av.Conditional != nil {
					cond = av.Conditional.String()
					block = pyBool(av.ConditionalBlock)
				}
				for _, src := range av.Source.Expand() {
					for _, tgt := range av.Target.Expand() {
						key := xkey{cond, block, src.Name, tgt.Name, av.Class.Name, av.XPermType}
						cell := cells[key]
						if cell == nil {
							cell = &xcell{left: &XPermSet{}, right: &XPermSet{}}
							cells[key] = cell
						}
						target := &cell.left
						orig := &cell.leftRule
						if !isLeft {
							target = &cell.right
							orig = &cell.rightRule
						}
						*target = unionXPerms(*target, av.Perms)
						if *orig == nil {
							*orig = av
						}
					}
				}
			}
		}
		for key, cell := range cells {
			plainKey := avKey{src: key.src, tgt: key.tgt, class: key.class}
			switch {
			case cell.left.Len() == 0 && cell.right.Len() == 0:
			case cell.right.Len() == 0:
				fam.diff.Removed = append(fam.diff.Removed, deriveAV(cell.leftRule, plainKey, nil))
			case cell.left.Len() == 0:
				fam.diff.Added = append(fam.diff.Added, deriveAV(cell.rightRule, plainKey, nil))
			default:
				matched := intersectXPerms(cell.left, cell.right)
				added := differenceXPerms(cell.right, cell.left)
				removed := differenceXPerms(cell.left, cell.right)
				if added.Len() == 0 && removed.Len() == 0 {
					continue
				}
				fam.diff.Modified = append(fam.diff.Modified, ModifiedAVXperm{
					Statement:    deriveAV(cell.leftRule, plainKey, nil),
					Ruletype:     cell.leftRule.Kind().String(),
					Source:       key.src,
					Target:       key.tgt,
					Class:        key.class,
					XpermType:    key.xperm,
					Conditional:  condOf(cell.leftRule),
					MatchedPerms: matched,
					AddedPerms:   added,
					RemovedPerms: removed,
				})
			}
		}
	}
}

func unionXPerms(a, b *XPermSet) *XPermSet {
	out := append([]uint32(nil), a.Values()...)
	out = append(out, b.Values()...)
	return NewXPermSet(out...)
}

func intersectXPerms(a, b *XPermSet) *XPermSet {
	var out []uint32
	for _, v := range a.Values() {
		if b.Contains(v) {
			out = append(out, v)
		}
	}
	return NewXPermSet(out...)
}

func differenceXPerms(a, b *XPermSet) *XPermSet {
	var out []uint32
	for _, v := range a.Values() {
		if !b.Contains(v) {
			out = append(out, v)
		}
	}
	return NewXPermSet(out...)
}

// teEntry is one type_* rule of one policy in a cell.
type teEntry struct {
	cond string
	def  string
	rule Rule
	used bool
}

// teKey identifies one type_* rule cell.
type teKey struct{ src, tgt, class, block, filename string }

// diffTE computes the type_transition, type_change and type_member
// differences.
func diffTE(d *PolicyDiff, left, right *Policy) {
	for _, fam := range []struct {
		ruletype RuleType
		diff     *TEDiff
	}{
		{TypeTransition, &d.TypeTransitions},
		{TypeChange, &d.TypeChanges},
		{TypeMember, &d.TypeMembers},
	} {
		lcells := teCells(left, fam.ruletype)
		rcells := teCells(right, fam.ruletype)
		for _, key := range sortedTEKeys(lcells) {
			for _, le := range lcells[key] {
				re, found := matchTEEntry(rcells[key], le)
				if !found {
					fam.diff.Removed = append(fam.diff.Removed, teStatement(le.rule))
					continue
				}
				if re.def != le.def {
					fam.diff.Modified = append(fam.diff.Modified, ModifiedTERule{
						Statement:      teStatement(le.rule),
						Ruletype:       le.rule.Kind().String(),
						Source:         key.src,
						Target:         key.tgt,
						Class:          key.class,
						Filename:       key.filename,
						Conditional:    conditionalString(le.cond),
						AddedDefault:   re.def,
						RemovedDefault: le.def,
					})
				}
			}
		}
		for _, key := range sortedTEKeys(rcells) {
			for _, re := range rcells[key] {
				if _, found := matchTEEntry(lcells[key], re); !found {
					fam.diff.Added = append(fam.diff.Added, teStatement(re.rule))
				}
			}
		}
		sort.Strings(fam.diff.Added)
		sort.Strings(fam.diff.Removed)
	}
}

// teCells buckets the type_* rules of one policy by their identity.
func teCells(p *Policy, ruletype RuleType) map[teKey][]teEntry {
	cells := make(map[teKey][]teEntry)
	for _, rule := range p.TERules() {
		var src, tgt, class, def, filename, cond, block string
		switch r := rule.(type) {
		case *TERule:
			if r.Kind() != ruletype {
				continue
			}
			src, tgt, class, def = r.Source.Name, r.Target.Name, r.Class.Name, r.Default.Name
			cond, block = unconditional, "True"
			if r.Conditional != nil {
				cond = r.Conditional.String()
				block = pyBool(r.ConditionalBlock)
			}
		case *FileNameTERule:
			if ruletype != TypeTransition {
				continue
			}
			src, tgt, class, def = r.Source.Name, r.Target.Name, r.Class.Name, r.Default.Name
			filename = r.Filename
		default:
			continue
		}
		key := teKey{src, tgt, class, block, filename}
		cells[key] = append(cells[key], teEntry{cond: cond, def: def, rule: rule})
	}
	return cells
}

// matchTEEntry finds an unused entry with the same conditional expression.
func matchTEEntry(entries []teEntry, e teEntry) (*teEntry, bool) {
	for i := range entries {
		if entries[i].cond == e.cond && !entries[i].used {
			entries[i].used = true
			return &entries[i], true
		}
	}
	return nil, false
}

// conditionalString renders a conditional expression, mapping the
// unconditional placeholder to the empty string the command expects.
func conditionalString(cond string) string {
	if cond == unconditional {
		return ""
	}
	return cond
}

// teStatement renders a type_* rule as a policy statement.
func teStatement(rule Rule) string {
	switch r := rule.(type) {
	case *TERule:
		return r.String()
	case *FileNameTERule:
		return r.String()
	}
	return ""
}

// sortedTEKeys returns the keys of a cell map in a stable order.
func sortedTEKeys(cells map[teKey][]teEntry) []teKey {
	out := make([]teKey, 0, len(cells))
	for key := range cells {
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].src != out[j].src {
			return out[i].src < out[j].src
		}
		if out[i].tgt != out[j].tgt {
			return out[i].tgt < out[j].tgt
		}
		if out[i].class != out[j].class {
			return out[i].class < out[j].class
		}
		if out[i].block != out[j].block {
			return out[i].block < out[j].block
		}
		return out[i].filename < out[j].filename
	})
	return out
}

// diffRBAC computes the role allow and role_transition differences.
func diffRBAC(d *PolicyDiff, left, right *Policy) {
	lallow, rall := map[string]string{}, map[string]string{}
	ltrans, rtrans := map[string]string{}, map[string]string{}
	lrule, rrule := map[string]*RoleTransitionRule{}, map[string]*RoleTransitionRule{}
	for _, p := range []*Policy{left, right} {
		allows, trans := lallow, ltrans
		rules := lrule
		if p == right {
			allows, trans = rall, rtrans
			rules = rrule
		}
		for _, rule := range p.RBACRules() {
			switch r := rule.(type) {
			case *RoleAllowRule:
				allows[r.Source.Name+"->"+r.Target.Name] = r.String()
			case *RoleTransitionRule:
				key := r.Source.Name + "|" + r.Target.Name + "|" + r.Class.Name
				trans[key] = r.String()
				rules[key] = r
			}
		}
	}
	d.AddedRoleAllows, d.RemovedRoleAllows = valueDiff(lallow, rall)
	d.AddedRoleTransitions, d.RemovedRoleTransitions = valueDiff(ltrans, rtrans)
	for _, key := range intersect(mapKeys(ltrans), mapKeys(rtrans)) {
		l, r := lrule[key], rrule[key]
		if l.Default.Name != r.Default.Name {
			d.ModifiedRoleTransitions = append(d.ModifiedRoleTransitions, ModifiedRuleDefault{
				Ruletype:       RuleRoleTransition.String(),
				Source:         l.Source.Name,
				Target:         l.Target.Name,
				Class:          l.Class.Name,
				AddedDefault:   r.Default.Name,
				RemovedDefault: l.Default.Name,
			})
		}
	}
}

// diffMLS computes the range_transition differences.
func diffMLS(d *PolicyDiff, left, right *Policy) {
	ltrans, rtrans := map[string]string{}, map[string]string{}
	lrule, rrule := map[string]*MLSRule{}, map[string]*MLSRule{}
	for _, p := range []*Policy{left, right} {
		trans := ltrans
		rules := lrule
		if p == right {
			trans = rtrans
			rules = rrule
		}
		for _, rule := range p.MLSRules() {
			r := rule.(*MLSRule)
			key := r.Source.Name + "|" + r.Target.Name + "|" + r.Class.Name
			trans[key] = r.String()
			rules[key] = r
		}
	}
	d.AddedRangeTransitions, d.RemovedRangeTransitions = valueDiff(ltrans, rtrans)
	for _, key := range intersect(mapKeys(ltrans), mapKeys(rtrans)) {
		l, r := lrule[key], rrule[key]
		if l.Default.String() != r.Default.String() {
			d.ModifiedRangeTransitions = append(d.ModifiedRangeTransitions, ModifiedRuleDefault{
				Ruletype:       l.Ruletype.String(),
				Source:         l.Source.Name,
				Target:         l.Target.Name,
				Class:          l.Class.Name,
				AddedDefault:   r.Default.String(),
				RemovedDefault: l.Default.String(),
			})
		}
	}
}

// valueDiffObj splits two object maps into added and removed statements,
// rendered with render.
func valueDiffObj[T any](left, right map[string]T, render func(T) string) (added, removed []string) {
	l := make(map[string]string, len(left))
	for k, v := range left {
		l[k] = render(v)
	}
	r := make(map[string]string, len(right))
	for k, v := range right {
		r[k] = render(v)
	}
	return valueDiff(l, r)
}

// valueDiff splits two statement maps into added and removed statements.
func valueDiff(left, right map[string]string) (added, removed []string) {
	for _, key := range sortedKeys(mapKeys(right)) {
		if _, ok := left[key]; !ok {
			added = append(added, right[key])
		}
	}
	for _, key := range sortedKeys(mapKeys(left)) {
		if _, ok := right[key]; !ok {
			removed = append(removed, left[key])
		}
	}
	return added, removed
}
