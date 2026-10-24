package sego

// Helpers for the policy difference computation: name keyed maps of the
// policy's symbols and small set operations on name lists.

import (
	"sort"
)

func policyCapNames(p *Policy) []string {
	var out []string
	for _, cap := range p.PolicyCaps() {
		out = append(out, cap.Name)
	}
	return out
}

func commonNameMap(p *Policy) map[string]*Common {
	m := make(map[string]*Common)
	for _, c := range p.Commons() {
		m[c.Name] = c
	}
	return m
}

func classNameMap(p *Policy) map[string]*Class {
	m := make(map[string]*Class)
	for _, c := range p.Classes() {
		m[c.Name] = c
	}
	return m
}

func boolNameMap(p *Policy) map[string]*Boolean {
	m := make(map[string]*Boolean)
	for _, b := range p.Booleans() {
		m[b.Name] = b
	}
	return m
}

func roleMap(p *Policy) map[string]*Role {
	m := make(map[string]*Role)
	for _, r := range p.Roles() {
		m[r.Name] = r
	}
	return m
}

func typeMap(p *Policy) map[string]*Type {
	m := make(map[string]*Type)
	for _, t := range p.Types() {
		m[t.Name] = t
	}
	return m
}

func attrMap(p *Policy) map[string]*Type {
	m := make(map[string]*Type)
	for _, t := range p.TypeAttributes() {
		m[t.Name] = t
	}
	return m
}

func userMap(p *Policy) map[string]*User {
	m := make(map[string]*User)
	for _, u := range p.Users() {
		m[u.Name] = u
	}
	return m
}

func categoryMap(p *Policy) map[string]*Category {
	m := make(map[string]*Category)
	for _, c := range p.Categories() {
		m[c.Name] = c
	}
	return m
}

func sensitivityMap(p *Policy) map[string]*Sensitivity {
	m := make(map[string]*Sensitivity)
	for _, s := range p.Sensitivities() {
		m[s.Name] = s
	}
	return m
}

func levelMap(p *Policy) map[string]*Level {
	m := make(map[string]*Level)
	for _, l := range p.LevelDecls() {
		m[p.sensName(l.Sens())] = l
	}
	return m
}

func defaultMap(p *Policy) map[string]Default {
	m := make(map[string]Default)
	for _, d := range p.Defaults() {
		m[d.Kind+"|"+d.Class.Name] = d
	}
	return m
}

func boundsMap(p *Policy) map[string]Bounds {
	m := make(map[string]Bounds)
	for _, b := range p.TypeBounds() {
		m[b.Child.Name] = b
	}
	return m
}

func attrNames(t *Type) []string {
	var out []string
	for _, a := range t.Attributes() {
		out = append(out, a.Name)
	}
	return out
}

func memberNames(t *Type) []string {
	var out []string
	for _, m := range t.Members() {
		out = append(out, m.Name)
	}
	return out
}

func concreteNames(m map[string]*Type) []string {
	var out []string
	for name, t := range m {
		if !t.IsAttribute {
			out = append(out, name)
		}
	}
	return out
}

func roleTypeNames(r *Role) []string {
	var out []string
	for _, t := range r.Types() {
		out = append(out, t.Name)
	}
	return out
}

func levelCatNames(l *Level) []string {
	var out []string
	for _, v := range l.categoryValues() {
		if c, ok := l.policy.categoryValue(v); ok && c != nil {
			out = append(out, c.Name)
		}
	}
	return out
}

// levelStatement renders a level declaration; the reference's str(level) is
// the level itself, without the keyword or a terminator.
func levelStatement(l *Level) string {
	return l.String()
}

func isPermissive(p *Policy, name string) bool {
	for _, value := range p.DB().Permissive {
		if t := p.byValue[value]; t != nil && t.Name == name {
			return true
		}
	}
	return false
}

func userLevel(u *User) string {
	if l := u.DefaultLevel(); l != nil && u.policy.MLS() {
		return l.String()
	}
	return "None (MLS Disabled)"
}

func userRange(u *User) string {
	if r := u.Range(); r != nil && u.policy.MLS() {
		return r.String()
	}
	return "None (MLS Disabled)"
}

// nameDiff splits two name lists into added (right only) and removed (left
// only) names.
func nameDiff(left, right []string) (added, removed []string) {
	return setDiffNames(left, right)
}

// setDiffNames splits two name lists into right-only and left-only names.
func setDiffNames(left, right []string) (added, removed []string) {
	lset := make(map[string]bool, len(left))
	for _, n := range left {
		lset[n] = true
	}
	rset := make(map[string]bool, len(right))
	for _, n := range right {
		rset[n] = true
	}
	for _, n := range right {
		if !lset[n] {
			added = append(added, n)
		}
	}
	for _, n := range left {
		if !rset[n] {
			removed = append(removed, n)
		}
	}
	return added, removed
}

// intersect returns the names present in both lists, sorted.
func intersect(left, right []string) []string {
	lset := make(map[string]bool, len(left))
	for _, n := range left {
		lset[n] = true
	}
	var out []string
	for _, n := range right {
		if lset[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// mapKeys returns the keys of a name keyed map, sorted.
func mapKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeys sorts a name list in place and returns it.
func sortedKeys(names []string) []string {
	sort.Strings(names)
	return names
}

// defaultDiff splits the default statements into added and removed ones.
func defaultDiff(left, right map[string]Default) (added, removed []Default) {
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
