package policy

import "fmt"

// Symbol values are 1-based; the datum for value N lives at index N-1.
// Tables may be sparse (kernel policies omit role attributes), so a nil slot
// means "no symbol with that value in this policy".

func growTo[T any](r *reader, slice []T, value uint32, kind string) []T {
	if value == 0 {
		r.fail("invalid %s value 0", kind)
		return slice
	}
	if int(value) > maxSymbols {
		r.fail("invalid %s value %d", kind, value)
		return slice
	}
	for len(slice) < int(value) {
		slice = append(slice, *new(T))
	}
	return slice
}

func (p *Policy) putCommon(r *reader, c *Common) {
	p.Commons = growTo(r, p.Commons, c.Value, "common")
	if r.err == nil {
		p.Commons[c.Value-1] = c
	}
}

func (p *Policy) putClass(r *reader, c *Class) {
	p.Classes = growTo(r, p.Classes, c.Value, "class")
	if r.err == nil {
		p.Classes[c.Value-1] = c
	}
}

func (p *Policy) putRole(r *reader, ro *Role) {
	p.Roles = growTo(r, p.Roles, ro.Value, "role")
	if r.err == nil {
		p.Roles[ro.Value-1] = ro
	}
}

// putType places a type record. Alias records share the value of the type they
// alias, so they are folded into the primary datum's alias list whatever order
// they appear in.
func (p *Policy) putType(r *reader, t *Type) {
	p.Types = growTo(r, p.Types, t.Value, "type")
	if r.err != nil {
		return
	}
	slot := p.Types[t.Value-1]
	if slot == nil {
		p.Types[t.Value-1] = t
		return
	}
	if !t.Primary {
		slot.Aliases = append(slot.Aliases, t.Name)
		return
	}
	if !slot.Primary {
		// The primary datum arrived after one or more of its aliases.
		t.Aliases = append(t.Aliases, slot.Name)
		t.Aliases = append(t.Aliases, slot.Aliases...)
	}
	p.Types[t.Value-1] = t
}

func (p *Policy) putUser(r *reader, u *User) {
	p.Users = growTo(r, p.Users, u.Value, "user")
	if r.err == nil {
		p.Users[u.Value-1] = u
	}
}

func (p *Policy) putBool(r *reader, b *Bool) {
	p.Bools = growTo(r, p.Bools, b.Value, "bool")
	if r.err == nil {
		p.Bools[b.Value-1] = b
	}
}

func (p *Policy) putLevel(r *reader, l *Level) {
	if l.Sens > maxSymbols {
		r.fail("invalid sensitivity value %d", l.Sens)
		return
	}
	for len(p.Levels) < int(l.Sens) {
		p.Levels = append(p.Levels, nil)
	}
	if r.err == nil {
		p.Levels[l.Sens-1] = l
	}
}

func (p *Policy) putCat(r *reader, c *Cat) {
	p.Cats = growTo(r, p.Cats, c.Value, "category")
	if r.err == nil {
		p.Cats[c.Value-1] = c
	}
}

// TypeValue returns the type or attribute with value v, or nil.
func (p *Policy) TypeValue(v uint32) *Type {
	if v == 0 || int(v) > len(p.Types) {
		return nil
	}
	return p.Types[v-1]
}

// Name returns the name of the type or attribute with value v.
func (p *Policy) TypeName(v uint32) string {
	if t := p.TypeValue(v); t != nil {
		return t.Name
	}
	return fmt.Sprintf("<unknown type %d>", v)
}

// RoleName returns the name of the role with value v.
func (p *Policy) RoleName(v uint32) string {
	if v == 0 || int(v) > len(p.Roles) || p.Roles[v-1] == nil {
		return fmt.Sprintf("<unknown role %d>", v)
	}
	return p.Roles[v-1].Name
}

// ClassValue returns the class with value v, or nil.
func (p *Policy) ClassValue(v uint32) *Class {
	if v == 0 || int(v) > len(p.Classes) {
		return nil
	}
	return p.Classes[v-1]
}

// ClassName returns the name of the class with value v.
func (p *Policy) ClassName(v uint32) string {
	if c := p.ClassValue(v); c != nil {
		return c.Name
	}
	return fmt.Sprintf("<unknown class %d>", v)
}

// BoolValue returns the boolean with value v, or nil.
func (p *Policy) BoolValue(v uint32) *Bool {
	if v == 0 || int(v) > len(p.Bools) {
		return nil
	}
	return p.Bools[v-1]
}

// SensName returns the name of the sensitivity with value v.
func (p *Policy) SensName(v uint32) string {
	if v == 0 || int(v) > len(p.Levels) || p.Levels[v-1] == nil {
		return fmt.Sprintf("<unknown sensitivity %d>", v)
	}
	return p.Levels[v-1].Name
}

// CatName returns the name of the category with value v.
func (p *Policy) CatName(v uint32) string {
	if v == 0 || int(v) > len(p.Cats) || p.Cats[v-1] == nil {
		return fmt.Sprintf("<unknown category %d>", v)
	}
	return p.Cats[v-1].Name
}

// Perms returns the effective permission set of c: its own permissions plus,
// when a common is attached, the common's permissions (the common's values are
// always a prefix of the class's, but the list is emitted in value order).
func (p *Policy) ClassPerms(c *Class) []Perm {
	if c == nil {
		return nil
	}
	var common []Perm
	if c.Common != "" {
		for _, cm := range p.Commons {
			if cm != nil && cm.Name == c.Common {
				common = cm.Perms
				break
			}
		}
	}
	out := make([]Perm, 0, len(common)+len(c.Perms))
	seen := make(map[string]bool, len(common)+len(c.Perms))
	for _, group := range [][]Perm{common, c.Perms} {
		for _, pm := range group {
			if seen[pm.Name] {
				continue
			}
			seen[pm.Name] = true
			out = append(out, pm)
		}
	}
	return out
}
