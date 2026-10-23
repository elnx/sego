// Package sego is a pure-Go reimplementation of the setools policy analysis
// tools. It reads SELinux binary kernel policies and provides the policy
// object model, rule queries and rule rendering used by the tools.
//
// The behaviour mirrors setools 4.7/4.8: symbol lookup, criteria matching and
// rule statements produce the same results as the original tools. Only kernel
// policies (the compiled policy.X binaries) are supported, so features that
// only exist in source policies or policy modules - aliases, neverallow and
// neverallowxperm rules, unexpanded type attributes - are not represented.
package sego

import (
	"fmt"
	"os"

	"github.com/elnx/sego/policy"
)

// Policy is a parsed SELinux binary kernel policy.
type Policy struct {
	db   *policy.Policy
	path string

	types     []*Type // all types and attributes, in policy order
	attribs   []*Type // only attributes
	roles     []*Role
	users     []*User
	classes   []*Class
	bools     []*Boolean
	sens      []*Sensitivity
	cats      []*Category
	levels    []*Level
	teRules   []Rule // TE rules, in policy order
	rbacRules []Rule // role allow and role_transition rules, in policy order
	mlsRules  []Rule // range_transition rules, in policy order
	rulesOnce bool

	byName       map[string]*Type
	byValue      map[uint32]*Type
	roleByValue  map[uint32]*Role
	classByValue map[uint32]*Class
	boolByValue  map[uint32]*Boolean
}

// Open reads and parses the policy file at path.
func Open(path string) (*Policy, error) {
	db, err := policy.Open(path)
	if err != nil {
		return nil, err
	}
	return New(db, path), nil
}

// New wraps an already parsed policy database.
func New(db *policy.Policy, path string) *Policy {
	p := &Policy{
		db:           db,
		path:         path,
		byName:       make(map[string]*Type, len(db.Types)),
		byValue:      make(map[uint32]*Type, len(db.Types)),
		roleByValue:  make(map[uint32]*Role, len(db.Roles)),
		classByValue: make(map[uint32]*Class, len(db.Classes)),
		boolByValue:  make(map[uint32]*Boolean, len(db.Bools)),
	}
	// Index by symbol order (symbol value, which is 1-based) so that policy
	// declaration order is preserved where the tools rely on it.
	byValue := make([]*Type, len(db.Types))
	for i, t := range db.Types {
		if t == nil {
			continue
		}
		ty := &Type{
			policy:      p,
			Name:        t.Name,
			Value:       t.Value,
			IsAttribute: t.IsAttribute,
			aliases:     t.Aliases,
		}
		byValue[i] = ty
		p.byName[ty.Name] = ty
		for _, alias := range ty.aliases {
			p.byName[alias] = ty
		}
		p.byValue[ty.Value] = ty
		p.types = append(p.types, ty)
		if ty.IsAttribute {
			p.attribs = append(p.attribs, ty)
		}
	}
	// The kernel policy stores, for every type, the attributes it belongs
	// to (including the type itself); the reverse map holds the member
	// types of an attribute (the type itself for plain types).
	for i, t := range byValue {
		if t == nil {
			continue
		}
		for _, attr := range db.TypeAttrMap[i] {
			if attr == t.Value || attr == 0 || int(attr) > len(byValue) || byValue[attr-1] == nil {
				continue
			}
			t.attributes = append(t.attributes, byValue[attr-1])
		}
		for _, member := range db.AttrTypeMap[i] {
			if member == t.Value || member == 0 || int(member) > len(byValue) || byValue[member-1] == nil {
				continue
			}
			t.members = append(t.members, byValue[member-1])
		}
	}
	for _, r := range db.Roles {
		if r == nil {
			continue
		}
		role := &Role{policy: p, Name: r.Name, Value: r.Value}
		p.roles = append(p.roles, role)
		p.roleByValue[role.Value] = role
	}
	for _, u := range db.Users {
		if u == nil {
			continue
		}
		p.users = append(p.users, &User{policy: p, Name: u.Name, Value: u.Value})
	}
	for _, c := range db.Classes {
		if c == nil {
			continue
		}
		cls := &Class{policy: p, Name: c.Name, Value: c.Value, Common: c.Common}
		cls.perms = p.permNames(c)
		p.classes = append(p.classes, cls)
		p.classByValue[cls.Value] = cls
	}
	for _, b := range db.Bools {
		if b == nil {
			continue
		}
		bl := &Boolean{policy: p, Name: b.Name, Value: b.Value, state: b.State}
		p.bools = append(p.bools, bl)
		p.boolByValue[bl.Value] = bl
	}
	for _, l := range db.Levels {
		if l == nil {
			continue
		}
		p.sens = append(p.sens, &Sensitivity{policy: p, Name: l.Name, Value: l.Sens})
		p.levels = append(p.levels, &Level{policy: p, sens: l.Sens, cats: l.Cats})
	}
	for _, c := range db.Cats {
		if c == nil {
			continue
		}
		p.cats = append(p.cats, &Category{policy: p, Name: c.Name, Value: c.Value})
	}
	return p
}

// Path returns the path the policy was loaded from, if any.
func (p *Policy) Path() string { return p.path }

// Version returns the policy version of the loaded file.
func (p *Policy) Version() uint32 { return p.db.Version }

// Target returns the policy target platform ("SE Linux" or "XenFlask").
func (p *Policy) Target() string { return p.db.Target }

// MLS reports whether MLS is enabled in the policy.
func (p *Policy) MLS() bool { return p.db.MLS }

// HandleUnknown returns the unknown-permission handling setting.
func (p *Policy) HandleUnknown() uint32 { return p.db.HandleUnknown }

// DB returns the parsed policy database. It is exposed for tools that need
// raw access to the policy file contents.
func (p *Policy) DB() *policy.Policy { return p.db }

// Types returns all types, in policy order.
func (p *Policy) Types() []*Type { return p.types }

// TypeAttributes returns all type attributes, in policy order.
func (p *Policy) TypeAttributes() []*Type { return p.attribs }

// Roles returns all roles, in policy order.
func (p *Policy) Roles() []*Role { return p.roles }

// Users returns all users, in policy order.
func (p *Policy) Users() []*User { return p.users }

// Classes returns all object classes, in policy order.
func (p *Policy) Classes() []*Class { return p.classes }

// Booleans returns all booleans, in policy order.
func (p *Policy) Booleans() []*Boolean { return p.bools }

// Sensitivities returns all sensitivities, in policy order.
func (p *Policy) Sensitivities() []*Sensitivity { return p.sens }

// Categories returns all categories, in policy order.
func (p *Policy) Categories() []*Category { return p.cats }

// LevelDecls returns all level declarations, in policy order.
func (p *Policy) LevelDecls() []*Level { return p.levels }

// Type is a type or a type attribute.
type Type struct {
	policy *Policy

	Name        string
	Value       uint32
	IsAttribute bool

	aliases    []string
	members    []*Type // attributes: the types they contain
	attributes []*Type // types: the attributes they belong to
}

func (t *Type) String() string { return t.Name }

// Aliases returns the other names the type is known by. Kernel policies keep
// one symbol table record per name, so aliases are collected when the policy
// is read.
func (t *Type) Aliases() []string { return t.aliases }

// Members returns the member types of an attribute. It is empty for types.
func (t *Type) Members() []*Type { return t.members }

// Attributes returns the attributes the type belongs to. It is empty for
// attributes.
func (t *Type) Attributes() []*Type { return t.attributes }

// Expand returns the types the symbol stands for: the member types for an
// attribute, and the type itself otherwise.
func (t *Type) Expand() []*Type {
	if !t.IsAttribute {
		return []*Type{t}
	}
	return t.members
}

// Role is a role.
type Role struct {
	policy *Policy
	Name   string
	Value  uint32
}

func (r *Role) String() string { return r.Name }

// Expand returns the role itself, mirroring setools' treatment of roles.
func (r *Role) Expand() []*Role { return []*Role{r} }

// User is a user.
type User struct {
	policy *Policy
	Name   string
	Value  uint32
}

func (u *User) String() string { return u.Name }

// Roles returns the names of the roles the user is allowed to have, in
// policy order.
func (u *User) Roles() []string {
	raw := u.policy.db
	if int(u.Value) > len(raw.Users) || raw.Users[u.Value-1] == nil {
		return nil
	}
	var names []string
	for _, role := range raw.Users[u.Value-1].Roles {
		if int(role) <= len(raw.Roles) && raw.Roles[role-1] != nil {
			names = append(names, raw.Roles[role-1].Name)
		}
	}
	return names
}

// Class is an object class.
type Class struct {
	policy *Policy

	Name   string
	Value  uint32
	Common string

	perms []string
}

func (c *Class) String() string { return c.Name }

// Perms returns the permissions of the class, in policy order.
func (c *Class) Perms() []string { return c.perms }

// permNames returns the permission names of a class, in value order. The
// common's permissions (when the class inherits one) come first because their
// values are always lower than the class's own.
func (p *Policy) permNames(c *policy.Class) []string {
	names := make(map[uint32]string, len(c.Perms))
	for _, cm := range p.db.Commons {
		if cm == nil || cm.Name != c.Common {
			continue
		}
		for _, pm := range cm.Perms {
			names[pm.Value] = pm.Name
		}
	}
	for _, pm := range c.Perms {
		names[pm.Value] = pm.Name
	}
	out := make([]string, 0, len(names))
	for v := uint32(1); v <= c.NumPerms; v++ {
		if n, ok := names[v]; ok {
			out = append(out, n)
		}
	}
	return out
}

// permVector renders a permission bit vector as permission names. Bit i (0
// based) of the vector corresponds to the class permission with value i+1.
func (c *Class) permVector(vector uint32) []string {
	var out []string
	for i, name := range c.perms {
		if vector&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// Boolean is a conditional boolean.
type Boolean struct {
	policy *Policy

	Name  string
	Value uint32
	state bool
}

func (b *Boolean) String() string { return b.Name }

// State returns the default state of the boolean.
func (b *Boolean) State() bool { return b.state }

// Lookup helpers. The error messages match setools' so that tools produce the
// same diagnostics.

// TypeByName returns the type or attribute with the given name.
func (p *Policy) TypeByName(name string) (*Type, error) {
	if t, ok := p.byName[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("%s is not a valid type attribute", name)
}

// TypeAttributeByName returns the attribute with the given name.
func (p *Policy) TypeAttributeByName(name string) (*Type, error) {
	for _, t := range p.attribs {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid type attribute", name)
}

// RoleByName returns the role with the given name.
func (p *Policy) RoleByName(name string) (*Role, error) {
	for _, r := range p.roles {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid role", name)
}

// ClassByName returns the object class with the given name.
func (p *Policy) ClassByName(name string) (*Class, error) {
	for _, c := range p.classes {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid class", name)
}

// BooleanByName returns the boolean with the given name.
func (p *Policy) BooleanByName(name string) (*Boolean, error) {
	for _, b := range p.bools {
		if b.Name == name {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid Boolean", name)
}

// SensitivityByName returns the sensitivity with the given name.
func (p *Policy) SensitivityByName(name string) (*Sensitivity, error) {
	for _, s := range p.sens {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid sensitivity", name)
}

// CategoryByName returns the category with the given name.
func (p *Policy) CategoryByName(name string) (*Category, error) {
	for _, c := range p.cats {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid category", name)
}

// typeValue resolves a type or attribute value.
func (p *Policy) typeValue(v uint32) *Type { return p.byValue[v] }

func (p *Policy) classValue(v uint32) *Class { return p.classByValue[v] }

func (p *Policy) boolName(v uint32) string {
	if b, ok := p.boolByValue[v]; ok {
		return b.Name
	}
	return fmt.Sprintf("<unknown Boolean %d>", v)
}

func (p *Policy) boolValue(v uint32) *Boolean { return p.boolByValue[v] }

// FindPolicyPath locates the policy to use when the user does not name one,
// mirroring setools: the running policy is preferred, then the installed
// binary policies from the highest version down.
func FindPolicyPath() (string, error) {
	if _, err := os.Stat("/sys/fs/selinux/policy"); err == nil {
		return "/sys/fs/selinux/policy", nil
	}
	selinuxType := os.Getenv("SELINUXTYPE")
	if selinuxType == "" {
		selinuxType = "targeted"
	}
	dir := "/etc/selinux/" + selinuxType + "/policy"
	for v := policy.VersionMax; v >= policy.VersionMin; v-- {
		path := fmt.Sprintf("%s/policy.%d", dir, v)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("unable to locate an SELinux policy to load")
}
