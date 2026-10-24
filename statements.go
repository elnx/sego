package sego

// Symbol statement rendering, matching setools' policyrep statement() methods.
// The seinfo and sediff tools print these statements; the formats are the
// reference tools' interface and are reproduced exactly, quirks included
// (sorted permission and role lists, alias lists that are sorted for types but
// policy order for MLS symbols, the multiline class and common bodies).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/elnx/sego/policy"
)

// Common is a set of shared permissions (a "common" class prefix).
type Common struct {
	policy *Policy
	Name   string
	Value  uint32

	perms []string
}

// Perms returns the permissions of the common, in policy order.
func (c *Common) Perms() []string { return c.perms }

// String returns the common's name, mirroring setools' PolicySymbol.
func (c *Common) String() string { return c.Name }

// Statement renders the common as a policy statement: a multiline body with
// one tab-indented permission per line, sorted.
func (c *Common) Statement() string {
	perms := append([]string(nil), c.perms...)
	sort.Strings(perms)
	return fmt.Sprintf("common %s\n{\n\t%s\n}", c.Name, strings.Join(perms, "\n\t"))
}

// commons returns the commons of the policy, in policy order.
func (p *Policy) commons() []*Common {
	if p.commonObjs != nil {
		return p.commonObjs
	}
	for _, cm := range p.db.Commons {
		if cm == nil {
			continue
		}
		common := &Common{policy: p, Name: cm.Name, Value: cm.Value}
		names := make([]string, 0, len(cm.Perms))
		for _, pm := range cm.Perms {
			names = append(names, pm.Name)
		}
		common.perms = names
		p.commonObjs = append(p.commonObjs, common)
	}
	return p.commonObjs
}

// Commons returns all commons, in policy order.
func (p *Policy) Commons() []*Common { return p.commons() }

// CommonByName returns the common with the given name.
func (p *Policy) CommonByName(name string) (*Common, error) {
	for _, c := range p.commons() {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%s is not a valid common", name)
}

// Statement renders the object class as a policy statement: the class line, an
// optional inherits line and an optional multiline permission block with
// tab-indented, sorted permissions.
func (c *Class) Statement() string {
	var b strings.Builder
	fmt.Fprintf(&b, "class %s\n", c.Name)
	if c.Common != "" {
		fmt.Fprintf(&b, "inherits %s\n", c.Common)
	}
	if len(c.ownPerms) > 0 {
		perms := append([]string(nil), c.ownPerms...)
		sort.Strings(perms)
		fmt.Fprintf(&b, "{\n\t%s\n}", strings.Join(perms, "\n\t"))
	}
	return b.String()
}

// Statement renders the boolean as a policy statement.
func (b *Boolean) Statement() string {
	if b.state {
		return fmt.Sprintf("bool %s true;", b.Name)
	}
	return fmt.Sprintf("bool %s false;", b.Name)
}

// Statement renders the type as a policy statement: aliases sorted, then the
// attributes the type belongs to, sorted.
func (t *Type) Statement() string {
	var b strings.Builder
	fmt.Fprintf(&b, "type %s", t.Name)
	switch len(t.aliases) {
	case 0:
	case 1:
		fmt.Fprintf(&b, " alias %s", t.aliases[0])
	default:
		aliases := append([]string(nil), t.aliases...)
		sort.Strings(aliases)
		fmt.Fprintf(&b, " alias { %s }", strings.Join(aliases, " "))
	}
	if len(t.attributes) > 0 {
		attrs := make([]*Type, len(t.attributes))
		copy(attrs, t.attributes)
		sort.Slice(attrs, func(i, j int) bool { return attrs[i].Name < attrs[j].Name })
		names := make([]string, len(attrs))
		for i, a := range attrs {
			names[i] = a.Name
		}
		fmt.Fprintf(&b, ", %s", strings.Join(names, ", "))
	}
	b.WriteByte(';')
	return b.String()
}

// AttributeStatement renders the type attribute as a policy statement.
func (t *Type) AttributeStatement() string {
	return fmt.Sprintf("attribute %s;", t.Name)
}

// Types returns the types assigned to the role, in policy order.
func (r *Role) Types() []*Type {
	db := r.policy.db
	var out []*Type
	for _, v := range db.Roles[r.Value-1].Types {
		if int(v) <= len(db.Types) && db.Types[v-1] != nil {
			out = append(out, r.policy.byValue[v])
		}
	}
	return out
}

// Statement renders the role as a policy statement: the type set sorted, in
// braces when there is more than one.
func (r *Role) Statement() string {
	types := r.Types()
	switch len(types) {
	case 0:
		return fmt.Sprintf("role %s;", r.Name)
	case 1:
		return fmt.Sprintf("role %s types %s;", r.Name, types[0].Name)
	}
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = t.Name
	}
	sort.Strings(names)
	return fmt.Sprintf("role %s types { %s };", r.Name, strings.Join(names, " "))
}

// DefaultLevel returns the user's default level, or nil when MLS is disabled.
func (u *User) DefaultLevel() *Level {
	db := u.policy.db
	lv := db.Users[u.Value-1].DefaultLevel
	if lv.Sens == 0 && len(lv.Cats) == 0 {
		return nil
	}
	return &Level{policy: u.policy, sens: lv.Sens, cats: lv.Cats}
}

// Range returns the user's MLS range, or nil when MLS is disabled.
func (u *User) Range() *Range {
	db := u.policy.db
	r := db.Users[u.Value-1].Range
	if r.Low.Sens == 0 && r.High.Sens == 0 {
		return nil
	}
	return u.policy.rangeValue(r)
}

// Statement renders the user as a policy statement: the role set sorted, and
// the level and range only when the policy has MLS.
func (u *User) Statement() string {
	var b strings.Builder
	fmt.Fprintf(&b, "user %s roles ", u.Name)
	roles := u.Roles()
	if len(roles) == 1 {
		b.WriteString(roles[0])
	} else {
		sorted := append([]string(nil), roles...)
		sort.Strings(sorted)
		fmt.Fprintf(&b, "{ %s }", strings.Join(sorted, " "))
	}
	level, rng := u.DefaultLevel(), u.Range()
	if level != nil && rng != nil && u.policy.MLS() {
		fmt.Fprintf(&b, " level %s range %s;", level, rng)
	} else {
		b.WriteString(";")
	}
	return b.String()
}

// Bounds pairs a child type with the type it is bounded by.
type Bounds struct {
	Child  *Type
	Parent *Type
}

// Statement renders the typebounds statement.
func (b *Bounds) Statement() string {
	return fmt.Sprintf("typebounds %s %s;", b.Parent.Name, b.Child.Name)
}

// TypeBounds returns every typebounds statement of the policy, in child policy
// order.
func (p *Policy) TypeBounds() []Bounds {
	var out []Bounds
	for _, t := range p.types {
		bound := p.db.Types[t.Value-1].Bounds
		if bound == 0 {
			continue
		}
		parent := p.byValue[bound]
		if parent == nil {
			continue
		}
		out = append(out, Bounds{Child: t, Parent: parent})
	}
	return out
}

// PermissiveTypes returns the types marked permissive, in policy order.
func (p *Policy) PermissiveTypes() []*Type {
	var out []*Type
	// The permissive bitmap holds type values, not zero-based indices.
	for _, value := range p.db.Permissive {
		if t := p.byValue[value]; t != nil {
			out = append(out, t)
		}
	}
	return out
}

// polcapNames maps the policy capability bit to its name, in bit order. The
// names are the ones libsepol's polcaps.c uses.
var polcapNames = []string{
	"network_peer_controls",
	"open_perms",
	"extended_socket_class",
	"always_check_network",
	"cgroup_seclabel",
	"nnp_nosuid_transition",
	"genfs_seclabel_symlinks",
	"ioctl_skip_cloexec",
	"userspace_initial_context",
	"netlink_xperm",
	"netif_wildcard",
	"genfs_seclabel_wildcard",
	"functionfs_seclabel",
	"memfd_class",
	"bpf_token_perms",
}

// PolicyCap is one policy capability.
type PolicyCap struct {
	Name  string
	Value uint32
}

// Statement renders the policycap statement.
func (c PolicyCap) Statement() string {
	return fmt.Sprintf("policycap %s;", c.Name)
}

// PolicyCaps returns the policy capabilities set in the policy, in bit order.
func (p *Policy) PolicyCaps() []PolicyCap {
	var out []PolicyCap
	for _, bit := range p.db.PolicyCaps {
		if int(bit) < len(polcapNames) {
			out = append(out, PolicyCap{Name: polcapNames[bit], Value: bit})
		}
	}
	return out
}

// defaultObjectValues renders the default_user/default_role/default_type
// setting of a class. The values are the constants of libsepol's policydb.h.
func defaultObjectValues(v uint32) (string, bool) {
	switch v {
	case 1:
		return "source", true
	case 2:
		return "target", true
	case 3:
		return "glblub", true
	}
	return "", false
}

// defaultRangeValues renders the default_range setting of a class.
func defaultRangeValues(v uint32) (string, string, bool) {
	switch v {
	case 1: // DEFAULT_SOURCE_LOW
		return "source", "low", true
	case 2: // DEFAULT_SOURCE_HIGH
		return "source", "high", true
	case 3: // DEFAULT_SOURCE_LOW_HIGH
		return "source", "low_high", true
	case 4: // DEFAULT_TARGET_LOW
		return "target", "low", true
	case 5: // DEFAULT_TARGET_HIGH
		return "target", "high", true
	case 6: // DEFAULT_TARGET_LOW_HIGH
		return "target", "low_high", true
	case 7: // DEFAULT_GLBLUB
		return "glblub", "", true
	}
	return "", "", false
}

// Default is one default_user/default_role/default_type/default_range
// statement.
type Default struct {
	Kind  string // "default_user", "default_role", "default_type" or "default_range"
	Class *Class

	value string // source, target or glblub
	rng   string // low, high or low_high; empty when not a range statement
}

// Statement renders the default statement.
func (d *Default) Statement() string {
	if d.rng != "" {
		return fmt.Sprintf("default_range %s %s %s;", d.Class.Name, d.value, d.rng)
	}
	return fmt.Sprintf("%s %s %s;", d.Kind, d.Class.Name, d.value)
}

// Defaults returns the default statements of the policy, in class order.
func (p *Policy) Defaults() []Default {
	var out []Default
	for _, c := range p.classes {
		raw := p.db.Classes[c.Value-1]
		for kind, v := range map[string]uint32{
			"default_user": raw.DefaultUser,
			"default_role": raw.DefaultRole,
			"default_type": raw.DefaultType,
		} {
			if value, ok := defaultObjectValues(v); ok {
				out = append(out, Default{Kind: kind, Class: c, value: value})
			}
		}
		if obj, rng, ok := defaultRangeValues(raw.DefaultRange); ok {
			out = append(out, Default{Kind: "default_range", Class: c, value: obj, rng: rng})
		}
	}
	return out
}

// Statement renders a sensitivity as a policy statement. Unlike type aliases,
// the alias list is not sorted: it keeps the order the policy records carry.
func (s *Sensitivity) Statement() string {
	return fmt.Sprintf("sensitivity %s%s;", s.Name, aliasClause(s.aliases))
}

// Statement renders a category as a policy statement.
func (c *Category) Statement() string {
	return fmt.Sprintf("category %s%s;", c.Name, aliasClause(c.aliases))
}

// aliasClause renders " alias a" or " alias { a b }". The reference tool
// renders these lists in libsepol's hash table order, which is not
// reproducible; this project renders them sorted.
func aliasClause(aliases []string) string {
	switch len(aliases) {
	case 0:
		return ""
	case 1:
		return " alias " + aliases[0]
	default:
		sorted := append([]string(nil), aliases...)
		sort.Strings(sorted)
		return " alias { " + strings.Join(sorted, " ") + " }"
	}
}

// Context renders a raw security context as "user:role:type" or
// "user:role:type:range".
func (p *Policy) Context(c policy.Context) string {
	var b strings.Builder
	if u := p.userName(c.User); u != "" {
		b.WriteString(u)
	}
	b.WriteByte(':')
	if r := p.roleName(c.Role); r != "" {
		b.WriteString(r)
	}
	b.WriteByte(':')
	if t := p.typeValue(c.Type); t != nil {
		b.WriteString(t.Name)
	}
	if p.MLS() {
		if r := p.rangeValue(c.Range); r != nil {
			b.WriteByte(':')
			b.WriteString(r.String())
		}
	}
	return b.String()
}

func (p *Policy) userName(v uint32) string {
	if int(v) <= len(p.db.Users) && v > 0 && p.db.Users[v-1] != nil {
		return p.db.Users[v-1].Name
	}
	return ""
}

func (p *Policy) roleName(v uint32) string {
	if int(v) <= len(p.db.Roles) && v > 0 && p.db.Roles[v-1] != nil {
		return p.db.Roles[v-1].Name
	}
	return ""
}
