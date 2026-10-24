package sego

// Policy difference computation, mirroring setools' diff package: symbols
// match by name; matched symbols are compared by component-specific criteria;
// AV rules match by their expanded permutation cells (conditional, block,
// source, target, class) with unconditional permissions subtracted from the
// conditional cells; the other rule families match on their identity fields
// and differ in their default.

import (
	"fmt"
	"sort"
)

// PolicyDiff holds the differences between two policies. Every list is
// unsorted; the command sorts what it prints.
type PolicyDiff struct {
	ModifiedProperties []ModifiedProperty

	AddedPolcaps   []string
	RemovedPolcaps []string

	AddedCommons    []string
	RemovedCommons  []string
	ModifiedCommons []ModifiedPerms

	AddedClasses    []string
	RemovedClasses  []string
	ModifiedClasses []ModifiedPerms

	AddedDefaults    []Default
	RemovedDefaults  []Default
	ModifiedDefaults []ModifiedDefault

	AddedBooleans    []string
	RemovedBooleans  []string
	ModifiedBooleans []ModifiedBoolean

	AddedRoles    []string
	RemovedRoles  []string
	ModifiedRoles []ModifiedNameSet

	AddedTypes    []string
	RemovedTypes  []string
	ModifiedTypes []ModifiedType

	AddedTypebounds    []Bounds
	RemovedTypebounds  []Bounds
	ModifiedTypebounds []ModifiedBounds

	AddedTypeAttributes    []string
	RemovedTypeAttributes  []string
	ModifiedTypeAttributes []ModifiedNameSet

	AddedUsers    []string
	RemovedUsers  []string
	ModifiedUsers []ModifiedUser

	AddedCategories    []string
	RemovedCategories  []string
	ModifiedCategories []ModifiedAliases

	AddedSensitivities    []string
	RemovedSensitivities  []string
	ModifiedSensitivities []ModifiedAliases

	AddedLevels    []string
	RemovedLevels  []string
	ModifiedLevels []ModifiedLevelDecl

	// TE rules, per rule family: the AV families are allow, auditallow and
	// dontaudit; the xperm families allowxperm, auditallowxperm and
	// dontauditxperm; the type_* families cover type_transition (with
	// filename transitions), type_change and type_member. Kernel policies
	// have no neverallow rules, so there are no neverallow families.
	Allows           AVRuleDiff
	Auditallows      AVRuleDiff
	Dontaudits       AVRuleDiff
	Allowxperms      AVXpermDiff
	Auditallowxperms AVXpermDiff
	Dontauditxperms  AVXpermDiff
	TypeTransitions  TEDiff
	TypeChanges      TEDiff
	TypeMembers      TEDiff

	AddedRoleAllows         []string
	RemovedRoleAllows       []string
	AddedRoleTransitions    []string
	RemovedRoleTransitions  []string
	ModifiedRoleTransitions []ModifiedRuleDefault

	AddedRangeTransitions    []string
	RemovedRangeTransitions  []string
	ModifiedRangeTransitions []ModifiedRuleDefault

	AddedConstrains         []string
	RemovedConstrains       []string
	AddedMLSConstrains      []string
	RemovedMLSConstrains    []string
	AddedValidatetrans      []string
	RemovedValidatetrans    []string
	AddedMLSValidatetrans   []string
	RemovedMLSValidatetrans []string

	AddedInitialSIDs    []string
	RemovedInitialSIDs  []string
	ModifiedInitialSIDs []ModifiedContext

	AddedFSUses    []string
	RemovedFSUses  []string
	ModifiedFSUses []ModifiedContext

	AddedGenfscons    []string
	RemovedGenfscons  []string
	ModifiedGenfscons []ModifiedContext

	AddedNetifcons    []string
	RemovedNetifcons  []string
	ModifiedNetifcons []ModifiedNetifcon

	AddedNodecons    []string
	RemovedNodecons  []string
	ModifiedNodecons []ModifiedContext

	AddedPortcons    []string
	RemovedPortcons  []string
	ModifiedPortcons []ModifiedContext

	AddedIbendportcons    []string
	RemovedIbendportcons  []string
	ModifiedIbendportcons []ModifiedContext

	AddedIbpkeycons    []string
	RemovedIbpkeycons  []string
	ModifiedIbpkeycons []ModifiedContext
}

// ModifiedProperty is a changed policy property (version, MLS, unknown
// handling).
type ModifiedProperty struct {
	Property string
	Added    string
	Removed  string
}

// ModifiedPerms holds added and removed permissions of a matched symbol.
type ModifiedPerms struct {
	Name         string
	AddedPerms   []string
	RemovedPerms []string
}

// ModifiedBoolean is a Boolean whose default state changed.
type ModifiedBoolean struct {
	Name         string
	AddedState   bool
	RemovedState bool
}

// ModifiedNameSet holds added and removed members of a matched symbol.
type ModifiedNameSet struct {
	Name         string
	AddedTypes   []string
	RemovedTypes []string
}

// ModifiedType holds the changes of a matched type.
type ModifiedType struct {
	Name              string
	AddedAttributes   []string
	RemovedAttributes []string
	AddedAliases      []string
	RemovedAliases    []string

	// PermissiveModified reports whether the permissive flag differs;
	// Permissive is the left policy's value.
	PermissiveModified bool
	Permissive         bool
}

// ModifiedBounds is a typebounds statement whose parent changed.
type ModifiedBounds struct {
	Child        string
	AddedBound   string
	RemovedBound string
}

// ModifiedDefault is a default statement whose default changed.
type ModifiedDefault struct {
	// Statement is the statement of the left policy.
	Statement string
	Kind      string
	Class     string

	AddedDefault   string
	RemovedDefault string

	// Range statements only.
	AddedDefaultRange   string
	RemovedDefaultRange string
	HasRange            bool
}

// ModifiedAliases holds added and removed aliases of a matched MLS symbol.
type ModifiedAliases struct {
	Name           string
	AddedAliases   []string
	RemovedAliases []string
}

// ModifiedLevelDecl is a level declaration whose categories changed.
type ModifiedLevelDecl struct {
	Sensitivity       string
	AddedCategories   []string
	RemovedCategories []string
}

// ModifiedUser is a user whose roles, level or range changed.
type ModifiedUser struct {
	Name         string
	AddedRoles   []string
	RemovedRoles []string

	LevelChanged bool
	AddedLevel   string
	RemovedLevel string

	RangeChanged bool
	AddedRange   string
	RemovedRange string
}

// AVRuleDiff holds the differences of one AV rule family.
type AVRuleDiff struct {
	Added    []string
	Removed  []string
	Modified []ModifiedAVRule
}

// ModifiedAVRule is an AV rule whose permissions changed. The MatchedPerms,
// AddedPerms and RemovedPerms lists carry the common, right-only and
// left-only permissions.
type ModifiedAVRule struct {
	// Statement renders the rule of the left policy with its full permission
	// set; the command composes its own rendering from the parts.
	Statement   string
	Ruletype    string
	Source      string
	Target      string
	Class       string
	Conditional string

	MatchedPerms []string
	AddedPerms   []string
	RemovedPerms []string
}

// AVXpermDiff holds the differences of one extended permission rule family.
type AVXpermDiff struct {
	Added    []string
	Removed  []string
	Modified []ModifiedAVXperm
}

// ModifiedAVXperm is an extended permission rule whose permission set changed.
type ModifiedAVXperm struct {
	Statement   string
	Ruletype    string
	Source      string
	Target      string
	Class       string
	XpermType   string
	Conditional string

	MatchedPerms *XPermSet
	AddedPerms   *XPermSet
	RemovedPerms *XPermSet
}

// TEDiff holds the differences of one type_* rule family.
type TEDiff struct {
	Added    []string
	Removed  []string
	Modified []ModifiedTERule
}

// ModifiedTERule is a type_transition, type_change or type_member rule whose
// default type changed.
type ModifiedTERule struct {
	Statement   string
	Ruletype    string
	Source      string
	Target      string
	Class       string
	Filename    string
	Conditional string

	AddedDefault   string
	RemovedDefault string
}

// ModifiedRuleDefault is a role_transition or range_transition rule whose
// default changed.
type ModifiedRuleDefault struct {
	Ruletype       string
	Source         string
	Target         string
	Class          string
	AddedDefault   string
	RemovedDefault string
}

// ModifiedContext is a labeling statement whose context changed.
type ModifiedContext struct {
	// Statement is the rendering prefix without the contexts, e.g.
	// "sid kernel" or "portcon tcp 1111"; the command adds the contexts.
	Statement string

	AddedContext   string
	RemovedContext string
}

// ModifiedNetifcon is a netifcon statement whose contexts changed.
type ModifiedNetifcon struct {
	Device string

	ContextChanged bool
	AddedContext   string
	RemovedContext string

	PacketChanged bool
	AddedPacket   string
	RemovedPacket string
}

// DiffPolicies computes the differences from left to right.
func DiffPolicies(left, right *Policy) *PolicyDiff {
	d := &PolicyDiff{}
	diffProperties(d, left, right)
	diffSymbols(d, left, right)
	diffRules(d, left, right)
	diffConstraints(d, left, right)
	diffOContexts(d, left, right)
	d.normalize()
	return d
}

// ruleDefaultKey renders the identity fields of a modified role or range
// transition for sorting.
func ruleDefaultKey(m ModifiedRuleDefault) string {
	return m.Ruletype + " " + m.Source + " " + m.Target + ":" + m.Class
}

// normalize sorts every difference list the way the reference sorts its
// results: by rendered statement for rules and statements, by name (or
// identity field) for symbols.
func (d *PolicyDiff) normalize() {
	sort.Strings(d.AddedPolcaps)
	sort.Strings(d.RemovedPolcaps)
	sort.Strings(d.AddedCommons)
	sort.Strings(d.RemovedCommons)
	sort.Strings(d.AddedClasses)
	sort.Strings(d.RemovedClasses)
	for _, list := range [][]ModifiedPerms{d.ModifiedCommons, d.ModifiedClasses} {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	}
	sort.Slice(d.AddedDefaults, func(i, j int) bool { return d.AddedDefaults[i].Statement() < d.AddedDefaults[j].Statement() })
	sort.Slice(d.RemovedDefaults, func(i, j int) bool { return d.RemovedDefaults[i].Statement() < d.RemovedDefaults[j].Statement() })
	sort.Slice(d.ModifiedDefaults, func(i, j int) bool { return d.ModifiedDefaults[i].Statement < d.ModifiedDefaults[j].Statement })
	sort.Strings(d.AddedBooleans)
	sort.Strings(d.RemovedBooleans)
	sort.Slice(d.ModifiedBooleans, func(i, j int) bool { return d.ModifiedBooleans[i].Name < d.ModifiedBooleans[j].Name })
	sort.Strings(d.AddedRoles)
	sort.Strings(d.RemovedRoles)
	sort.Slice(d.ModifiedRoles, func(i, j int) bool { return d.ModifiedRoles[i].Name < d.ModifiedRoles[j].Name })
	sort.Strings(d.AddedTypes)
	sort.Strings(d.RemovedTypes)
	sort.Slice(d.ModifiedTypes, func(i, j int) bool { return d.ModifiedTypes[i].Name < d.ModifiedTypes[j].Name })
	sort.Slice(d.AddedTypebounds, func(i, j int) bool { return d.AddedTypebounds[i].Statement() < d.AddedTypebounds[j].Statement() })
	sort.Slice(d.RemovedTypebounds, func(i, j int) bool { return d.RemovedTypebounds[i].Statement() < d.RemovedTypebounds[j].Statement() })
	sort.Slice(d.ModifiedTypebounds, func(i, j int) bool { return d.ModifiedTypebounds[i].Child < d.ModifiedTypebounds[j].Child })
	sort.Strings(d.AddedTypeAttributes)
	sort.Strings(d.RemovedTypeAttributes)
	sort.Slice(d.ModifiedTypeAttributes, func(i, j int) bool { return d.ModifiedTypeAttributes[i].Name < d.ModifiedTypeAttributes[j].Name })
	sort.Strings(d.AddedUsers)
	sort.Strings(d.RemovedUsers)
	sort.Slice(d.ModifiedUsers, func(i, j int) bool { return d.ModifiedUsers[i].Name < d.ModifiedUsers[j].Name })
	sort.Strings(d.AddedCategories)
	sort.Strings(d.RemovedCategories)
	sort.Slice(d.ModifiedCategories, func(i, j int) bool { return d.ModifiedCategories[i].Name < d.ModifiedCategories[j].Name })
	sort.Strings(d.AddedSensitivities)
	sort.Strings(d.RemovedSensitivities)
	sort.Slice(d.ModifiedSensitivities, func(i, j int) bool { return d.ModifiedSensitivities[i].Name < d.ModifiedSensitivities[j].Name })
	sort.Strings(d.AddedLevels)
	sort.Strings(d.RemovedLevels)
	sort.Slice(d.ModifiedLevels, func(i, j int) bool { return d.ModifiedLevels[i].Sensitivity < d.ModifiedLevels[j].Sensitivity })

	for _, av := range []*AVRuleDiff{&d.Allows, &d.Auditallows, &d.Dontaudits} {
		sort.Strings(av.Added)
		sort.Strings(av.Removed)
		sort.Slice(av.Modified, func(i, j int) bool { return av.Modified[i].Statement < av.Modified[j].Statement })
	}
	for _, xp := range []*AVXpermDiff{&d.Allowxperms, &d.Auditallowxperms, &d.Dontauditxperms} {
		sort.Strings(xp.Added)
		sort.Strings(xp.Removed)
		sort.Slice(xp.Modified, func(i, j int) bool { return xp.Modified[i].Statement < xp.Modified[j].Statement })
	}
	for _, te := range []*TEDiff{&d.TypeTransitions, &d.TypeChanges, &d.TypeMembers} {
		sort.Strings(te.Added)
		sort.Strings(te.Removed)
		sort.Slice(te.Modified, func(i, j int) bool { return te.Modified[i].Statement < te.Modified[j].Statement })
	}
	sort.Strings(d.AddedRoleAllows)
	sort.Strings(d.RemovedRoleAllows)
	sort.Strings(d.AddedRoleTransitions)
	sort.Strings(d.RemovedRoleTransitions)
	sort.Slice(d.ModifiedRoleTransitions, func(i, j int) bool {
		return ruleDefaultKey(d.ModifiedRoleTransitions[i]) < ruleDefaultKey(d.ModifiedRoleTransitions[j])
	})
	sort.Strings(d.AddedRangeTransitions)
	sort.Strings(d.RemovedRangeTransitions)
	sort.Slice(d.ModifiedRangeTransitions, func(i, j int) bool {
		return ruleDefaultKey(d.ModifiedRangeTransitions[i]) < ruleDefaultKey(d.ModifiedRangeTransitions[j])
	})
	for _, list := range [][]string{d.AddedConstrains, d.RemovedConstrains,
		d.AddedMLSConstrains, d.RemovedMLSConstrains, d.AddedValidatetrans,
		d.RemovedValidatetrans, d.AddedMLSValidatetrans, d.RemovedMLSValidatetrans} {
		sort.Strings(list)
	}
	for _, list := range [][]string{d.AddedInitialSIDs, d.RemovedInitialSIDs,
		d.AddedFSUses, d.RemovedFSUses, d.AddedGenfscons, d.RemovedGenfscons,
		d.AddedNetifcons, d.RemovedNetifcons, d.AddedNodecons, d.RemovedNodecons,
		d.AddedPortcons, d.RemovedPortcons, d.AddedIbendportcons, d.RemovedIbendportcons,
		d.AddedIbpkeycons, d.RemovedIbpkeycons} {
		sort.Strings(list)
	}
	for _, list := range [][]ModifiedContext{d.ModifiedInitialSIDs, d.ModifiedFSUses,
		d.ModifiedGenfscons, d.ModifiedNodecons, d.ModifiedPortcons,
		d.ModifiedIbendportcons, d.ModifiedIbpkeycons} {
		sort.Slice(list, func(i, j int) bool { return list[i].Statement < list[j].Statement })
	}
	sort.Slice(d.ModifiedNetifcons, func(i, j int) bool { return d.ModifiedNetifcons[i].Device < d.ModifiedNetifcons[j].Device })
	sort.Slice(d.ModifiedProperties, func(i, j int) bool { return d.ModifiedProperties[i].Property < d.ModifiedProperties[j].Property })
}

// diffProperties compares the policy properties.
func diffProperties(d *PolicyDiff, left, right *Policy) {
	if left.HandleUnknown() != right.HandleUnknown() {
		d.ModifiedProperties = append(d.ModifiedProperties, ModifiedProperty{
			Property: "handle_unknown",
			Added:    handleUnknownName(right), Removed: handleUnknownName(left)})
	}
	if left.MLS() != right.MLS() {
		d.ModifiedProperties = append(d.ModifiedProperties, ModifiedProperty{
			Property: "MLS",
			Added:    pyBool(right.MLS()), Removed: pyBool(left.MLS())})
	}
	if left.Version() != right.Version() {
		d.ModifiedProperties = append(d.ModifiedProperties, ModifiedProperty{
			Property: "version",
			Added:    fmt.Sprint(right.Version()), Removed: fmt.Sprint(left.Version())})
	}
}

func handleUnknownName(p *Policy) string {
	switch p.DB().HandleUnknown {
	case 0:
		return "deny"
	case 2:
		return "reject"
	case 4:
		return "allow"
	}
	return fmt.Sprintf("%d", p.DB().HandleUnknown)
}

// diffSymbols computes the symbol component differences.
func diffSymbols(d *PolicyDiff, left, right *Policy) {
	// Policy capabilities.
	d.AddedPolcaps, d.RemovedPolcaps = nameDiff(policyCapNames(left), policyCapNames(right))

	// Commons.
	lc := commonNameMap(left)
	rc := commonNameMap(right)
	d.AddedCommons, d.RemovedCommons = nameDiff(mapKeys(lc), mapKeys(rc))
	for _, name := range intersect(mapKeys(lc), mapKeys(rc)) {
		if added, removed := setDiffNames(lc[name].Perms(), rc[name].Perms()); len(added) > 0 || len(removed) > 0 {
			d.ModifiedCommons = append(d.ModifiedCommons,
				ModifiedPerms{Name: name, AddedPerms: added, RemovedPerms: removed})
		}
	}

	// Classes.
	lcl := classNameMap(left)
	rcl := classNameMap(right)
	d.AddedClasses, d.RemovedClasses = nameDiff(mapKeys(lcl), mapKeys(rcl))
	for _, name := range intersect(mapKeys(lcl), mapKeys(rcl)) {
		if added, removed := setDiffNames(lcl[name].Perms(), rcl[name].Perms()); len(added) > 0 || len(removed) > 0 {
			d.ModifiedClasses = append(d.ModifiedClasses,
				ModifiedPerms{Name: name, AddedPerms: added, RemovedPerms: removed})
		}
	}

	// Defaults.
	ldef := defaultMap(left)
	rdef := defaultMap(right)
	d.AddedDefaults, d.RemovedDefaults = defaultDiff(ldef, rdef)
	for _, key := range intersect(mapKeys(ldef), mapKeys(rdef)) {
		l, r := ldef[key], rdef[key]
		if l.Statement() != r.Statement() {
			md := ModifiedDefault{Kind: l.Kind, Class: l.Class.Name, Statement: l.Statement()}
			md.AddedDefault = r.value
			md.RemovedDefault = l.value
			if l.Kind == "default_range" {
				md.HasRange = true
				md.AddedDefaultRange = r.rng
				md.RemovedDefaultRange = l.rng
			}
			d.ModifiedDefaults = append(d.ModifiedDefaults, md)
		}
	}

	// Booleans.
	lb, rb := boolNameMap(left), boolNameMap(right)
	d.AddedBooleans, d.RemovedBooleans = nameDiff(mapKeys(lb), mapKeys(rb))
	for _, name := range intersect(mapKeys(lb), mapKeys(rb)) {
		if lb[name].State() != rb[name].State() {
			d.ModifiedBooleans = append(d.ModifiedBooleans, ModifiedBoolean{
				Name: name, AddedState: rb[name].State(), RemovedState: lb[name].State()})
		}
	}

	// Roles.
	lr := roleMap(left)
	rr := roleMap(right)
	d.AddedRoles, d.RemovedRoles = nameDiff(mapKeys(lr), mapKeys(rr))
	for _, name := range intersect(mapKeys(lr), mapKeys(rr)) {
		added, removed := setDiffNames(roleTypeNames(lr[name]), roleTypeNames(rr[name]))
		if len(added) > 0 || len(removed) > 0 {
			d.ModifiedRoles = append(d.ModifiedRoles,
				ModifiedNameSet{Name: name, AddedTypes: added, RemovedTypes: removed})
		}
	}

	// Types.
	lt, rt := typeMap(left), typeMap(right)
	d.AddedTypes, d.RemovedTypes = nameDiff(concreteNames(lt), concreteNames(rt))
	for _, name := range intersect(concreteNames(lt), concreteNames(rt)) {
		l, r := lt[name], rt[name]
		mt := ModifiedType{Name: name}
		mt.AddedAttributes, mt.RemovedAttributes = setDiffNames(attrNames(l), attrNames(r))
		mt.AddedAliases, mt.RemovedAliases = setDiffNames(l.Aliases(), r.Aliases())
		leftPermissive, rightPermissive := isPermissive(left, name), isPermissive(right, name)
		if leftPermissive != rightPermissive {
			mt.PermissiveModified = true
			mt.Permissive = leftPermissive
		}
		if len(mt.AddedAttributes) > 0 || len(mt.RemovedAttributes) > 0 ||
			len(mt.AddedAliases) > 0 || len(mt.RemovedAliases) > 0 || mt.PermissiveModified {
			d.ModifiedTypes = append(d.ModifiedTypes, mt)
		}
	}

	// Type attributes.
	la, ra := attrMap(left), attrMap(right)
	d.AddedTypeAttributes, d.RemovedTypeAttributes = nameDiff(mapKeys(la), mapKeys(ra))
	for _, name := range intersect(mapKeys(la), mapKeys(ra)) {
		added, removed := setDiffNames(memberNames(la[name]), memberNames(ra[name]))
		if len(added) > 0 || len(removed) > 0 {
			d.ModifiedTypeAttributes = append(d.ModifiedTypeAttributes,
				ModifiedNameSet{Name: name, AddedTypes: added, RemovedTypes: removed})
		}
	}

	// Typebounds.
	lbnd := boundsMap(left)
	rbnd := boundsMap(right)
	for _, child := range mapKeys(lbnd) {
		if _, ok := rbnd[child]; !ok {
			d.RemovedTypebounds = append(d.RemovedTypebounds, lbnd[child])
		}
	}
	for _, child := range mapKeys(rbnd) {
		if _, ok := lbnd[child]; !ok {
			d.AddedTypebounds = append(d.AddedTypebounds, rbnd[child])
		}
	}
	for _, child := range intersect(mapKeys(lbnd), mapKeys(rbnd)) {
		if lbnd[child].Parent.Name != rbnd[child].Parent.Name {
			d.ModifiedTypebounds = append(d.ModifiedTypebounds, ModifiedBounds{
				Child: child, AddedBound: rbnd[child].Parent.Name,
				RemovedBound: lbnd[child].Parent.Name})
		}
	}

	// Users.
	lu := userMap(left)
	ru := userMap(right)
	d.AddedUsers, d.RemovedUsers = nameDiff(mapKeys(lu), mapKeys(ru))
	for _, name := range intersect(mapKeys(lu), mapKeys(ru)) {
		mu := ModifiedUser{Name: name}
		mu.AddedRoles, mu.RemovedRoles = setDiffNames(lu[name].Roles(), ru[name].Roles())
		ll, rl := userLevel(lu[name]), userLevel(ru[name])
		if ll != rl {
			mu.LevelChanged = true
			mu.AddedLevel, mu.RemovedLevel = rl, ll
		}
		lrng, rrng := userRange(lu[name]), userRange(ru[name])
		if lrng != rrng {
			mu.RangeChanged = true
			mu.AddedRange, mu.RemovedRange = rrng, lrng
		}
		if len(mu.AddedRoles) > 0 || len(mu.RemovedRoles) > 0 || mu.LevelChanged || mu.RangeChanged {
			d.ModifiedUsers = append(d.ModifiedUsers, mu)
		}
	}

	// Categories and sensitivities.
	lcat := categoryMap(left)
	rcat := categoryMap(right)
	d.AddedCategories, d.RemovedCategories = nameDiff(mapKeys(lcat), mapKeys(rcat))
	for _, name := range intersect(mapKeys(lcat), mapKeys(rcat)) {
		added, removed := setDiffNames(lcat[name].Aliases(), rcat[name].Aliases())
		if len(added) > 0 || len(removed) > 0 {
			d.ModifiedCategories = append(d.ModifiedCategories,
				ModifiedAliases{Name: name, AddedAliases: added, RemovedAliases: removed})
		}
	}

	lsen := sensitivityMap(left)
	rsen := sensitivityMap(right)
	d.AddedSensitivities, d.RemovedSensitivities = nameDiff(mapKeys(lsen), mapKeys(rsen))
	for _, name := range intersect(mapKeys(lsen), mapKeys(rsen)) {
		added, removed := setDiffNames(lsen[name].Aliases(), rsen[name].Aliases())
		if len(added) > 0 || len(removed) > 0 {
			d.ModifiedSensitivities = append(d.ModifiedSensitivities,
				ModifiedAliases{Name: name, AddedAliases: added, RemovedAliases: removed})
		}
	}

	// Level declarations.
	llvl := levelMap(left)
	rlvl := levelMap(right)
	for _, name := range mapKeys(llvl) {
		if _, ok := rlvl[name]; !ok {
			d.RemovedLevels = append(d.RemovedLevels, levelStatement(llvl[name]))
		}
	}
	for _, name := range mapKeys(rlvl) {
		if _, ok := llvl[name]; !ok {
			d.AddedLevels = append(d.AddedLevels, levelStatement(rlvl[name]))
		}
	}
	for _, name := range intersect(mapKeys(llvl), mapKeys(rlvl)) {
		added, removed := setDiffNames(levelCatNames(llvl[name]), levelCatNames(rlvl[name]))
		if len(added) > 0 || len(removed) > 0 {
			d.ModifiedLevels = append(d.ModifiedLevels, ModifiedLevelDecl{
				Sensitivity: name, AddedCategories: added, RemovedCategories: removed})
		}
	}
}
