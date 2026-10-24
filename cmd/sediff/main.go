// Command sediff reports the semantic differences of two SELinux binary
// kernel policies. It is the sego reimplementation of setools' sediff and
// reproduces the reference tool's output, exit statuses and diagnostics.
//
// Usage errors (bad usage of the command line) are printed to stderr with the
// usage line, and exit with status 2. Runtime errors (a policy that cannot be
// opened) print only the error message, to stdout, and exit with status 1,
// exactly as the reference tool does.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/sediff
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes sediff with argv (argv[0] is the program name) and returns the
// process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "sediff"
	if len(argv) > 0 {
		if base := filepath.Base(argv[0]); base != "" && base != "." {
			prog = base
		}
	}
	p := argparse.New(prog, description, epilog, optionTable())

	a, err := p.Parse(argv[1:])
	if err != nil {
		return p.Error(stderr, err)
	}
	if a.VersionRequested() {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if a.HelpRequested() {
		p.HelpTo(stdout)
		return 0
	}

	out := bufio.NewWriter(stdout)
	err = sediff(a, out, stderr)
	out.Flush()
	if err != nil {
		if a.Flag("debug") {
			// The reference tool re-raises the exception under --debug: it
			// exits 1 with a traceback on stderr instead of the message on
			// stdout.
			fmt.Fprintf(stderr, "%s%s\n", debug.Stack(), err)
			return 1
		}
		fmt.Fprintln(out, err)
		out.Flush()
		return 1
	}
	return 0
}

// sediff loads both policies and prints the selected difference sections.
func sediff(a *argparse.Args, out, stderr io.Writer) error {
	verbosef(a, stderr, "Opening SELinux policy %q", a.Value("POLICY1"))
	left, err := sego.Open(a.Value("POLICY1"))
	if err != nil {
		return err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", a.Value("POLICY1"))
	verbosef(a, stderr, "Opening SELinux policy %q", a.Value("POLICY2"))
	right, err := sego.Open(a.Value("POLICY2"))
	if err != nil {
		return err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", a.Value("POLICY2"))

	diff := sego.DiffPolicies(left, right)
	if a.Flag("verbose") || a.Flag("debug") {
		verbosef(a, stderr, "Policy diff left policy set to %s", left.Path())
		verbosef(a, stderr, "Policy diff right policy set to %s", right.Path())
		logDiffSelection(a, stderr, left, right)
	}

	stats := a.Flag("stats")
	all := allDifferences(a)
	r := reporter{out: out, stats: stats}

	// -A selects the allow and allowxperm families, as in the reference.
	allow := a.Flag("allow") || a.Flag("A")
	allowxperm := a.Flag("allowxperm") || a.Flag("A")

	if on(a, all, "property") && (len(diff.ModifiedProperties) > 0 || a.Flag("property")) {
		r.titlef("Policy Properties (%d Modified)", len(diff.ModifiedProperties))
		if !stats {
			for _, prop := range diff.ModifiedProperties {
				r.itemf("      * %s +%s -%s", prop.Property, prop.Added, prop.Removed)
			}
		}
		r.blank()
	}

	if on(a, all, "polcap") && (len(diff.AddedPolcaps) > 0 || len(diff.RemovedPolcaps) > 0 || a.Flag("polcap")) {
		r.titlef("Policy Capabilities (%d Added, %d Removed)", len(diff.AddedPolcaps), len(diff.RemovedPolcaps))
		r.addedRemoved("Policy Capabilities",
			diff.AddedPolcaps, diff.RemovedPolcaps)
		r.blank()
	}

	if on(a, all, "common") && (len(diff.AddedCommons) > 0 || len(diff.RemovedCommons) > 0 || len(diff.ModifiedCommons) > 0 || a.Flag("common")) {
		r.titlef("Commons (%d Added, %d Removed, %d Modified)",
			len(diff.AddedCommons), len(diff.RemovedCommons), len(diff.ModifiedCommons))
		r.addedRemoved("Commons", diff.AddedCommons, diff.RemovedCommons)
		if len(diff.ModifiedCommons) > 0 && !stats {
			r.listf("   Modified Commons: %d", len(diff.ModifiedCommons))
			for _, m := range diff.ModifiedCommons {
				r.modifiedPermSet(m.Name, m.AddedPerms, m.RemovedPerms, "permissions")
			}
		}
		r.blank()
	}

	if on(a, all, "class") && (len(diff.AddedClasses) > 0 || len(diff.RemovedClasses) > 0 || len(diff.ModifiedClasses) > 0 || a.Flag("class")) {
		r.titlef("Classes (%d Added, %d Removed, %d Modified)",
			len(diff.AddedClasses), len(diff.RemovedClasses), len(diff.ModifiedClasses))
		r.addedRemoved("Classes", diff.AddedClasses, diff.RemovedClasses)
		if len(diff.ModifiedClasses) > 0 && !stats {
			r.listf("   Modified Classes: %d", len(diff.ModifiedClasses))
			for _, m := range diff.ModifiedClasses {
				r.modifiedPermSet(m.Name, m.AddedPerms, m.RemovedPerms, "permissions")
			}
		}
		r.blank()
	}

	if on(a, all, "default") && (len(diff.AddedDefaults) > 0 || len(diff.RemovedDefaults) > 0 || len(diff.ModifiedDefaults) > 0 || a.Flag("default")) {
		r.titlef("Defaults (%d Added, %d Removed, %d Modified)",
			len(diff.AddedDefaults), len(diff.RemovedDefaults), len(diff.ModifiedDefaults))
		addedRemovedFunc(&r, "Added Defaults", "Defaults",
			diff.AddedDefaults, diff.RemovedDefaults, defaultStatement)
		if len(diff.ModifiedDefaults) > 0 && !stats {
			r.listf("   Modified Defaults: %d", len(diff.ModifiedDefaults))
			for _, m := range diff.ModifiedDefaults {
				r.modifiedDefault(m)
			}
		}
		r.blank()
	}

	if on(a, all, "bool") && (len(diff.AddedBooleans) > 0 || len(diff.RemovedBooleans) > 0 || len(diff.ModifiedBooleans) > 0 || a.Flag("bool")) {
		r.titlef("Booleans (%d Added, %d Removed, %d Modified)",
			len(diff.AddedBooleans), len(diff.RemovedBooleans), len(diff.ModifiedBooleans))
		r.addedRemoved("Booleans", diff.AddedBooleans, diff.RemovedBooleans)
		if len(diff.ModifiedBooleans) > 0 && !stats {
			r.listf("   Modified Booleans: %d", len(diff.ModifiedBooleans))
			for _, m := range diff.ModifiedBooleans {
				r.itemf("      * %s (Modified default state)", m.Name)
				r.itemf("          + %s", pythonBool(m.AddedState))
				r.itemf("          - %s", pythonBool(m.RemovedState))
			}
		}
		r.blank()
	}

	if on(a, all, "role") && (len(diff.AddedRoles) > 0 || len(diff.RemovedRoles) > 0 || len(diff.ModifiedRoles) > 0 || a.Flag("role")) {
		r.titlef("Roles (%d Added, %d Removed, %d Modified)",
			len(diff.AddedRoles), len(diff.RemovedRoles), len(diff.ModifiedRoles))
		r.addedRemoved("Roles", diff.AddedRoles, diff.RemovedRoles)
		if len(diff.ModifiedRoles) > 0 && !stats {
			r.listf("   Modified Roles: %d", len(diff.ModifiedRoles))
			for _, m := range diff.ModifiedRoles {
				r.modifiedNameSet(m.Name, m.AddedTypes, m.RemovedTypes, "types")
			}
		}
		r.blank()
	}

	if on(a, all, "type") && (len(diff.AddedTypes) > 0 || len(diff.RemovedTypes) > 0 || len(diff.ModifiedTypes) > 0 || a.Flag("type")) {
		r.titlef("Types (%d Added, %d Removed, %d Modified)",
			len(diff.AddedTypes), len(diff.RemovedTypes), len(diff.ModifiedTypes))
		r.addedRemoved("Types", diff.AddedTypes, diff.RemovedTypes)
		if len(diff.ModifiedTypes) > 0 && !stats {
			r.listf("   Modified Types: %d", len(diff.ModifiedTypes))
			for _, m := range diff.ModifiedTypes {
				r.modifiedType(m)
			}
		}
		r.blank()
	}

	if on(a, all, "typebounds") && (len(diff.AddedTypebounds) > 0 || len(diff.RemovedTypebounds) > 0 || len(diff.ModifiedTypebounds) > 0 || a.Flag("typebounds")) {
		r.titlef("Typebounds (%d Added, %d Removed, %d Modified)",
			len(diff.AddedTypebounds), len(diff.RemovedTypebounds), len(diff.ModifiedTypebounds))
		addedRemovedFunc(&r, "Added Typebounds", "Typebounds",
			diff.AddedTypebounds, diff.RemovedTypebounds, boundsStatement)
		if len(diff.ModifiedTypebounds) > 0 && !stats {
			r.listf("   Modified Typebounds: %d", len(diff.ModifiedTypebounds))
			for _, m := range diff.ModifiedTypebounds {
				r.itemf("      * typebounds +%s -%s %s;", m.AddedBound, m.RemovedBound, m.Child)
			}
		}
		r.blank()
	}

	if on(a, all, "attribute") && (len(diff.AddedTypeAttributes) > 0 || len(diff.RemovedTypeAttributes) > 0 || len(diff.ModifiedTypeAttributes) > 0 || a.Flag("attribute")) {
		r.titlef("Type Attributes (%d Added, %d Removed, %d Modified)",
			len(diff.AddedTypeAttributes), len(diff.RemovedTypeAttributes), len(diff.ModifiedTypeAttributes))
		r.addedRemoved("Type Attributes",
			diff.AddedTypeAttributes, diff.RemovedTypeAttributes)
		if len(diff.ModifiedTypeAttributes) > 0 && !stats {
			r.listf("   Modified Type Attributes: %d", len(diff.ModifiedTypeAttributes))
			for _, m := range diff.ModifiedTypeAttributes {
				r.modifiedNameSet(m.Name, m.AddedTypes, m.RemovedTypes, "types")
			}
		}
		r.blank()
	}

	if on(a, all, "user") && (len(diff.AddedUsers) > 0 || len(diff.RemovedUsers) > 0 || len(diff.ModifiedUsers) > 0 || a.Flag("user")) {
		r.titlef("Users (%d Added, %d Removed, %d Modified)",
			len(diff.AddedUsers), len(diff.RemovedUsers), len(diff.ModifiedUsers))
		r.addedRemoved("Users", diff.AddedUsers, diff.RemovedUsers)
		if len(diff.ModifiedUsers) > 0 && !stats {
			r.listf("   Modified Users: %d", len(diff.ModifiedUsers))
			for _, m := range diff.ModifiedUsers {
				r.modifiedUser(m)
			}
		}
		r.blank()
	}

	if on(a, all, "category") && (len(diff.AddedCategories) > 0 || len(diff.RemovedCategories) > 0 || len(diff.ModifiedCategories) > 0 || a.Flag("category")) {
		r.titlef("Categories (%d Added, %d Removed, %d Modified)",
			len(diff.AddedCategories), len(diff.RemovedCategories), len(diff.ModifiedCategories))
		r.addedRemoved("Categories", diff.AddedCategories, diff.RemovedCategories)
		if len(diff.ModifiedCategories) > 0 && !stats {
			r.listf("   Modified Categories: %d", len(diff.ModifiedCategories))
			for _, m := range diff.ModifiedCategories {
				r.modifiedAliases(m.Name, m.AddedAliases, m.RemovedAliases)
			}
		}
		r.blank()
	}

	if on(a, all, "sensitivity") && (len(diff.AddedSensitivities) > 0 || len(diff.RemovedSensitivities) > 0 || len(diff.ModifiedSensitivities) > 0 || a.Flag("sensitivity")) {
		r.titlef("Sensitivities (%d Added, %d Removed, %d Modified)",
			len(diff.AddedSensitivities), len(diff.RemovedSensitivities), len(diff.ModifiedSensitivities))
		r.addedRemoved("Sensitivities",
			diff.AddedSensitivities, diff.RemovedSensitivities)
		if len(diff.ModifiedSensitivities) > 0 && !stats {
			r.listf("   Modified Sensitivities: %d", len(diff.ModifiedSensitivities))
			for _, m := range diff.ModifiedSensitivities {
				r.modifiedAliases(m.Name, m.AddedAliases, m.RemovedAliases)
			}
		}
		r.blank()
	}

	if on(a, all, "level") && (len(diff.AddedLevels) > 0 || len(diff.RemovedLevels) > 0 || len(diff.ModifiedLevels) > 0 || a.Flag("level")) {
		r.titlef("Levels (%d Added, %d Removed, %d Modified)",
			len(diff.AddedLevels), len(diff.RemovedLevels), len(diff.ModifiedLevels))
		r.addedRemoved("Levels", diff.AddedLevels, diff.RemovedLevels)
		if len(diff.ModifiedLevels) > 0 && !stats {
			r.listf("   Modified Levels: %d", len(diff.ModifiedLevels))
			for _, m := range diff.ModifiedLevels {
				r.modifiedLevel(m)
			}
		}
		r.blank()
	}

	// The rule sections print in the reference tool's order: each AV
	// family immediately followed by its extended permission counterpart.
	ruleFamilies := []ruleSection{
		{opt: "allow", on: allow, av: &diff.Allows, title: "Allow Rules"},
		{opt: "allowxperm", on: allowxperm, xperm: &diff.Allowxperms, title: "Allowxperm Rules"},
		{opt: "auditallow", on: a.Flag("auditallow"), av: &diff.Auditallows, title: "Auditallow Rules"},
		{opt: "auditallowxperm", on: a.Flag("auditallowxperm"), xperm: &diff.Auditallowxperms,
			title: "Auditallowxperm Rules"},
		{opt: "dontaudit", on: a.Flag("dontaudit"), av: &diff.Dontaudits, title: "Dontaudit Rules"},
		{opt: "dontauditxperm", on: a.Flag("dontauditxperm"), xperm: &diff.Dontauditxperms,
			title: "Dontauditxperm Rules"},
	}
	for _, fam := range ruleFamilies {
		// A section prints when every difference is selected, when its own
		// option was given, or when -A selected the allow families.
		if !all && !fam.on {
			continue
		}
		if !fam.hasResults() && !fam.on {
			continue
		}
		r.ruleSection(fam)
	}

	teFamilies := []struct {
		opt   string
		diff  sego.TEDiff
		title string
	}{
		{"type_trans", diff.TypeTransitions, "Type_transition Rules"},
		{"type_change", diff.TypeChanges, "Type_change Rules"},
		{"type_member", diff.TypeMembers, "Type_member Rules"},
	}
	for _, fam := range teFamilies {
		if !on(a, all, fam.opt) || !(len(fam.diff.Added) > 0 || len(fam.diff.Removed) > 0 || len(fam.diff.Modified) > 0 || a.Flag(fam.opt)) {
			continue
		}
		r.titlef("%s (%d Added, %d Removed, %d Modified)",
			fam.title, len(fam.diff.Added), len(fam.diff.Removed), len(fam.diff.Modified))
		r.addedRemoved(fam.title, fam.diff.Added, fam.diff.Removed)
		if len(fam.diff.Modified) > 0 && !stats {
			r.listf("   Modified %s: %d", fam.title, len(fam.diff.Modified))
			for _, m := range fam.diff.Modified {
				r.modifiedTERule(m)
			}
		}
		r.blank()
	}

	if on(a, all, "role_allow") && (len(diff.AddedRoleAllows) > 0 || len(diff.RemovedRoleAllows) > 0 || a.Flag("role_allow")) {
		r.titlef("Role allow Rules (%d Added, %d Removed)", len(diff.AddedRoleAllows), len(diff.RemovedRoleAllows))
		r.addedRemoved("Role Allow Rules",
			diff.AddedRoleAllows, diff.RemovedRoleAllows)
		r.blank()
	}

	if on(a, all, "role_trans") && (len(diff.AddedRoleTransitions) > 0 || len(diff.RemovedRoleTransitions) > 0 || len(diff.ModifiedRoleTransitions) > 0 || a.Flag("role_trans")) {
		r.titlef("Role_transition Rules (%d Added, %d Removed, %d Modified)",
			len(diff.AddedRoleTransitions), len(diff.RemovedRoleTransitions), len(diff.ModifiedRoleTransitions))
		r.addedRemoved("Role_transition Rules",
			diff.AddedRoleTransitions, diff.RemovedRoleTransitions)
		if len(diff.ModifiedRoleTransitions) > 0 && !stats {
			r.listf("   Modified Role_transition Rules: %d", len(diff.ModifiedRoleTransitions))
			for _, m := range diff.ModifiedRoleTransitions {
				r.itemf("      * %s %s %s:%s +%s -%s;",
					m.Ruletype, m.Source, m.Target, m.Class, m.AddedDefault, m.RemovedDefault)
			}
		}
		r.blank()
	}

	if on(a, all, "range_trans") && (len(diff.AddedRangeTransitions) > 0 || len(diff.RemovedRangeTransitions) > 0 || len(diff.ModifiedRangeTransitions) > 0 || a.Flag("range_trans")) {
		r.titlef("Range_transition Rules (%d Added, %d Removed, %d Modified)",
			len(diff.AddedRangeTransitions), len(diff.RemovedRangeTransitions), len(diff.ModifiedRangeTransitions))
		r.addedRemoved("Range_transition Rules",
			diff.AddedRangeTransitions, diff.RemovedRangeTransitions)
		if len(diff.ModifiedRangeTransitions) > 0 && !stats {
			r.listf("   Modified Range_transition Rules: %d", len(diff.ModifiedRangeTransitions))
			for _, m := range diff.ModifiedRangeTransitions {
				r.itemf("      * %s %s %s:%s +[%s] -[%s];",
					m.Ruletype, m.Source, m.Target, m.Class, m.AddedDefault, m.RemovedDefault)
			}
		}
		r.blank()
	}

	constraintFamilies := []struct {
		opt            string
		added, removed []string
		title          string
		addedTitle     string
		removedTitle   string
	}{
		{"constrain", diff.AddedConstrains, diff.RemovedConstrains, "Constraints",
			"Added Constraints", "Removed Constraints"},
		{"mlsconstrain", diff.AddedMLSConstrains, diff.RemovedMLSConstrains, "MLS Constraints",
			"Added MLS Constraints", "Removed MLS Constraints"},
		{"validatetrans", diff.AddedValidatetrans, diff.RemovedValidatetrans, "Validatetrans",
			"Added Validatetrans", "Removed Validatetrans"},
		{"mlsvalidatetrans", diff.AddedMLSValidatetrans, diff.RemovedMLSValidatetrans, "MLS Validatetrans",
			"Added MLS Validatetrans", "Removed MLS Validatetrans"},
	}
	for _, fam := range constraintFamilies {
		if !on(a, all, fam.opt) || !(len(fam.added) > 0 || len(fam.removed) > 0 || a.Flag(fam.opt)) {
			continue
		}
		r.titlef("%s (%d Added, %d Removed)", fam.title, len(fam.added), len(fam.removed))
		if len(fam.added) > 0 && !stats {
			r.listf("   %s: %d", fam.addedTitle, len(fam.added))
			for _, c := range fam.added {
				r.itemf("      + %s", c)
			}
		}
		if len(fam.removed) > 0 && !stats {
			r.listf("   %s: %d", fam.removedTitle, len(fam.removed))
			for _, c := range fam.removed {
				r.itemf("      - %s", c)
			}
		}
		r.blank()
	}

	// The labeling sections print in the reference tool's order: initial
	// SIDs, ibendportcon, ibpkeycon, fs_use, genfscon, netifcon, nodecon,
	// portcon.
	labelingFamilies := []struct {
		opt      string
		added    []string
		removed  []string
		modified []sego.ModifiedContext
		title    string
	}{
		{"initialsid", diff.AddedInitialSIDs, diff.RemovedInitialSIDs, diff.ModifiedInitialSIDs, "Initial SIDs"},
		{"ibendportcon", diff.AddedIbendportcons, diff.RemovedIbendportcons, diff.ModifiedIbendportcons, "Ibendportcons"},
		{"ibpkeycon", diff.AddedIbpkeycons, diff.RemovedIbpkeycons, diff.ModifiedIbpkeycons, "Ibpkeycons"},
		{"fs_use", diff.AddedFSUses, diff.RemovedFSUses, diff.ModifiedFSUses, "Fs_use"},
		{"genfscon", diff.AddedGenfscons, diff.RemovedGenfscons, diff.ModifiedGenfscons, "Genfscons"},
	}
	for _, fam := range labelingFamilies {
		r.labelingSection(a, all, fam.opt, fam.title, fam.added, fam.removed, fam.modified)
	}

	if on(a, all, "netifcon") {
	}
	r.netifconSection(a, all, diff)

	for _, fam := range []struct {
		opt      string
		added    []string
		removed  []string
		modified []sego.ModifiedContext
		title    string
	}{
		{"nodecon", diff.AddedNodecons, diff.RemovedNodecons, diff.ModifiedNodecons, "Nodecons"},
		{"portcon", diff.AddedPortcons, diff.RemovedPortcons, diff.ModifiedPortcons, "Portcons"},
	} {
		r.labelingSection(a, all, fam.opt, fam.title, fam.added, fam.removed, fam.modified)
	}

	return nil
}

// ruleSection is one AV or extended permission rule section.
type ruleSection struct {
	opt   string
	on    bool
	av    *sego.AVRuleDiff
	xperm *sego.AVXpermDiff
	title string
}

// hasResults reports whether the section has any differences.
func (f ruleSection) hasResults() bool {
	if f.av != nil {
		return len(f.av.Added) > 0 || len(f.av.Removed) > 0 || len(f.av.Modified) > 0
	}
	return len(f.xperm.Added) > 0 || len(f.xperm.Removed) > 0 || len(f.xperm.Modified) > 0
}

// ruleSection prints one AV or extended permission rule section.
func (r *reporter) ruleSection(f ruleSection) {
	if f.av != nil {
		r.titlef("%s (%d Added, %d Removed, %d Modified)",
			f.title, len(f.av.Added), len(f.av.Removed), len(f.av.Modified))
		r.addedRemoved(f.title, f.av.Added, f.av.Removed)
		if len(f.av.Modified) > 0 && !r.stats {
			r.listf("   Modified %s: %d", f.title, len(f.av.Modified))
			for _, m := range f.av.Modified {
				r.modifiedAVRule(m)
			}
		}
		r.blank()
		return
	}
	r.titlef("%s (%d Added, %d Removed, %d Modified)",
		f.title, len(f.xperm.Added), len(f.xperm.Removed), len(f.xperm.Modified))
	r.addedRemoved(f.title, f.xperm.Added, f.xperm.Removed)
	if len(f.xperm.Modified) > 0 && !r.stats {
		r.listf("   Modified %s: %d", f.title, len(f.xperm.Modified))
		for _, m := range f.xperm.Modified {
			r.modifiedAVXperm(m)
		}
	}
	r.blank()
}

// labelingSection prints one labeling statement section.
func (r *reporter) labelingSection(a *argparse.Args, all bool, opt, title string,
	added, removed []string, modified []sego.ModifiedContext) {
	if !on(a, all, opt) ||
		!(len(added) > 0 || len(removed) > 0 || len(modified) > 0 || a.Flag(opt)) {
		return
	}
	r.titlef("%s (%d Added, %d Removed, %d Modified)", title,
		len(added), len(removed), len(modified))
	r.addedRemoved(title, added, removed)
	if len(modified) > 0 && !r.stats {
		r.listf("   Modified %s: %d", title, len(modified))
		for _, m := range modified {
			r.modifiedContext(m, title)
		}
	}
	r.blank()
}

// netifconSection prints the netifcon section, whose modified statements
// carry two contexts and need their own layout.
func (r *reporter) netifconSection(a *argparse.Args, all bool, diff *sego.PolicyDiff) {
	if !on(a, all, "netifcon") || !(len(diff.AddedNetifcons) > 0 ||
		len(diff.RemovedNetifcons) > 0 || len(diff.ModifiedNetifcons) > 0 || a.Flag("netifcon")) {
		return
	}
	r.titlef("Netifcons (%d Added, %d Removed, %d Modified)",
		len(diff.AddedNetifcons), len(diff.RemovedNetifcons), len(diff.ModifiedNetifcons))
	r.addedRemoved("Netifcons", diff.AddedNetifcons, diff.RemovedNetifcons)
	if len(diff.ModifiedNetifcons) > 0 && !r.stats {
		r.listf("   Modified Netifcons: %d", len(diff.ModifiedNetifcons))
		for _, m := range diff.ModifiedNetifcons {
			r.modifiedNetifcon(m)
		}
	}
	r.blank()
}

// verbosef prints an informational message for -v/--verbose. The reference
// tool logs these through the logging module, which writes to stderr.
func verbosef(a *argparse.Args, stderr io.Writer, format string, args ...any) {
	if a.Flag("verbose") || a.Flag("debug") {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}

// logDiffSelection logs the reference diff component's informational lines in
// its access order: one "Generating ... differences" line per selected
// component, with the AV-rule expansion lines of the permission families. The
// reference logs these lazily while it prints; this tool logs them up front,
// so with -v and merged streams the interleaving with stdout differs.
func logDiffSelection(a *argparse.Args, stderr io.Writer, left, right *sego.Policy) {
	p1, p2 := left.Path(), right.Path()
	gen := func(what string) {
		fmt.Fprintf(stderr, "Generating %s differences from %s to %s\n", what, p1, p2)
	}
	avLines := func() {
		fmt.Fprintf(stderr, "Expanding AV rules from %s.\n", p1)
		fmt.Fprintf(stderr, "Expanding AV rules from %s.\n", p2)
		fmt.Fprintln(stderr, "Removing redundant AV rules.")
		fmt.Fprintln(stderr, "Generating AV rule diff.")
	}
	all := allDifferences(a)
	selected := func(dest string) bool { return all || a.Flag(dest) }
	selectedA := func(dest string) bool { return selected(dest) || a.Flag("A") }

	if selected("polcap") {
		gen("policy cap")
	}
	if selected("common") {
		gen("common")
	}
	if selected("class") {
		gen("class")
	}
	if selected("default") {
		gen("default_*")
	}
	if selected("bool") {
		gen("Boolean")
	}
	if selected("role") {
		gen("role")
	}
	if selected("type") {
		gen("type")
	}
	if selected("typebounds") {
		gen("typebounds")
	}
	if selected("attribute") {
		gen("type attribute")
	}
	if selected("user") {
		gen("user")
	}
	if selected("category") {
		gen("category")
	}
	if selected("sensitivity") {
		gen("sensitivity")
	}
	if selected("level") {
		gen("level decl")
	}
	for _, fam := range []struct {
		opt string
		av  bool
	}{
		{"allow", true}, {"allowxperm", false}, {"neverallow", true}, {"neverallowxperm", false},
		{"auditallow", true}, {"auditallowxperm", false}, {"dontaudit", true}, {"dontauditxperm", false},
		{"type_trans", false}, {"type_change", false}, {"type_member", false},
	} {
		// The neverallow families exist only in the reference's dead CLI
		// code paths; they are accessed when every difference is selected.
		var famOn bool
		switch fam.opt {
		case "neverallow", "neverallowxperm":
			famOn = all
		case "allow", "allowxperm":
			famOn = selectedA(fam.opt)
		default:
			famOn = selected(fam.opt)
		}
		if !famOn {
			continue
		}
		name := fam.opt
		if name == "type_trans" {
			name = "type_transition"
		}
		gen(name)
		if fam.av {
			avLines()
		}
	}
	if selected("role_allow") {
		gen("role allow")
	}
	if selected("role_trans") {
		gen("role_transition")
	}
	if selected("range_trans") {
		gen("range_transition")
	}
	for _, fam := range []struct{ opt, name string }{
		{"constrain", "constraint"}, {"mlsconstrain", "MLS constraint"},
		{"validatetrans", "validatetrans"}, {"mlsvalidatetrans", "mlsvalidatetrans"},
		{"initialsid", "initial SID"}, {"ibendportcon", "ibendportcon"},
		{"ibpkeycon", "ibpkeycon"}, {"fs_use", "fs_use_*"},
		{"genfscon", "genfscon"}, {"netifcon", "netifcon"},
		{"nodecon", "nodecon"}, {"portcon", "portcon"},
	} {
		if selected(fam.opt) {
			gen(fam.name)
		}
	}
}

// on reports whether a section was selected: explicitly, or because every
// difference was selected.
func on(a *argparse.Args, all bool, dest string) bool {
	return all || a.Flag(dest)
}

// allDifferences reports whether no difference was selected, in which case
// every section is printed.
func allDifferences(a *argparse.Args) bool {
	dests := []string{"A", "class", "common", "type", "attribute", "role", "user", "bool",
		"sensitivity", "category", "level", "allow", "auditallow", "dontaudit",
		"type_trans", "type_change", "type_member", "role_allow", "role_trans",
		"range_trans", "initialsid", "genfscon", "netifcon", "nodecon", "portcon",
		"fs_use", "polcap", "property", "default", "constrain", "mlsconstrain",
		"validatetrans", "mlsvalidatetrans", "typebounds", "allowxperm",
		"auditallowxperm", "dontauditxperm", "ibendportcon", "ibpkeycon"}
	return !slices.ContainsFunc(dests, a.Flag)
}

// addedRemovedFunc prints the added and removed blocks, rendering each item
// with render.
func addedRemovedFunc[T any](r *reporter, addedTitle, removedTitle string, added, removed []T, render func(T) string) {
	if len(added) > 0 && !r.stats {
		r.listf(addedTitle+": %d", len(added))
		for _, item := range added {
			r.itemf("      + %s", render(item))
		}
	}
	if len(removed) > 0 && !r.stats {
		r.listf(removedTitle+": %d", len(removed))
		for _, item := range removed {
			r.itemf("      - %s", render(item))
		}
	}
}

// reporter writes the difference sections.
type reporter struct {
	out   io.Writer
	stats bool
}

func (r *reporter) titlef(format string, args ...any) {
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *reporter) listf(format string, args ...any) {
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *reporter) itemf(format string, args ...any) {
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *reporter) blank() {
	fmt.Fprintln(r.out)
}

// any3 reports whether any result exists; the reference also prints the
// section header when the option was selected explicitly.
func (r *reporter) any3(a *argparse.Args, dest string, added, removed []string, modified bool) bool {
	return len(added) > 0 || len(removed) > 0 || modified || a.Flag(dest)
}

// addedRemoved prints the added and removed blocks of one section. The titles
// already carry their indentation.
func (r *reporter) addedRemoved(title string, added, removed []string) {
	addedRemovedFunc(r, "   Added "+title, "   Removed "+title, added, removed,
		func(s string) string { return s })
}

// modifiedPermSet prints a modified class or common: the change list and the
// added and removed permissions.
func (r *reporter) modifiedPermSet(name string, added, removed []string, kind string) {
	var change []string
	if len(added) > 0 {
		change = append(change, fmt.Sprintf("%d Added %s", len(added), kind))
	}
	if len(removed) > 0 {
		change = append(change, fmt.Sprintf("%d Removed %s", len(removed), kind))
	}
	r.itemf("      * %s (%s)", name, strings.Join(change, ", "))
	for _, p := range added {
		r.itemf("          + %s", p)
	}
	for _, p := range removed {
		r.itemf("          - %s", p)
	}
}

// modifiedNameSet prints a modified role or type attribute.
func (r *reporter) modifiedNameSet(name string, added, removed []string, kind string) {
	var change []string
	if len(added) > 0 {
		change = append(change, fmt.Sprintf("%d Added %s", len(added), kind))
	}
	if len(removed) > 0 {
		change = append(change, fmt.Sprintf("%d Removed %s", len(removed), kind))
	}
	r.itemf("      * %s (%s)", name, strings.Join(change, ", "))
	for _, t := range added {
		r.itemf("          + %s", t)
	}
	for _, t := range removed {
		r.itemf("          - %s", t)
	}
}

// modifiedType prints a modified type. The change list joins with a bare
// comma, a quirk of the reference tool.
func (r *reporter) modifiedType(m sego.ModifiedType) {
	var change []string
	if len(m.AddedAttributes) > 0 {
		change = append(change, fmt.Sprintf("%d Added attributes", len(m.AddedAttributes)))
	}
	if len(m.RemovedAttributes) > 0 {
		change = append(change, fmt.Sprintf("%d Removed attributes", len(m.RemovedAttributes)))
	}
	if len(m.AddedAliases) > 0 {
		change = append(change, fmt.Sprintf("%d Added aliases", len(m.AddedAliases)))
	}
	if len(m.RemovedAliases) > 0 {
		change = append(change, fmt.Sprintf("%d Removed aliases", len(m.RemovedAliases)))
	}
	if m.PermissiveModified {
		if m.Permissive {
			change = append(change, "Removed permissive")
		} else {
			change = append(change, "Added permissive")
		}
	}
	r.itemf("      * %s (%s)", m.Name, strings.Join(change, ","))
	if len(m.AddedAttributes) > 0 || len(m.RemovedAttributes) > 0 {
		r.itemf("          Attributes:")
		for _, a := range m.AddedAttributes {
			r.itemf("          + %s", a)
		}
		for _, a := range m.RemovedAttributes {
			r.itemf("          - %s", a)
		}
	}
	if len(m.AddedAliases) > 0 || len(m.RemovedAliases) > 0 {
		r.itemf("          Aliases:")
		for _, a := range m.AddedAliases {
			r.itemf("          + %s", a)
		}
		for _, a := range m.RemovedAliases {
			r.itemf("          - %s", a)
		}
	}
}

// modifiedUser prints a modified user.
func (r *reporter) modifiedUser(m sego.ModifiedUser) {
	var change []string
	if len(m.AddedRoles) > 0 {
		change = append(change, fmt.Sprintf("%d Added roles", len(m.AddedRoles)))
	}
	if len(m.RemovedRoles) > 0 {
		change = append(change, fmt.Sprintf("%d Removed roles", len(m.RemovedRoles)))
	}
	if m.LevelChanged {
		change = append(change, "Modified default level")
	}
	if m.RangeChanged {
		change = append(change, "Modified range")
	}
	r.itemf("      * %s (%s)", m.Name, strings.Join(change, ", "))
	if len(m.AddedRoles) > 0 || len(m.RemovedRoles) > 0 {
		r.itemf("          Roles:")
		for _, role := range m.AddedRoles {
			r.itemf("          + %s", role)
		}
		for _, role := range m.RemovedRoles {
			r.itemf("          - %s", role)
		}
	}
	if m.LevelChanged {
		r.itemf("          Default level:")
		r.itemf("          + %s", m.AddedLevel)
		r.itemf("          - %s", m.RemovedLevel)
	}
	if m.RangeChanged {
		r.itemf("          Range:")
		r.itemf("          + %s", m.AddedRange)
		r.itemf("          - %s", m.RemovedRange)
	}
}

// modifiedAliases prints a modified category or sensitivity.
func (r *reporter) modifiedAliases(name string, added, removed []string) {
	var change []string
	if len(added) > 0 {
		change = append(change, fmt.Sprintf("%d Added Aliases", len(added)))
	}
	if len(removed) > 0 {
		change = append(change, fmt.Sprintf("%d Removed Aliases", len(removed)))
	}
	r.itemf("      * %s (%s)", name, strings.Join(change, ", "))
	r.itemf("          Aliases:")
	for _, a := range added {
		r.itemf("          + %s", a)
	}
	for _, a := range removed {
		r.itemf("          - %s", a)
	}
}

// modifiedLevel prints a modified level declaration.
func (r *reporter) modifiedLevel(m sego.ModifiedLevelDecl) {
	var change []string
	if len(m.AddedCategories) > 0 {
		change = append(change, fmt.Sprintf("%d Added Categories", len(m.AddedCategories)))
	}
	if len(m.RemovedCategories) > 0 {
		change = append(change, fmt.Sprintf("%d Removed Categories", len(m.RemovedCategories)))
	}
	r.itemf("      * level %s (%s)", m.Sensitivity, strings.Join(change, ", "))
	for _, cat := range m.AddedCategories {
		r.itemf("          + %s", cat)
	}
	for _, cat := range m.RemovedCategories {
		r.itemf("          - %s", cat)
	}
}

// modifiedDefault prints a modified default statement.
func (r *reporter) modifiedDefault(m sego.ModifiedDefault) {
	var line strings.Builder
	if m.HasRange {
		fmt.Fprintf(&line, "      * default_range %s +%s -%s +%s -%s;", m.Class,
			m.AddedDefault, m.RemovedDefault, m.AddedDefaultRange, m.RemovedDefaultRange)
	} else {
		fmt.Fprintf(&line, "      * %s %s +%s -%s;", m.Kind, m.Class,
			m.AddedDefault, m.RemovedDefault)
	}
	r.itemf("%s", line.String())
}

// modifiedAVRule prints a modified AV rule: the common, added and removed
// permissions inline.
func (r *reporter) modifiedAVRule(m sego.ModifiedAVRule) {
	permStr := strings.Join(permChangeList(m.MatchedPerms, m.AddedPerms, m.RemovedPerms), " ")
	conditional := ""
	if m.Conditional != "" {
		conditional = " [ " + m.Conditional + " ]"
	}
	r.itemf("      * %s %s %s:%s { %s };%s",
		m.Ruletype, m.Source, m.Target, m.Class, permStr, conditional)
}

// permChangeList renders the permission change list: the common permissions,
// then the added with a + prefix, then the removed with a - prefix.
func permChangeList(matched, added, removed []string) []string {
	out := make([]string, 0, len(matched)+len(added)+len(removed))
	out = append(out, matched...)
	for _, p := range added {
		out = append(out, "+"+p)
	}
	for _, p := range removed {
		out = append(out, "-"+p)
	}
	return out
}

// modifiedAVXperm prints a modified extended permission rule.
func (r *reporter) modifiedAVXperm(m sego.ModifiedAVXperm) {
	var perms []string
	if m.MatchedPerms != nil && m.MatchedPerms.Len() > 0 {
		perms = append(perms, strings.Fields(m.MatchedPerms.String())...)
	}
	permTokens(m.AddedPerms, "+", &perms)
	permTokens(m.RemovedPerms, "-", &perms)
	conditional := ""
	_ = conditional
	r.itemf("      * %s %s %s:%s %s { %s };",
		m.Ruletype, m.Source, m.Target, m.Class, m.XpermType, strings.Join(perms, " "))
}

// permTokens appends the set's tokens with the prefix, bracketing tokens that
// contain a range dash.
func permTokens(set *sego.XPermSet, prefix string, out *[]string) {
	if set == nil {
		return
	}
	for token := range strings.FieldsSeq(set.String()) {
		if strings.Contains(token, "-") {
			*out = append(*out, prefix+"["+token+"]")
		} else {
			*out = append(*out, prefix+token)
		}
	}
}

// modifiedTERule prints a modified type_* rule.
func (r *reporter) modifiedTERule(m sego.ModifiedTERule) {
	filename := ""
	if m.Filename != "" {
		filename = " " + m.Filename
	}
	conditional := ""
	if m.Conditional != "" {
		conditional = " [ " + m.Conditional + " ]"
	}
	r.itemf("      * %s %s %s:%s +%s -%s%s;%s",
		m.Ruletype, m.Source, m.Target, m.Class,
		m.AddedDefault, m.RemovedDefault, filename, conditional)
}

// modifiedContext prints a modified labeling statement, except netifcon,
// whose two contexts get their own rendering.
func (r *reporter) modifiedContext(m sego.ModifiedContext, title string) {
	switch title {
	case "Ibendportcons":
		// The reference omits the trailing semicolon here.
		r.itemf("      * %s +[%s] -[%s]", m.Statement, m.AddedContext, m.RemovedContext)
	case "Ibpkeycons":
		r.itemf("      * %s +[%s] -[%s]", m.Statement, m.AddedContext, m.RemovedContext)
	case "Initial SIDs":
		r.itemf("      * %s +[%s] -[%s];", m.Statement, m.AddedContext, m.RemovedContext)
	case "Fs_use":
		r.itemf("      * %s +[%s] -[%s];", m.Statement, m.AddedContext, m.RemovedContext)
	case "Genfscons":
		r.itemf("      * %s +[%s] -[%s];", m.Statement, m.AddedContext, m.RemovedContext)
	case "Nodecons":
		r.itemf("      * %s +[%s] -[%s];", m.Statement, m.AddedContext, m.RemovedContext)
	case "Portcons":
		r.itemf("      * %s +[%s] -[%s];", m.Statement, m.AddedContext, m.RemovedContext)
	}
}

// modifiedNetifcon prints a modified netifcon with its two contexts.
func (r *reporter) modifiedNetifcon(m sego.ModifiedNetifcon) {
	var change []string
	if m.ContextChanged {
		change = append(change, "Modified Context")
	}
	if m.PacketChanged {
		change = append(change, "Modified Packet Context")
	}
	r.itemf("      * netif %s (%s)", m.Device, strings.Join(change, ", "))
	if m.ContextChanged {
		r.itemf("          Context:")
		r.itemf("             + %s", m.AddedContext)
		r.itemf("             - %s", m.RemovedContext)
	}
	if m.PacketChanged {
		r.itemf("          Packet Context:")
		r.itemf("             + %s", m.AddedPacket)
		r.itemf("             - %s", m.RemovedPacket)
	}
}

// pythonBool renders a bool the way the reference's f-strings do.
func pythonBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// defaultStatement renders a default statement for the added and removed
// lists.
func defaultStatement(d sego.Default) string { return d.Statement() }

// boundsStatement renders a typebounds statement for the added and removed
// lists.
func boundsStatement(b sego.Bounds) string { return b.Statement() }
