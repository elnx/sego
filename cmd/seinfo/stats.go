package main

// The statistics block of seinfo, reproducing the reference tool's counters
// and alignment.

import (
	"fmt"
	"io"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/policy"
)

// writeStats prints the statistics block: the policy header lines and the
// two-column counter lines.
func writeStats(out io.Writer, p *sego.Policy) {
	mls := "disabled"
	if p.MLS() {
		mls = "enabled"
	}
	target := "selinux"
	if p.DB().Target == policy.TargetXen {
		target = "xen"
	}
	fmt.Fprintf(out, "Statistics for policy file: %s\n", p.Path())
	fmt.Fprintf(out, "Policy Version:             %d (MLS %s)\n", p.Version(), mls)
	fmt.Fprintf(out, "Target Policy:              %s\n", target)
	fmt.Fprintf(out, "Handle unknown classes:     %s\n", handleUnknown(p))

	c := newCounters(p)

	fmt.Fprintf(out, "  Classes:         %7d    Permissions:     %7d\n", c.classCount, c.permCount)
	fmt.Fprintf(out, "  Sensitivities:   %7d    Categories:      %7d\n", c.levelCount, c.catCount)
	fmt.Fprintf(out, "  Types:           %7d    Attributes:      %7d\n", c.typeCount, c.attrCount)
	fmt.Fprintf(out, "  Users:           %7d    Roles:           %7d\n", c.userCount, c.roleCount)
	fmt.Fprintf(out, "  Booleans:        %7d    Cond. Expr.:     %7d\n", c.boolCount, c.condCount)
	fmt.Fprintf(out, "  Allow:           %7d    Neverallow:      %7d\n", c.allowCount, c.neverallowCount)
	fmt.Fprintf(out, "  Auditallow:      %7d    Dontaudit:       %7d\n", c.auditallowCount, c.dontauditCount)
	fmt.Fprintf(out, "  Type_trans:      %7d    Type_change:     %7d\n", c.typeTransCount, c.typeChangeCount)
	fmt.Fprintf(out, "  Type_member:     %7d    Range_trans:     %7d\n", c.typeMemberCount, c.rangeTransCount)
	fmt.Fprintf(out, "  Role allow:      %7d    Role_trans:      %7d\n", c.roleAllowCount, c.roleTransCount)
	fmt.Fprintf(out, "  Constraints:     %7d    Validatetrans:   %7d\n", c.constraintCount, c.validatetransCount)
	fmt.Fprintf(out, "  MLS Constrain:   %7d    MLS Val. Tran:   %7d\n", c.mlsConstrainCount, c.mlsValidatetransCount)
	fmt.Fprintf(out, "  Permissives:     %7d    Polcap:          %7d\n", c.permissiveCount, c.polcapCount)
	fmt.Fprintf(out, "  Defaults:        %7d    Typebounds:      %7d\n", c.defaultCount, c.typeboundsCount)

	if p.DB().Target == policy.TargetXen {
		fmt.Fprintf(out, "  Initial SIDs:    %7d    Devicetreecon:   %7d\n", c.initialSidCount, c.devicetreeconCount)
		fmt.Fprintf(out, "  Iomemcon:        %7d    Ioportcon:       %7d\n", c.iomemconCount, c.ioportconCount)
		fmt.Fprintf(out, "  Pcidevicecon:    %7d    Pirqcon:         %7d\n", c.pcideviceconCount, c.pirqconCount)
		return
	}
	fmt.Fprintf(out, "  Allowxperm:      %7d    Neverallowxperm: %7d\n", c.allowxpermCount, c.neverallowxpermCount)
	fmt.Fprintf(out, "  Auditallowxperm: %7d    Dontauditxperm:  %7d\n", c.auditallowxpermCount, c.dontauditxpermCount)
	fmt.Fprintf(out, "  Ibendportcon:    %7d    Ibpkeycon:       %7d\n", c.ibendportconCount, c.ibpkeyconCount)
	fmt.Fprintf(out, "  Initial SIDs:    %7d    Fs_use:          %7d\n", c.initialSidCount, c.fsuseCount)
	fmt.Fprintf(out, "  Genfscon:        %7d    Portcon:         %7d\n", c.genfsconCount, c.portconCount)
	fmt.Fprintf(out, "  Netifcon:        %7d    Nodecon:         %7d\n", c.netifconCount, c.nodeconCount)
}

// handleUnknown names the unknown-permission handling setting.
func handleUnknown(p *sego.Policy) string {
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

// counters holds every statistics value.
type counters struct {
	classCount, permCount       int
	levelCount, catCount        int
	typeCount, attrCount        int
	userCount, roleCount        int
	boolCount, condCount        int
	allowCount, neverallowCount int
	auditallowCount             int
	dontauditCount              int
	typeTransCount              int
	typeChangeCount             int
	typeMemberCount             int
	rangeTransCount             int
	roleAllowCount              int
	roleTransCount              int
	constraintCount             int
	validatetransCount          int
	mlsConstrainCount           int
	mlsValidatetransCount       int
	permissiveCount             int
	polcapCount                 int
	defaultCount                int
	typeboundsCount             int
	allowxpermCount             int
	neverallowxpermCount        int
	auditallowxpermCount        int
	dontauditxpermCount         int
	ibendportconCount           int
	ibpkeyconCount              int
	initialSidCount             int
	fsuseCount                  int
	genfsconCount               int
	portconCount                int
	netifconCount               int
	nodeconCount                int
	devicetreeconCount          int
	iomemconCount               int
	ioportconCount              int
	pcideviceconCount           int
	pirqconCount                int
}

// newCounters computes the statistics of a policy. The TE rule counts cover
// the unconditional rules, the filename transitions (which the reference adds
// to the type_transition count) and the conditional true and false blocks.
func newCounters(p *sego.Policy) *counters {
	c := &counters{
		classCount: len(p.Classes()),
		attrCount:  len(p.TypeAttributes()),
		userCount:  len(p.Users()),
		roleCount:  len(p.Roles()),
		boolCount:  len(p.Booleans()),
		levelCount: len(p.Sensitivities()),
		catCount:   len(p.Categories()),
	}
	for _, t := range p.Types() {
		if !t.IsAttribute {
			c.typeCount++
		}
	}
	for _, common := range p.Commons() {
		c.permCount += len(common.Perms())
	}
	// Only the class's own permissions count; the inherited ones are already
	// in the common.
	for _, class := range p.DB().Classes {
		if class != nil {
			c.permCount += len(class.Perms)
		}
	}
	c.condCount = len(p.DB().Conditions)

	for _, rule := range p.TERules() {
		switch r := rule.(type) {
		case *sego.AVRule:
			switch r.Kind() {
			case sego.Allow:
				c.allowCount++
			case sego.AuditAllow:
				c.auditallowCount++
			case sego.DontAudit:
				c.dontauditCount++
			case sego.NeverAllow:
				c.neverallowCount++
			}
		case *sego.AVRuleXperm:
			switch r.Kind() {
			case sego.AllowXPerm:
				c.allowxpermCount++
			case sego.AuditAllowXPerm:
				c.auditallowxpermCount++
			case sego.DontAuditXPerm:
				c.dontauditxpermCount++
			case sego.NeverAllowXPerm:
				c.neverallowxpermCount++
			}
		case *sego.TERule:
			switch r.Kind() {
			case sego.TypeTransition:
				c.typeTransCount++
			case sego.TypeChange:
				c.typeChangeCount++
			case sego.TypeMember:
				c.typeMemberCount++
			}
		case *sego.FileNameTERule:
			c.typeTransCount++
		}
	}

	c.rangeTransCount = len(p.MLSRules())
	for _, rule := range p.RBACRules() {
		switch rule.(type) {
		case *sego.RoleAllowRule:
			c.roleAllowCount++
		case *sego.RoleTransitionRule:
			c.roleTransCount++
		}
	}

	for _, con := range p.Constraints() {
		if con.Kind == "mlsconstrain" {
			c.mlsConstrainCount++
		} else {
			c.constraintCount++
		}
	}
	for _, con := range p.Validatetrans() {
		if con.Kind == "mlsvalidatetrans" {
			c.mlsValidatetransCount++
		} else {
			c.validatetransCount++
		}
	}

	c.permissiveCount = len(p.PermissiveTypes())
	c.polcapCount = len(p.PolicyCaps())
	c.defaultCount = len(p.Defaults())
	c.typeboundsCount = len(p.TypeBounds())
	c.ibendportconCount = len(p.Ibendportcons())
	c.ibpkeyconCount = len(p.Ibpkeycons())
	if p.DB().Target == policy.TargetXen {
		c.initialSidCount = len(p.XenInitialSIDs())
	} else {
		c.initialSidCount = len(p.InitialSIDs())
	}
	c.fsuseCount = len(p.FSUses())
	c.genfsconCount = len(p.Genfscons())
	c.portconCount = len(p.Portcons())
	c.netifconCount = len(p.Netifcons())
	c.nodeconCount = len(p.Nodecons())
	c.devicetreeconCount = len(p.XenDeviceTreecons())
	c.iomemconCount = len(p.XenIOMemcons())
	c.ioportconCount = len(p.XenIOPortcons())
	c.pcideviceconCount = len(p.XenPCIDevicecons())
	c.pirqconCount = len(p.XenPirqcons())
	return c
}
