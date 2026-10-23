// Package policy reads SELinux binary (kernel) policy files.
//
// The reader is a pure-Go reimplementation of the kernel-policy portion of
// libsepol's policydb_read()/write.c format. Supported policy versions are
// 30 through 35 (the range accepted by libsepol 3.11), for both the selinux
// and xen target platforms.
package policy

import (
	"fmt"
	"os"
	"slices"
)

// Policy versions understood by this package.
const (
	VersionMin        = 30 // xperms ioctl, xen devicetree
	VersionInfiniband = 31
	VersionGlblub     = 32
	VersionCompFtrans = 33 // compressed filename transitions
	VersionCondXperms = 34 // extended permissions in conditional rules
	VersionNeverAudit = 35 // neveraudit types
	VersionMax        = VersionNeverAudit
)

// Policy file magic numbers.
const (
	magicKern = 0xf97cff8c
	magicMod  = 0xf27f28d8
)

// Target platform strings, as stored in the policy file header.
const (
	targetSELinux = "SE Linux"
	targetXen     = "Xen"
)

// Symbol table indices, matching libsepol's SYM_* values.
const (
	SymCommons = iota
	SymClasses
	SymRoles
	SymTypes
	SymUsers
	SymBools
	SymLevels
	SymCats
	SymNum
)

// Number of ocontext sections per target platform and version.
const (
	oconSelLinuxBase = 7 // OCON_NODE6 + 1
	oconSelLinuxIB   = 9 // OCON_IBENDPORT + 1
	oconXen          = 6 // OCON_XEN_DEVICETREE + 1
)

// Ocontext section indices (selinux target).
const (
	OConISid = iota
	OConFS
	OConPort
	OConNetif
	OConNode
	OConFSUse
	OConNode6
	OConIBPkey
	OConIBEndPort
)

// PolicyDB config flags.
const (
	ConfigMLS         = 0x1
	ConfigUnknownMask = 0x0300
)

// AVRule kind bits (avtab key "specified" field).
const (
	AVTabAllow           = 0x0001
	AVTabAuditAllow      = 0x0002
	AVTabAuditDeny       = 0x0004
	AVTabNeverAllow      = 0x0080
	AVTabTransition      = 0x0010
	AVTabMember          = 0x0020
	AVTabChange          = 0x0040
	AVTabXPermsAllowed   = 0x0100
	AVTabXPermsAudit     = 0x0200
	AVTabXPermsDontAudit = 0x0400
	AVTabXPermsNever     = 0x0800
	AVTabEnabled         = 0x8000

	AVTabAV     = AVTabAllow | AVTabAuditAllow | AVTabAuditDeny | AVTabNeverAllow
	AVTabType   = AVTabTransition | AVTabMember | AVTabChange
	AVTabXPerms = AVTabXPermsAllowed | AVTabXPermsAudit | AVTabXPermsDontAudit | AVTabXPermsNever
)

// Extended permission specifiers (xperms subtype).
const (
	XPermsIoctlFunction = 0x01
	XPermsIoctlDriver   = 0x02
	XPermsNLMsg         = 0x03
)

// Type datum properties.
const (
	TypePropertyPrimary    = 0x01
	TypePropertyAttribute  = 0x02
	TypePropertyAlias      = 0x04
	TypePropertyPermissive = 0x08
	TypePropertyNeverAudit = 0x10
)

// Constraint expression node types.
const (
	CExprNot   = 1
	CExprAnd   = 2
	CExprOr    = 3
	CExprAttr  = 4
	CExprNames = 5
)

// Constraint expression attributes.
const (
	CExprUser    = 1
	CExprRole    = 2
	CExprType    = 4
	CExprTarget  = 8
	CExprXTarget = 16
	CExprL1L2    = 32
	CExprL1H2    = 64
	CExprH1L2    = 128
	CExprH1H2    = 256
	CExprL1H1    = 512
	CExprL2H2    = 1024
)

// Constraint expression operators.
const (
	CExprEQ     = 1
	CExprNEQ    = 2
	CExprDom    = 3
	CExprDomBy  = 4
	CExprIncomp = 5
)

// Policy is a parsed kernel policy.
//
// Slice fields holding symbols are indexed by symbol value minus one, so the
// datum for value N is found at index N-1. Entries may be nil where the binary
// policy omits a value (e.g. role attributes, which are not written to kernel
// policies).
type Policy struct {
	Version       uint32
	Target        string
	MLS           bool
	HandleUnknown uint32

	PolicyCaps []uint32
	Permissive []uint32 // type values marked permissive
	NeverAudit []uint32 // type values marked neveraudit (v35+)

	Commons []*Common
	Classes []*Class
	Roles   []*Role
	Types   []*Type
	Users   []*User
	Bools   []*Bool
	Levels  []*Level
	Cats    []*Cat

	AVTab         []AVTabEntry
	Conditions    []*Condition
	RoleTrans     []RoleTrans
	RoleAllows    []RoleAllow
	FilenameTrans []FilenameTrans
	RangeTrans    []RangeTrans

	OContexts OContexts
	GenFS     []GenFS

	// TypeAttrMap[i] holds the attributes of the type with value i+1,
	// including the type itself; this is the bitmap stored in the policy
	// file. AttrTypeMap[i] is its inverse: the member types of the type
	// with value i+1 when that type is an attribute, and the type itself
	// otherwise.
	TypeAttrMap [][]uint32
	AttrTypeMap [][]uint32
}

// Common is a set of shared permissions (a "common" class prefix).
type Common struct {
	Name     string
	Value    uint32
	NumPerms uint32
	Perms    []Perm
}

// Class is an object class.
type Class struct {
	Name     string
	Value    uint32
	Common   string
	Perms    []Perm
	NumPerms uint32

	Constraints   []Constraint
	Validatetrans []Constraint

	DefaultUser  uint32
	DefaultRole  uint32
	DefaultRange uint32
	DefaultType  uint32
}

// Perm is a permission within a class or common.
type Perm struct {
	Name  string
	Value uint32
}

// Constraint is a constraint or validatetrans expression list.
type Constraint struct {
	Permissions uint32
	Exprs       []CExpr
}

// CExpr is one node of a constraint expression.
type CExpr struct {
	ExprType uint32
	Attr     uint32
	Op       uint32

	// Names, Types and NegTypes are only set for CExprNames nodes: the
	// bitmap of named types and the type set they are drawn from.
	Names    []uint32
	Types    []uint32
	NegTypes []uint32
	Flags    uint32
}

// Role is a role datum. Attributes are not present in kernel policies.
type Role struct {
	Name      string
	Value     uint32
	Bounds    uint32
	Dominates []uint32
	Types     []uint32
}

// Type is a type or type attribute.
type Type struct {
	Name        string
	Value       uint32
	IsAttribute bool

	// Primary is set on the record that defines the type; kernel policies
	// store one record per name, so aliases appear as records without it.
	Primary bool

	// Aliases holds the other names the type is known by.
	Aliases []string

	Bounds uint32
}

// User is a user datum.
type User struct {
	Name         string
	Value        uint32
	Bounds       uint32
	Roles        []uint32
	Range        Range
	DefaultLevel LevelValue
}

// Bool is a conditional boolean.
type Bool struct {
	Name  string
	Value uint32
	State bool
}

// Level is an MLS sensitivity level.
type Level struct {
	Name    string
	Value   uint32
	IsAlias bool
	Sens    uint32
	Cats    []uint32
}

// Cat is an MLS category.
type Cat struct {
	Name    string
	Value   uint32
	IsAlias bool
}

// Range is an MLS range (low and high level).
type Range struct {
	Low  LevelValue
	High LevelValue
}

// LevelValue is a sensitivity plus a set of categories.
type LevelValue struct {
	Sens uint32
	Cats []uint32
}

// AVTabEntry is one entry of the type enforcement avtab.
type AVTabEntry struct {
	Source    uint32 // type or attribute value
	Target    uint32 // type or attribute value
	Class     uint32
	Specified uint32

	Data   uint32         // permission vector, for non-xperms entries
	XPerms *ExtendedPerms // extended permissions, for xperms entries
}

// ExtendedPerms is the payload of an xperms avtab entry.
type ExtendedPerms struct {
	Specified uint32
	Driver    uint8
	Perms     [8]uint32
}

// Condition is a conditional rule block.
type Condition struct {
	CurState   uint32
	Exprs      []CondExpr
	TrueRules  []AVTabEntry
	FalseRules []AVTabEntry
}

// CondExpr is a node of a conditional expression in postfix order.
type CondExpr struct {
	ExprType uint32
	Boolean  uint32
}

// Conditional expression types and operators.
const (
	CondBool = 0x01
	CondNot  = 0x02
	CondOr   = 0x03
	CondAnd  = 0x04
	CondXor  = 0x05
	CondEq   = 0x06
	CondNeq  = 0x07
)

// RoleTrans is a role_transition rule.
type RoleTrans struct {
	Role    uint32
	Type    uint32
	Class   uint32
	NewRole uint32
}

// RoleAllow is a role allow rule.
type RoleAllow struct {
	Role    uint32
	NewRole uint32
}

// FilenameTrans is a filename based type transition.
type FilenameTrans struct {
	Name    string
	Target  uint32
	Class   uint32
	Sources []uint32
	Default uint32
}

// RangeTrans is a range_transition rule.
type RangeTrans struct {
	Source uint32
	Target uint32
	Class  uint32
	Range  Range
}

// GenFS is a genfscon section for one filesystem type.
type GenFS struct {
	FSType   string
	Contexts []GenFSContext
}

// GenFSContext is one genfscon entry.
type GenFSContext struct {
	Path    string
	Class   uint32
	Context Context
}

// Context is a security context.
type Context struct {
	User  uint32
	Role  uint32
	Type  uint32
	Range Range
}

// OContexts holds the object contexts (initial SIDs, ports, nodes, ...).
type OContexts struct {
	ISids      []ISidContext
	FS         []NameContext
	Ports      []PortContext
	Netifs     []NameContext
	Nodes      []NodeContext
	FSUse      []FSUseContext
	Nodes6     []Node6Context
	IBPkeys    []IBPkeyContext
	IBEndPorts []IBEndPortContext

	// Xen holds the contexts of a xen target policy; it is empty for the
	// selinux target.
	Xen XenOContexts
}

// ISidContext is an initial SID context.
type ISidContext struct {
	SID     uint32
	Context Context
}

// NameContext is an ocontext keyed by a device/filesystem name.
type NameContext struct {
	Name     string
	Context  Context
	Context2 Context
}

// PortContext is a port range context.
type PortContext struct {
	Protocol uint32
	LowPort  uint16
	HighPort uint16
	Context  Context
}

// NodeContext is an IPv4 node context.
type NodeContext struct {
	Addr    [4]byte
	Mask    [4]byte
	Context Context
}

// Node6Context is an IPv6 node context.
type Node6Context struct {
	Addr    [16]byte
	Mask    [16]byte
	Context Context
}

// FSUseContext is an fs_use_xattr/fs_use_task/fs_use_trans context.
type FSUseContext struct {
	Behavior uint32
	FSType   string
	Context  Context
}

// IBPkeyContext is an InfiniBand pkey context.
type IBPkeyContext struct {
	SubnetPrefix [8]byte
	LowPKey      uint16
	HighPKey     uint16
	Context      Context
}

// IBEndPortContext is an InfiniBand end port context.
type IBEndPortContext struct {
	DeviceName string
	Port       uint8
	Context    Context
}

// FS use behaviors.
const (
	FSUseXattr = 0x1
	FSUseTrans = 0x2
	FSUseTask  = 0x3
)

// XenOContexts holds the object contexts of a xen target policy. The xen
// sections are unrelated to the selinux ones, so they are kept separate.
type XenOContexts struct {
	ISids       []ISidContext
	Pirqs       []XenPirqContext
	IOPorts     []XenIOPortContext
	IOMems      []XenIOMemContext
	PCIDevices  []XenPCIDeviceContext
	DeviceTrees []XenDeviceTreeContext
}

// XenPirqContext is a physical IRQ context.
type XenPirqContext struct {
	IRQ     uint16
	Context Context
}

// XenIOPortContext is an I/O port range context.
type XenIOPortContext struct {
	Low     uint32
	High    uint32
	Context Context
}

// XenIOMemContext is an I/O memory range context.
type XenIOMemContext struct {
	Low     uint64
	High    uint64
	Context Context
}

// XenPCIDeviceContext is a PCI device context.
type XenPCIDeviceContext struct {
	Device  uint32
	Context Context
}

// XenDeviceTreeContext is a device tree node context.
type XenDeviceTreeContext struct {
	Path    string
	Context Context
}

// Open reads and parses the kernel policy file at path.
func Open(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// ErrNotKernelPolicy is returned when the file is a policy module rather than
// a kernel policy.
var ErrNotKernelPolicy = fmt.Errorf("policy module, not a kernel policy")

// Parse parses an in-memory kernel policy.
func Parse(data []byte) (*Policy, error) {
	r := newReader(data)
	p := &Policy{}

	magic := r.u32()
	identLen := r.u32()
	switch magic {
	case magicKern:
	case magicMod:
		return nil, ErrNotKernelPolicy
	default:
		if r.err != nil {
			return nil, r.err
		}
		return nil, fmt.Errorf("invalid policy magic %#08x (offset 0)", magic)
	}
	if identLen == 0 || identLen > 128 {
		return nil, fmt.Errorf("invalid policy target string length %d (offset 4)", identLen)
	}
	target := string(r.bytes(int(identLen)))
	p.Target = target
	if target != targetSELinux && target != targetXen {
		return nil, fmt.Errorf("unknown policy target %q", target)
	}

	p.Version = r.u32()
	config := r.u32()
	symNum := r.u32()
	oconNum := r.u32()
	if err := r.err; err != nil {
		return nil, err
	}
	if p.Version < VersionMin || p.Version > VersionMax {
		return nil, fmt.Errorf("unsupported policy version %d (supported: %d-%d)",
			p.Version, VersionMin, VersionMax)
	}
	p.MLS = config&ConfigMLS != 0
	p.HandleUnknown = config & ConfigUnknownMask

	wantSym, wantOcon := symCounts(p.Version, p.Target)
	if int(symNum) != wantSym {
		return nil, fmt.Errorf("policy table size %d does not match expected %d for version %d",
			symNum, wantSym, p.Version)
	}
	if int(oconNum) != wantOcon {
		return nil, fmt.Errorf("policy ocontext size %d does not match expected %d for version %d",
			oconNum, wantOcon, p.Version)
	}

	p.PolicyCaps = r.bitmap()
	p.Permissive = r.bitmap()
	if p.Version >= VersionNeverAudit && p.Target == targetSELinux {
		p.NeverAudit = r.bitmap()
	}
	if err := r.err; err != nil {
		return nil, err
	}

	// Symbol tables. Each entry is a (nprim, nel) pair followed by nel records.
	for i := range wantSym {
		nprim := r.u32()
		nel := r.u32()
		if err := r.err; err != nil {
			return nil, err
		}
		if nprim > maxSymbols {
			return nil, fmt.Errorf("symbol table %d has %d primary symbols", i, nprim)
		}
		for j := range nel {
			if err := p.readSymbol(r, i); err != nil {
				return nil, fmt.Errorf("symbol table %d entry %d: %w", i, j, err)
			}
		}
	}

	p.AVTab = readAVTab(r, p.Version)
	p.Conditions = readConditions(r, p.Version)
	p.RoleTrans = readRoleTrans(r)
	p.RoleAllows = readRoleAllows(r)
	p.FilenameTrans = readFilenameTrans(r, p.Version, p.Target)
	if p.Target == targetXen {
		p.OContexts.Xen = readXenOContexts(r, int(oconNum))
	} else {
		p.OContexts = readOContexts(r, int(oconNum))
	}
	p.GenFS = readGenFS(r)
	p.RangeTrans = readRangeTrans(r)
	p.TypeAttrMap = readTypeAttrMap(r, len(p.Types))
	if err := r.err; err != nil {
		return nil, err
	}
	if r.off != len(r.data) {
		return nil, fmt.Errorf("trailing data after policy: %d of %d bytes consumed",
			r.off, len(r.data))
	}
	p.buildAttrTypeMap()
	return p, nil
}

func symCounts(version uint32, target string) (int, int) {
	if target == targetXen {
		return SymNum, oconXen
	}
	if version >= VersionInfiniband {
		return SymNum, oconSelLinuxIB
	}
	return SymNum, oconSelLinuxBase
}

// TypeByName returns the type or attribute with the given name. Alias names
// resolve to the type they alias.
func (p *Policy) TypeByName(name string) *Type {
	for _, t := range p.Types {
		if t == nil {
			continue
		}
		if t.Name == name || slices.Contains(t.Aliases, name) {
			return t
		}
	}
	return nil
}

// RoleByName returns the role with the given name.
func (p *Policy) RoleByName(name string) *Role {
	for _, t := range p.Roles {
		if t != nil && t.Name == name {
			return t
		}
	}
	return nil
}

// ClassByName returns the object class with the given name.
func (p *Policy) ClassByName(name string) *Class {
	for _, t := range p.Classes {
		if t != nil && t.Name == name {
			return t
		}
	}
	return nil
}

// BoolByName returns the boolean with the given name.
func (p *Policy) BoolByName(name string) *Bool {
	for _, t := range p.Bools {
		if t != nil && t.Name == name {
			return t
		}
	}
	return nil
}

// buildAttrTypeMap inverts TypeAttrMap the way libsepol's policydb_read does:
// every type contributes itself to the member list of each attribute it
// belongs to, ignoring the degenerate self reference.
func (p *Policy) buildAttrTypeMap() {
	p.AttrTypeMap = make([][]uint32, len(p.Types))
	for _, attrs := range p.TypeAttrMap {
		slices.Sort(attrs)
	}
	for i, attrs := range p.TypeAttrMap {
		value := uint32(i + 1)
		for _, attr := range attrs {
			if attr == value || attr == 0 || int(attr) > len(p.Types) {
				continue
			}
			p.AttrTypeMap[attr-1] = append(p.AttrTypeMap[attr-1], value)
		}
	}
}
