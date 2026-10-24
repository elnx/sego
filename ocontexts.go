package sego

// Object context statement rendering, matching setools' policyrep (initsid,
// fscontext, netcontext, xencontext .pxi files). Statements that the policy
// language writes without a trailing semicolon are rendered that way; only
// fs_use carries one.

import (
	"fmt"
	"net"

	"github.com/elnx/sego/policy"
)

// InitialSID is one initial SID and its context.
type InitialSID struct {
	Name   string
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (s *InitialSID) Context() string { return s.policy.Context(s.ctx) }

// Statement renders the initial SID as a policy statement.
func (s *InitialSID) Statement() string {
	return fmt.Sprintf("sid %s %s", s.Name, s.Context())
}

// InitialSIDs returns the initial SIDs, in policy order.
func (p *Policy) InitialSIDs() []*InitialSID {
	out := make([]*InitialSID, 0, len(p.db.OContexts.ISids))
	for _, s := range p.db.OContexts.ISids {
		out = append(out, &InitialSID{Name: s.Name, policy: p, ctx: s.Context})
	}
	return out
}

// FSUse is one fs_use_xattr / fs_use_trans / fs_use_task statement.
type FSUse struct {
	Behavior uint32
	FSType   string
	policy   *Policy
	ctx      policy.Context
}

// Context renders the statement's security context.
func (f *FSUse) Context() string { return f.policy.Context(f.ctx) }

// Statement renders the fs_use statement, with its trailing semicolon.
func (f *FSUse) Statement() string {
	var kind string
	switch f.Behavior {
	case policy.FSUseXattr:
		kind = "fs_use_xattr"
	case policy.FSUseTrans:
		kind = "fs_use_trans"
	case policy.FSUseTask:
		kind = "fs_use_task"
	}
	return fmt.Sprintf("%s %s %s;", kind, f.FSType, f.Context())
}

// FSUses returns the fs_use statements, in policy order.
func (p *Policy) FSUses() []*FSUse {
	out := make([]*FSUse, 0, len(p.db.OContexts.FSUse))
	for _, f := range p.db.OContexts.FSUse {
		out = append(out, &FSUse{Behavior: f.Behavior, FSType: f.FSType, policy: p, ctx: f.Context})
	}
	return out
}

// Genfscon is one genfscon statement.
type Genfscon struct {
	FSType string
	Path   string
	Class  uint32 // object class value, 0 when the policy does not set one
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (g *Genfscon) Context() string { return g.policy.Context(g.ctx) }

// FileType renders the genfscon file type: the object class mapped to the
// stat-style file type strings ("-b", "-c", ...), or "" when the class is not
// a file object class or is unset.
func (g *Genfscon) FileType() string {
	if g.Class == 0 {
		return ""
	}
	c := g.policy.classValue(g.Class)
	if c == nil {
		return ""
	}
	return genfsFileTypes[c.Name]
}

// genfsFileTypes maps object class names to genfscon file type strings.
var genfsFileTypes = map[string]string{
	"dir":       "-d",
	"file":      "--",
	"lnk_file":  "-l",
	"fifo_file": "-p",
	"sock_file": "-s",
	"blk_file":  "-b",
	"chr_file":  "-c",
}

// Statement renders the genfscon statement.
func (g *Genfscon) Statement() string {
	return fmt.Sprintf("genfscon %s %s %s %s", g.FSType, g.Path, g.FileType(), g.Context())
}

// Genfscons returns the genfscon statements, in policy order (filesystems in
// table order, entries in stored order).
func (p *Policy) Genfscons() []*Genfscon {
	var out []*Genfscon
	for _, fs := range p.db.GenFS {
		for _, c := range fs.Contexts {
			out = append(out, &Genfscon{FSType: fs.FSType, Path: c.Path, Class: c.Class,
				policy: p, ctx: c.Context})
		}
	}
	return out
}

// Portcon is one portcon statement.
type Portcon struct {
	Protocol uint32
	LowPort  uint16
	HighPort uint16
	policy   *Policy
	ctx      policy.Context
}

// Context renders the statement's security context.
func (pc *Portcon) Context() string { return pc.policy.Context(pc.ctx) }

// Statement renders the portcon statement: the ports as "N" or "low-high".
func (pc *Portcon) Statement() string {
	return fmt.Sprintf("portcon %s %s %s", portProtocol(pc.Protocol), portRange(pc.LowPort, pc.HighPort),
		pc.Context())
}

// portProtocol names the IP protocol number.
func portProtocol(proto uint32) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 33:
		return "dccp"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("%d", proto)
}

// portRange renders a port range the way the reference does.
func portRange(low, high uint16) string {
	if low == high {
		return fmt.Sprintf("%d", low)
	}
	return fmt.Sprintf("%d-%d", low, high)
}

// Portcons returns the portcon statements, in policy order.
func (p *Policy) Portcons() []*Portcon {
	out := make([]*Portcon, 0, len(p.db.OContexts.Ports))
	for _, pc := range p.db.OContexts.Ports {
		out = append(out, &Portcon{Protocol: pc.Protocol, LowPort: pc.LowPort, HighPort: pc.HighPort,
			policy: p, ctx: pc.Context})
	}
	return out
}

// Netifcon is one netifcon statement.
type Netifcon struct {
	Device string
	policy *Policy
	ctx    policy.Context
	packet policy.Context
}

// Context renders the interface's security context.
func (n *Netifcon) Context() string { return n.policy.Context(n.ctx) }

// PacketContext renders the interface's packet security context.
func (n *Netifcon) PacketContext() string { return n.policy.Context(n.packet) }

// Statement renders the netifcon statement.
func (n *Netifcon) Statement() string {
	return fmt.Sprintf("netifcon %s %s %s", n.Device, n.Context(), n.PacketContext())
}

// Netifcons returns the netifcon statements, in policy order.
func (p *Policy) Netifcons() []*Netifcon {
	out := make([]*Netifcon, 0, len(p.db.OContexts.Netifs))
	for _, n := range p.db.OContexts.Netifs {
		out = append(out, &Netifcon{Device: n.Name, policy: p, ctx: n.Context, packet: n.Context2})
	}
	return out
}

// Nodecon is one nodecon statement, IPv4 or IPv6.
type Nodecon struct {
	IPv6   bool
	Addr   [16]byte
	Mask   [16]byte
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (n *Nodecon) Context() string { return n.policy.Context(n.ctx) }

// addrStrings renders the address and netmask the way the reference does:
// dotted quads for IPv4 and compressed form for IPv6.
func (n *Nodecon) AddrStrings() (string, string) {
	if n.IPv6 {
		return net.IP(n.Addr[:]).String(), net.IP(n.Mask[:]).String()
	}
	return net.IP(n.Addr[:4]).String(), net.IP(n.Mask[:4]).String()
}

// Statement renders the nodecon statement: address and netmask as two words.
func (n *Nodecon) Statement() string {
	addr, mask := n.AddrStrings()
	return fmt.Sprintf("nodecon %s %s %s", addr, mask, n.Context())
}

// Nodecons returns the nodecon statements: IPv4 first, then IPv6, in policy
// order within each family.
func (p *Policy) Nodecons() []*Nodecon {
	out := make([]*Nodecon, 0, len(p.db.OContexts.Nodes)+len(p.db.OContexts.Nodes6))
	for _, n := range p.db.OContexts.Nodes {
		nc := &Nodecon{policy: p, ctx: n.Context}
		copy(nc.Addr[:4], n.Addr[:])
		copy(nc.Mask[:4], n.Mask[:])
		out = append(out, nc)
	}
	for _, n := range p.db.OContexts.Nodes6 {
		nc := &Nodecon{IPv6: true, policy: p, ctx: n.Context}
		copy(nc.Addr[:], n.Addr[:])
		copy(nc.Mask[:], n.Mask[:])
		out = append(out, nc)
	}
	return out
}

// Ibpkeycon is one ibpkeycon statement.
type Ibpkeycon struct {
	SubnetPrefix [8]byte
	LowPKey      uint16
	HighPKey     uint16
	policy       *Policy
	ctx          policy.Context
}

// Context renders the statement's security context.
func (i *Ibpkeycon) Context() string { return i.policy.Context(i.ctx) }

// SubnetPrefixString renders the subnet prefix: the 64 stored bits are the
// most significant half of an IPv6 address.
func (i *Ibpkeycon) SubnetPrefixString() string {
	var ip [16]byte
	copy(ip[:8], i.SubnetPrefix[:])
	return net.IP(ip[:]).String()
}

// PKeys renders the partition key or key range, in the 0x%04x notation.
func (i *Ibpkeycon) PKeys() string {
	if i.LowPKey == i.HighPKey {
		return fmt.Sprintf("0x%04x", i.LowPKey)
	}
	return fmt.Sprintf("0x%04x-0x%04x", i.LowPKey, i.HighPKey)
}

// Statement renders the ibpkeycon statement.
func (i *Ibpkeycon) Statement() string {
	return fmt.Sprintf("ibpkeycon %s %s %s", i.SubnetPrefixString(), i.PKeys(), i.Context())
}

// Ibpkeycons returns the ibpkeycon statements, in policy order.
func (p *Policy) Ibpkeycons() []*Ibpkeycon {
	out := make([]*Ibpkeycon, 0, len(p.db.OContexts.IBPkeys))
	for _, k := range p.db.OContexts.IBPkeys {
		ib := &Ibpkeycon{LowPKey: k.LowPKey, HighPKey: k.HighPKey, policy: p, ctx: k.Context}
		copy(ib.SubnetPrefix[:], k.SubnetPrefix[:])
		out = append(out, ib)
	}
	return out
}

// Ibendportcon is one ibendportcon statement.
type Ibendportcon struct {
	DeviceName string
	Port       uint8
	policy     *Policy
	ctx        policy.Context
}

// Context renders the statement's security context.
func (i *Ibendportcon) Context() string { return i.policy.Context(i.ctx) }

// Statement renders the ibendportcon statement.
func (i *Ibendportcon) Statement() string {
	return fmt.Sprintf("ibendportcon %s %d %s", i.DeviceName, i.Port, i.Context())
}

// Ibendportcons returns the ibendportcon statements, in policy order.
func (p *Policy) Ibendportcons() []*Ibendportcon {
	out := make([]*Ibendportcon, 0, len(p.db.OContexts.IBEndPorts))
	for _, e := range p.db.OContexts.IBEndPorts {
		out = append(out, &Ibendportcon{DeviceName: e.DeviceName, Port: e.Port, policy: p, ctx: e.Context})
	}
	return out
}

// XenInitialSID is one initial SID of a xen policy.
type XenInitialSID = InitialSID

// XenInitialSIDs returns the xen initial SIDs, in policy order.
func (p *Policy) XenInitialSIDs() []*InitialSID {
	out := make([]*InitialSID, 0, len(p.db.OContexts.Xen.ISids))
	for _, s := range p.db.OContexts.Xen.ISids {
		out = append(out, &InitialSID{Name: s.Name, policy: p, ctx: s.Context})
	}
	return out
}

// XenPirqcon is one pirqcon statement.
type XenPirqcon struct {
	IRQ    uint16
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (x *XenPirqcon) Context() string { return x.policy.Context(x.ctx) }

// Statement renders the pirqcon statement.
func (x *XenPirqcon) Statement() string {
	return fmt.Sprintf("pirqcon %d %s", x.IRQ, x.Context())
}

// XenPirqcons returns the pirqcon statements, in policy order.
func (p *Policy) XenPirqcons() []*XenPirqcon {
	out := make([]*XenPirqcon, 0, len(p.db.OContexts.Xen.Pirqs))
	for _, q := range p.db.OContexts.Xen.Pirqs {
		out = append(out, &XenPirqcon{IRQ: q.IRQ, policy: p, ctx: q.Context})
	}
	return out
}

// XenIOPortcon is one ioportcon statement.
type XenIOPortcon struct {
	Low    uint32
	High   uint32
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (x *XenIOPortcon) Context() string { return x.policy.Context(x.ctx) }

// Statement renders the ioportcon statement: the range in 0x%04x notation.
func (x *XenIOPortcon) Statement() string {
	if x.Low == x.High {
		return fmt.Sprintf("ioportcon 0x%04x %s", x.Low, x.Context())
	}
	return fmt.Sprintf("ioportcon 0x%04x-0x%04x %s", x.Low, x.High, x.Context())
}

// XenIOPortcons returns the ioportcon statements, in policy order.
func (p *Policy) XenIOPortcons() []*XenIOPortcon {
	out := make([]*XenIOPortcon, 0, len(p.db.OContexts.Xen.IOPorts))
	for _, o := range p.db.OContexts.Xen.IOPorts {
		out = append(out, &XenIOPortcon{Low: o.Low, High: o.High, policy: p, ctx: o.Context})
	}
	return out
}

// XenIOMemcon is one iomemcon statement.
type XenIOMemcon struct {
	Low    uint64
	High   uint64
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (x *XenIOMemcon) Context() string { return x.policy.Context(x.ctx) }

// Statement renders the iomemcon statement.
func (x *XenIOMemcon) Statement() string {
	if x.Low == x.High {
		return fmt.Sprintf("iomemcon 0x%04x %s", x.Low, x.Context())
	}
	return fmt.Sprintf("iomemcon 0x%04x-0x%04x %s", x.Low, x.High, x.Context())
}

// XenIOMemcons returns the iomemcon statements, in policy order.
func (p *Policy) XenIOMemcons() []*XenIOMemcon {
	out := make([]*XenIOMemcon, 0, len(p.db.OContexts.Xen.IOMems))
	for _, m := range p.db.OContexts.Xen.IOMems {
		out = append(out, &XenIOMemcon{Low: m.Low, High: m.High, policy: p, ctx: m.Context})
	}
	return out
}

// XenPCIDevicecon is one pcidevicecon statement.
type XenPCIDevicecon struct {
	Device uint32
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (x *XenPCIDevicecon) Context() string { return x.policy.Context(x.ctx) }

// Statement renders the pcidevicecon statement.
func (x *XenPCIDevicecon) Statement() string {
	return fmt.Sprintf("pcidevicecon 0x%04x %s", x.Device, x.Context())
}

// XenPCIDevicecons returns the pcidevicecon statements, in policy order.
func (p *Policy) XenPCIDevicecons() []*XenPCIDevicecon {
	out := make([]*XenPCIDevicecon, 0, len(p.db.OContexts.Xen.PCIDevices))
	for _, d := range p.db.OContexts.Xen.PCIDevices {
		out = append(out, &XenPCIDevicecon{Device: d.Device, policy: p, ctx: d.Context})
	}
	return out
}

// XenDeviceTreecon is one devicetreecon statement.
type XenDeviceTreecon struct {
	Path   string
	policy *Policy
	ctx    policy.Context
}

// Context renders the statement's security context.
func (x *XenDeviceTreecon) Context() string { return x.policy.Context(x.ctx) }

// Statement renders the devicetreecon statement.
func (x *XenDeviceTreecon) Statement() string {
	return fmt.Sprintf("devicetreecon %s %s", x.Path, x.Context())
}

// XenDeviceTreecons returns the devicetreecon statements, in policy order.
func (p *Policy) XenDeviceTreecons() []*XenDeviceTreecon {
	out := make([]*XenDeviceTreecon, 0, len(p.db.OContexts.Xen.DeviceTrees))
	for _, d := range p.db.OContexts.Xen.DeviceTrees {
		out = append(out, &XenDeviceTreecon{Path: d.Path, policy: p, ctx: d.Context})
	}
	return out
}
