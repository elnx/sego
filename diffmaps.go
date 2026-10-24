package sego

// Name keyed views of the labeling statements for the policy diff: the keys
// are the statement identity (everything but the context), the values are the
// statements themselves.

import "fmt"

func isidMap(p *Policy) map[string]*InitialSID {
	m := make(map[string]*InitialSID)
	for _, s := range p.InitialSIDs() {
		m[s.Name] = s
	}
	return m
}

func isidContext(s *InitialSID, p *Policy) string { return s.Context() }

func fsUseMap(p *Policy) map[string]*FSUse {
	m := make(map[string]*FSUse)
	for _, f := range p.FSUses() {
		m[f.FSType+"|"+fsUseBehavior(f.Behavior)] = f
	}
	return m
}

func fsUseBehavior(b uint32) string {
	switch b {
	case 1:
		return "fs_use_xattr"
	case 2:
		return "fs_use_trans"
	case 3:
		return "fs_use_task"
	}
	return fmt.Sprintf("%d", b)
}

func fsUseKey(f *FSUse) string { return fsUseBehavior(f.Behavior) + " " + f.FSType }
func fsUseContext(f *FSUse, p *Policy) string {
	return f.Context()
}

func genfsMap(p *Policy) map[string]*Genfscon {
	m := make(map[string]*Genfscon)
	for _, g := range p.Genfscons() {
		m[g.FSType+"|"+g.Path+"|"+g.FileType()] = g
	}
	return m
}

func genfsKey(g *Genfscon) string {
	return fmt.Sprintf("genfscon %s %s %s", g.FSType, g.Path, g.FileType())
}
func genfsContext(g *Genfscon, p *Policy) string {
	return g.Context()
}

func netifMap(p *Policy) map[string]*Netifcon {
	m := make(map[string]*Netifcon)
	for _, n := range p.Netifcons() {
		m[n.Device] = n
	}
	return m
}

func nodeconMap(p *Policy) map[string]*Nodecon {
	m := make(map[string]*Nodecon)
	for _, n := range p.Nodecons() {
		addr, mask := n.AddrStrings()
		m[addr+"|"+mask] = n
	}
	return m
}

func nodeconKey(n *Nodecon) string {
	addr, mask := n.AddrStrings()
	return fmt.Sprintf("nodecon %s %s", addr, mask)
}
func nodeconContext(n *Nodecon, p *Policy) string {
	return n.Context()
}

func portconMap(p *Policy) map[string]*Portcon {
	m := make(map[string]*Portcon)
	for _, pc := range p.Portcons() {
		m[portProtocol(pc.Protocol)+"|"+fmt.Sprint(pc.LowPort)+"|"+fmt.Sprint(pc.HighPort)] = pc
	}
	return m
}

func portconKey(pc *Portcon) string {
	return fmt.Sprintf("portcon %s %s", portProtocol(pc.Protocol), portRange(pc.LowPort, pc.HighPort))
}
func portconContext(pc *Portcon, p *Policy) string {
	return pc.Context()
}

func ibendportMap(p *Policy) map[string]*Ibendportcon {
	m := make(map[string]*Ibendportcon)
	for _, i := range p.Ibendportcons() {
		m[i.DeviceName+"|"+fmt.Sprint(i.Port)] = i
	}
	return m
}

func ibendportKey(i *Ibendportcon) string {
	return fmt.Sprintf("ibendportcon %s %d", i.DeviceName, i.Port)
}
func ibendportContext(i *Ibendportcon, p *Policy) string {
	return i.Context()
}

func ibpkeyMap(p *Policy) map[string]*Ibpkeycon {
	m := make(map[string]*Ibpkeycon)
	for _, i := range p.Ibpkeycons() {
		m[i.SubnetPrefixString()+"|"+i.PKeys()] = i
	}
	return m
}

func ibpkeyKey(i *Ibpkeycon) string {
	return fmt.Sprintf("ibpkeycon %s %s", i.SubnetPrefixString(), i.PKeys())
}
func ibpkeyContext(i *Ibpkeycon, p *Policy) string {
	return i.Context()
}
