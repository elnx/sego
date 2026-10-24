package sego

// Constraint and labeling statement differences of the policy diff.

// diffConstraints computes the constraint and validatetrans differences.
func diffConstraints(d *PolicyDiff, left, right *Policy) {
	constraintDiff(d, left, right, "constrain", "mlsconstrain", true)
	constraintDiff(d, left, right, "validatetrans", "mlsvalidatetrans", false)
}

// constraintDiff splits one constraint family into its two rule types and
// computes their added and removed statements.
func constraintDiff(d *PolicyDiff, left, right *Policy, kind, mlsKind string, constrain bool) {
	lset := constraintSet(left, kind, mlsKind, constrain)
	rset := constraintSet(right, kind, mlsKind, constrain)
	addedPlain, removedPlain := valueDiff(lset.plain, rset.plain)
	addedMLS, removedMLS := valueDiff(lset.mls, rset.mls)
	if constrain {
		d.AddedConstrains = addedPlain
		d.RemovedConstrains = removedPlain
		d.AddedMLSConstrains = addedMLS
		d.RemovedMLSConstrains = removedMLS
		return
	}
	d.AddedValidatetrans = addedPlain
	d.RemovedValidatetrans = removedPlain
	d.AddedMLSValidatetrans = addedMLS
	d.RemovedMLSValidatetrans = removedMLS
}

// constraintSet renders the constraints of one family, split into the plain
// and MLS rule types.
func constraintSet(p *Policy, kind, mlsKind string, constrain bool) struct {
	plain map[string]string
	mls   map[string]string
} {
	out := struct {
		plain map[string]string
		mls   map[string]string
	}{plain: map[string]string{}, mls: map[string]string{}}
	var all []*Constraint
	if constrain {
		all = p.Constraints()
	} else {
		all = p.Validatetrans()
	}
	for _, c := range all {
		if c.Kind == kind {
			out.plain[c.Statement()] = c.Statement()
		} else if c.Kind == mlsKind {
			out.mls[c.Statement()] = c.Statement()
		}
	}
	return out
}

// diffOContexts computes the labeling statement differences.
func diffOContexts(d *PolicyDiff, left, right *Policy) {
	// Initial SIDs.
	lisid := isidMap(left)
	risid := isidMap(right)
	d.AddedInitialSIDs, d.RemovedInitialSIDs = valueDiffObj(lisid, risid, func(s *InitialSID) string { return s.Statement() })
	for _, name := range intersect(mapKeys(lisid), mapKeys(risid)) {
		if isidContext(lisid[name], left) != isidContext(risid[name], right) {
			d.ModifiedInitialSIDs = append(d.ModifiedInitialSIDs, ModifiedContext{
				Statement:      "sid " + name,
				AddedContext:   isidContext(risid[name], right),
				RemovedContext: isidContext(lisid[name], left)})
		}
	}

	// fs_use.
	lfs := fsUseMap(left)
	rfs := fsUseMap(right)
	d.AddedFSUses, d.RemovedFSUses = valueDiffObj(lfs, rfs, func(f *FSUse) string { return f.Statement() })
	for _, key := range intersect(mapKeys(lfs), mapKeys(rfs)) {
		if fsUseContext(lfs[key], left) != fsUseContext(rfs[key], right) {
			d.ModifiedFSUses = append(d.ModifiedFSUses, ModifiedContext{
				Statement:      fsUseKey(lfs[key]),
				AddedContext:   fsUseContext(rfs[key], right),
				RemovedContext: fsUseContext(lfs[key], left)})
		}
	}

	// genfscon.
	lgen := genfsMap(left)
	rgen := genfsMap(right)
	d.AddedGenfscons, d.RemovedGenfscons = valueDiffObj(lgen, rgen, func(g *Genfscon) string { return g.Statement() })
	for _, key := range intersect(mapKeys(lgen), mapKeys(rgen)) {
		if genfsContext(lgen[key], left) != genfsContext(rgen[key], right) {
			d.ModifiedGenfscons = append(d.ModifiedGenfscons, ModifiedContext{
				Statement:      genfsKey(lgen[key]),
				AddedContext:   genfsContext(rgen[key], right),
				RemovedContext: genfsContext(lgen[key], left)})
		}
	}

	// netifcon.
	lnet := netifMap(left)
	rnet := netifMap(right)
	d.AddedNetifcons, d.RemovedNetifcons = valueDiffObj(lnet, rnet, func(n *Netifcon) string { return n.Statement() })
	for _, name := range intersect(mapKeys(lnet), mapKeys(rnet)) {
		mn := ModifiedNetifcon{Device: name}
		if lnet[name].Context() != rnet[name].Context() {
			mn.ContextChanged = true
			mn.AddedContext, mn.RemovedContext = rnet[name].Context(), lnet[name].Context()
		}
		if lnet[name].PacketContext() != rnet[name].PacketContext() {
			mn.PacketChanged = true
			mn.AddedPacket, mn.RemovedPacket = rnet[name].PacketContext(), lnet[name].PacketContext()
		}
		if mn.ContextChanged || mn.PacketChanged {
			d.ModifiedNetifcons = append(d.ModifiedNetifcons, mn)
		}
	}

	// nodecon.
	laddr := nodeconMap(left)
	raddr := nodeconMap(right)
	d.AddedNodecons, d.RemovedNodecons = valueDiffObj(laddr, raddr, func(n *Nodecon) string { return n.Statement() })
	for _, key := range intersect(mapKeys(laddr), mapKeys(raddr)) {
		if nodeconContext(laddr[key], left) != nodeconContext(raddr[key], right) {
			d.ModifiedNodecons = append(d.ModifiedNodecons, ModifiedContext{
				Statement:      nodeconKey(laddr[key]),
				AddedContext:   nodeconContext(raddr[key], right),
				RemovedContext: nodeconContext(laddr[key], left)})
		}
	}

	// portcon.
	lport := portconMap(left)
	rport := portconMap(right)
	d.AddedPortcons, d.RemovedPortcons = valueDiffObj(lport, rport, func(pc *Portcon) string { return pc.Statement() })
	for _, key := range intersect(mapKeys(lport), mapKeys(rport)) {
		if portconContext(lport[key], left) != portconContext(rport[key], right) {
			d.ModifiedPortcons = append(d.ModifiedPortcons, ModifiedContext{
				Statement:      portconKey(lport[key]),
				AddedContext:   portconContext(rport[key], right),
				RemovedContext: portconContext(lport[key], left)})
		}
	}

	// ibendportcon.
	lend := ibendportMap(left)
	rend := ibendportMap(right)
	d.AddedIbendportcons, d.RemovedIbendportcons = valueDiffObj(lend, rend, func(i *Ibendportcon) string { return i.Statement() })
	for _, key := range intersect(mapKeys(lend), mapKeys(rend)) {
		if ibendportContext(lend[key], left) != ibendportContext(rend[key], right) {
			d.ModifiedIbendportcons = append(d.ModifiedIbendportcons, ModifiedContext{
				Statement:      ibendportKey(lend[key]),
				AddedContext:   ibendportContext(rend[key], right),
				RemovedContext: ibendportContext(lend[key], left)})
		}
	}

	// ibpkeycon.
	lpkey := ibpkeyMap(left)
	rpkey := ibpkeyMap(right)
	d.AddedIbpkeycons, d.RemovedIbpkeycons = valueDiffObj(lpkey, rpkey, func(i *Ibpkeycon) string { return i.Statement() })
	for _, key := range intersect(mapKeys(lpkey), mapKeys(rpkey)) {
		if ibpkeyContext(lpkey[key], left) != ibpkeyContext(rpkey[key], right) {
			d.ModifiedIbpkeycons = append(d.ModifiedIbpkeycons, ModifiedContext{
				Statement:      ibpkeyKey(lpkey[key]),
				AddedContext:   ibpkeyContext(rpkey[key], right),
				RemovedContext: ibpkeyContext(lpkey[key], left)})
		}
	}
}
