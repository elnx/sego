package policy

// Rule table readers: the type enforcement avtab, conditional rule blocks,
// role transitions/allows, filename transitions and range transitions.

func readAVTab(r *reader, version uint32) []AVTabEntry {
	nel := r.count(minAVTabEntryBytes, "avtab")
	if r.err != nil {
		return nil
	}
	entries := make([]AVTabEntry, 0, nel)
	for range nel {
		e, ok := readAVTabEntry(r, version)
		if !ok {
			return entries
		}
		entries = append(entries, e)
	}
	return entries
}

// readAVTabEntry decodes one avtab key/payload pair. It reports false when the
// stream is exhausted or malformed.
func readAVTabEntry(r *reader, version uint32) (AVTabEntry, bool) {
	var e AVTabEntry
	e.Source = uint32(r.u16())
	e.Target = uint32(r.u16())
	e.Class = uint32(r.u16())
	e.Specified = uint32(r.u16())
	if err := r.err; err != nil {
		return e, false
	}
	if e.Source == 0 || e.Target == 0 || e.Class == 0 {
		r.fail("avtab entry with zero symbol")
		return e, false
	}
	switch {
	case e.Specified&AVTabXPerms != 0:
		if version < VersionXPermsIoctl {
			r.fail("avtab xperms entry in policy version %d", version)
			return e, false
		}
		x := &ExtendedPerms{
			Specified: uint32(r.u8()),
			Driver:    r.u8(),
		}
		for i := range x.Perms {
			x.Perms[i] = r.u32()
		}
		if err := r.err; err != nil {
			return e, false
		}
		e.XPerms = x
	case e.Specified&(AVTabAV|AVTabType) != 0:
		e.Data = r.u32()
		if err := r.err; err != nil {
			return e, false
		}
	default:
		r.fail("avtab entry with invalid specifier %#x", e.Specified)
		return e, false
	}
	return e, true
}

// VersionXPermsIoctl is the policy version that introduced extended permissions.
const VersionXPermsIoctl = 30

func readConditions(r *reader, version uint32) []*Condition {
	nel := r.count(16, "conditional block")
	if r.err != nil {
		return nil
	}
	conds := make([]*Condition, 0, nel)
	for range nel {
		c := &Condition{CurState: r.u32()}
		nexpr := r.count(8, "conditional expression")
		if r.err != nil {
			return conds
		}
		c.Exprs = make([]CondExpr, 0, nexpr)
		for range nexpr {
			c.Exprs = append(c.Exprs, CondExpr{
				ExprType: r.u32(),
				Boolean:  r.u32(),
			})
		}
		c.TrueRules = readAVTab(r, version)
		c.FalseRules = readAVTab(r, version)
		if err := r.err; err != nil {
			return conds
		}
		conds = append(conds, c)
	}
	return conds
}

func readRoleTrans(r *reader) []RoleTrans {
	nel := r.count(16, "role transition")
	if r.err != nil {
		return nil
	}
	out := make([]RoleTrans, 0, nel)
	for range nel {
		out = append(out, RoleTrans{
			Role:    r.u32(),
			Type:    r.u32(),
			NewRole: r.u32(),
			Class:   r.u32(),
		})
	}
	if r.err != nil {
		return out
	}
	return out
}

func readRoleAllows(r *reader) []RoleAllow {
	nel := r.count(8, "role allow")
	if r.err != nil {
		return nil
	}
	out := make([]RoleAllow, 0, nel)
	for range nel {
		out = append(out, RoleAllow{
			Role:    r.u32(),
			NewRole: r.u32(),
		})
	}
	if r.err != nil {
		return out
	}
	return out
}

func readFilenameTrans(r *reader, version uint32, target string) []FilenameTrans {
	nel := r.count(4, "filename transition")
	if r.err != nil {
		return nil
	}
	out := make([]FilenameTrans, 0, nel)
	if version < VersionCompFtrans || target != targetSELinux {
		// Uncompressed form: one record per (name, source type) pair.
		for range nel {
			name := r.str()
			// The source type is stored as a symbol value here, unlike the
			// compressed form below where it is a bitmap of zero based
			// indices.
			source := r.u32()
			target := r.u32()
			class := r.u32()
			def := r.u32()
			if r.err != nil {
				return out
			}
			out = append(out, FilenameTrans{
				Name:    name,
				Sources: []uint32{source},
				Target:  target,
				Class:   class,
				Default: def,
			})
		}
		return out
	}
	for range nel {
		name := r.str()
		target := r.u32()
		class := r.u32()
		ndatum := r.count(8, "filename transition datum")
		if r.err != nil {
			return out
		}
		for range ndatum {
			// The compressed form stores the set of source types as a
			// bitmap of zero based type indices.
			sources := r.symbolBitmap()
			def := r.u32()
			if r.err != nil {
				return out
			}
			out = append(out, FilenameTrans{
				Name:    name,
				Target:  target,
				Class:   class,
				Sources: sources,
				Default: def,
			})
		}
	}
	return out
}

func readRangeTrans(r *reader) []RangeTrans {
	nel := r.count(16, "range transition")
	if r.err != nil {
		return nil
	}
	out := make([]RangeTrans, 0, nel)
	for range nel {
		rt := RangeTrans{
			Source: r.u32(),
			Target: r.u32(),
			Class:  r.u32(),
		}
		rt.Range = readRange(r)
		if r.err != nil {
			return out
		}
		out = append(out, rt)
	}
	return out
}

// readRange reads an MLS range as written by mls_write_range_helper: a common
// item count followed by the low sensitivity (and the high sensitivity when the
// levels differ), then the low (and high) category bitmaps.
func readRange(r *reader) Range {
	var rg Range
	items := r.u32()
	if r.err != nil {
		return rg
	}
	switch items {
	case 1:
		rg.Low.Sens = r.u32()
		rg.High = rg.Low
	case 2:
		rg.Low.Sens = r.u32()
		rg.High.Sens = r.u32()
	default:
		r.fail("invalid MLS range item count %d", items)
		return rg
	}
	rg.Low.Cats = r.catBitmap()
	if items == 2 {
		rg.High.Cats = r.catBitmap()
	} else {
		rg.High.Cats = rg.Low.Cats
	}
	return rg
}
