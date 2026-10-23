package policy

import (
	"encoding/binary"
	"fmt"
)

// Limits used to sanity check counts read from a policy file.
const (
	maxSymbols         = 1 << 20
	maxNameLen         = 1 << 12
	minConstraintBytes = 8  // permissions + expression count
	minAVTabEntryBytes = 10 // 4 uint16 key fields + payload
)

// reader is a sequential decoder over the policy byte stream. Decoding errors
// are sticky: the first failure is recorded and later calls are no-ops, so the
// callers can decode a record and check for errors once.
type reader struct {
	data []byte
	off  int
	err  error
}

func newReader(data []byte) *reader { return &reader{data: data} }

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format+" (offset %d)", append(args, r.off)...)
	}
}

func (r *reader) remaining() int { return len(r.data) - r.off }

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.remaining() < n {
		r.fail("truncated policy: need %d bytes, %d available", n, r.remaining())
		return false
	}
	return true
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	b := r.data[r.off : r.off+n]
	r.off += n
	return b
}

func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.data[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.data[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.data[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.data[r.off:])
	r.off += 8
	return v
}

// str reads a uint32 length followed by that many bytes.
func (r *reader) str() string {
	n := r.u32()
	if !r.need(int(n)) {
		return ""
	}
	if n == 0 {
		return ""
	}
	return string(r.bytes(int(n)))
}

// count reads a uint32 element count and validates it against the number of
// bytes remaining for the smallest possible element size.
func (r *reader) count(minElemSize int, what string) uint32 {
	n := r.u32()
	if r.err != nil {
		return 0
	}
	if minElemSize > 0 && uint64(n)*uint64(minElemSize) > uint64(r.remaining()) {
		r.fail("invalid %s count %d", what, n)
		return 0
	}
	return n
}

// symbolBitmap decodes an ebitmap of symbol values. Symbol bitmaps in a kernel
// policy are indexed by symbol value minus one, so the bits are converted to
// the values used everywhere else.
func (r *reader) symbolBitmap() []uint32 {
	bits := r.bitmap()
	for i, b := range bits {
		bits[i] = b + 1
	}
	return bits
}

// catBitmap decodes an ebitmap of category values. Category bitmaps in a
// kernel policy are indexed by category value minus one, so the bits are
// converted to the category values used everywhere else.
func (r *reader) catBitmap() []uint32 {
	bits := r.bitmap()
	for i, b := range bits {
		bits[i] = b + 1
	}
	return bits
}

// bitmap decodes an ebitmap into the list of its set bit positions.
func (r *reader) bitmap() []uint32 {
	mapsize := r.u32()
	highbit := r.u32()
	count := r.u32()
	if r.err != nil {
		return nil
	}
	if mapsize != 64 && mapsize != 32 {
		r.fail("unsupported ebitmap map size %d", mapsize)
		return nil
	}
	if highbit%(mapsize) != 0 {
		r.fail("ebitmap high bit %d is not a multiple of map size %d", highbit, mapsize)
		return nil
	}
	if highbit == 0 {
		return nil
	}
	if count == 0 {
		r.fail("ebitmap with high bit %d and no maps", highbit)
		return nil
	}
	if r.err != nil {
		return nil
	}
	elemSize := int(mapsize)/8 + 4
	if uint64(count)*uint64(elemSize) > uint64(r.remaining()) {
		r.fail("ebitmap map count %d exceeds remaining data", count)
		return nil
	}
	bits := make([]uint32, 0, count*4)
	prev := uint32(0)
	for i := range count {
		start := r.u32()
		if r.err != nil {
			return bits
		}
		if start%mapsize != 0 {
			r.fail("ebitmap map start bit %d is not a multiple of %d", start, mapsize)
			return bits
		}
		if i > 0 && start <= prev {
			r.fail("ebitmap map start bits out of order (%d after %d)", start, prev)
			return bits
		}
		if start > highbit-mapsize {
			r.fail("ebitmap map start bit %d is past high bit %d", start, highbit)
			return bits
		}
		prev = start
		var m uint64
		if mapsize == 64 {
			m = r.u64()
		} else {
			m = uint64(r.u32())
		}
		if r.err != nil {
			return bits
		}
		if m == 0 {
			r.fail("ebitmap contains an empty map at bit %d", start)
			return bits
		}
		for b := range mapsize {
			if m&(1<<b) != 0 {
				bit := start + b
				if bit >= highbit {
					r.fail("ebitmap bit %d is past high bit %d", bit, highbit)
					return bits
				}
				bits = append(bits, bit)
			}
		}
	}
	return bits
}

// Symbol records are laid out with their fixed-size header first and the name
// string last (the length of the name is the first header item), so decoders
// read the length, the remaining fixed fields, and then the name bytes.

// readSymbol dispatches to the decoder for symbol table table.
func (p *Policy) readSymbol(r *reader, table int) error {
	switch table {
	case SymCommons:
		p.readCommon(r)
	case SymClasses:
		p.readClass(r)
	case SymRoles:
		p.readRole(r)
	case SymTypes:
		p.readType(r)
	case SymUsers:
		p.readUser(r)
	case SymBools:
		p.readBool(r)
	case SymLevels:
		p.readLevel(r)
	case SymCats:
		p.readCat(r)
	default:
		return fmt.Errorf("unknown symbol table %d", table)
	}
	return r.err
}

func (r *reader) name(length uint32) string {
	if length == 0 || length > maxNameLen {
		r.fail("invalid symbol name length %d", length)
		return ""
	}
	return string(r.bytes(int(length)))
}

func (p *Policy) readCommon(r *reader) {
	c := &Common{}
	nameLen := r.u32()
	c.Value = r.u32()
	c.NumPerms = r.u32()
	nperms := r.u32()
	if err := r.err; err != nil {
		return
	}
	if nperms > maxSymbols {
		r.fail("common has %d permissions", nperms)
		return
	}
	c.Name = r.name(nameLen)
	c.Perms = readPerms(r, nperms)
	p.putCommon(r, c)
}

func (p *Policy) readClass(r *reader) {
	c := &Class{}
	nameLen := r.u32()
	commonLen := r.u32()
	c.Value = r.u32()
	c.NumPerms = r.u32()
	nperms := r.u32()
	ncons := r.u32()
	if err := r.err; err != nil {
		return
	}
	if nperms > maxSymbols || ncons > maxSymbols {
		r.fail("class has %d permissions and %d constraints", nperms, ncons)
		return
	}
	c.Name = r.name(nameLen)
	if commonLen > 0 {
		c.Common = r.name(commonLen)
	}
	c.Perms = readPerms(r, nperms)
	c.Constraints = readConstraints(r, int(ncons), false)
	nvalidate := r.count(minConstraintBytes, "validatetrans")
	if r.err != nil {
		return
	}
	c.Validatetrans = readConstraints(r, int(nvalidate), true)
	c.DefaultUser = r.u32()
	c.DefaultRole = r.u32()
	c.DefaultRange = r.u32()
	c.DefaultType = r.u32()
	if r.err != nil {
		return
	}
	p.putClass(r, c)
}

func (p *Policy) readRole(r *reader) {
	ro := &Role{}
	nameLen := r.u32()
	ro.Value = r.u32()
	ro.Bounds = r.u32()
	if err := r.err; err != nil {
		return
	}
	ro.Name = r.name(nameLen)
	ro.Dominates = r.symbolBitmap()
	ro.Types = r.symbolBitmap()
	p.putRole(r, ro)
}

func (p *Policy) readType(r *reader) {
	t := &Type{}
	nameLen := r.u32()
	t.Value = r.u32()
	props := r.u32()
	t.Bounds = r.u32()
	if err := r.err; err != nil {
		return
	}
	t.Primary = props&TypePropertyPrimary != 0
	switch props & (TypePropertyAttribute | TypePropertyAlias) {
	case 0:
	case TypePropertyAttribute:
		t.IsAttribute = true
	default:
		r.fail("kernel policy type has invalid properties %#x", props)
		return
	}
	t.Name = r.name(nameLen)
	p.putType(r, t)
}

func (p *Policy) readUser(r *reader) {
	u := &User{}
	nameLen := r.u32()
	u.Value = r.u32()
	u.Bounds = r.u32()
	if err := r.err; err != nil {
		return
	}
	u.Name = r.name(nameLen)
	u.Roles = r.symbolBitmap()
	u.Range = readRange(r)
	u.DefaultLevel = LevelValue{Sens: r.u32(), Cats: r.catBitmap()}
	p.putUser(r, u)
}

func (p *Policy) readBool(r *reader) {
	b := &Bool{}
	b.Value = r.u32()
	b.State = r.u32() != 0
	nameLen := r.u32()
	if err := r.err; err != nil {
		return
	}
	b.Name = r.name(nameLen)
	p.putBool(r, b)
}

func (p *Policy) readLevel(r *reader) {
	l := &Level{}
	nameLen := r.u32()
	l.IsAlias = r.u32() != 0
	if err := r.err; err != nil {
		return
	}
	l.Name = r.name(nameLen)
	l.Sens = r.u32()
	l.Cats = r.catBitmap()
	p.putLevel(r, l)
}

func (p *Policy) readCat(r *reader) {
	c := &Cat{}
	nameLen := r.u32()
	c.Value = r.u32()
	c.IsAlias = r.u32() != 0
	if err := r.err; err != nil {
		return
	}
	c.Name = r.name(nameLen)
	p.putCat(r, c)
}

func readPerms(r *reader, n uint32) []Perm {
	perms := make([]Perm, 0, n)
	for range n {
		nameLen := r.u32()
		pm := Perm{Value: r.u32()}
		if err := r.err; err != nil {
			return perms
		}
		pm.Name = r.name(nameLen)
		perms = append(perms, pm)
	}
	return perms
}

func readConstraints(r *reader, n int, allowXTarget bool) []Constraint {
	out := make([]Constraint, 0, n)
	for range n {
		cons := Constraint{Permissions: r.u32()}
		nexpr := r.u32()
		if err := r.err; err != nil {
			return out
		}
		if nexpr > maxSymbols {
			r.fail("invalid constraint expression count %d", nexpr)
			return out
		}
		cons.Exprs = make([]CExpr, 0, nexpr)
		for range nexpr {
			e := CExpr{
				ExprType: r.u32(),
				Attr:     r.u32(),
				Op:       r.u32(),
			}
			if err := r.err; err != nil {
				return out
			}
			switch e.ExprType {
			case CExprNot, CExprAnd, CExprOr, CExprAttr:
			case CExprNames:
				if !allowXTarget && e.Attr&CExprXTarget != 0 {
					r.fail("constraint expression uses XTARGET")
					return out
				}
				e.Names = r.bitmap()
				e.Types = r.bitmap()
				e.NegTypes = r.bitmap()
				e.Flags = r.u32()
				if err := r.err; err != nil {
					return out
				}
			default:
				r.fail("invalid constraint expression type %#x", e.ExprType)
				return out
			}
			cons.Exprs = append(cons.Exprs, e)
		}
		out = append(out, cons)
	}
	return out
}
