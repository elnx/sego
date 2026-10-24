package policy

// Avtab iteration order.
//
// A kernel policy stores the type enforcement avtab as a sequence of entries,
// but libsepol reads it back into a hash table and iterates that table: the
// order the reference tools walk the rules in is the hash bucket order, with
// each bucket's list sorted by (source, target, class) as avtab_insert sorts
// it. The graph analyses expose that order (the order edges enter their
// graph), so the reader restores it here.
//
// The hash function and the bucket count are libsepol's avtab_hash() and
// avtab_alloc(): a 32 bit MurmurHash-style mix of the key fields and
// 2^(bits(nrules)-2) buckets, capped at 2^20.

import "math/bits"

// avtabHash computes the libsepol bucket of an entry.
func avtabHash(e AVTabEntry, mask uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	hash := uint32(0)
	mix := func(input uint32) {
		v := input
		v *= c1
		v = bits.RotateLeft32(v, 15)
		v *= c2
		hash ^= v
		hash = bits.RotateLeft32(hash, 13)
		hash = hash*5 + 0xe6546b64
	}
	mix(e.Class)
	mix(e.Target)
	mix(e.Source)

	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash & mask
}

// orderAVTab returns the entries in the order libsepol's hash table iteration
// yields them.
func orderAVTab(entries []AVTabEntry) []AVTabEntry {
	n := len(entries)
	if n < 2 {
		return entries
	}
	shift := bits.Len(uint(n))
	if shift > 2 {
		shift -= 2
	}
	nslot := 1 << shift
	const maxBuckets = 1 << 20
	if nslot > maxBuckets {
		nslot = maxBuckets
	}
	mask := uint32(nslot - 1)

	buckets := make([][]AVTabEntry, nslot)
	for _, e := range entries {
		h := avtabHash(e, mask)
		buckets[h] = avtabInsertSorted(buckets[h], e)
	}
	out := make([]AVTabEntry, 0, n)
	for _, bucket := range buckets {
		out = append(out, bucket...)
	}
	return out
}

// avtabInsertSorted inserts the entry into a bucket the way avtab_insert does:
// keeping the list sorted by (source, target, class), with a new extended
// permission entry of an existing key placed before the first match.
func avtabInsertSorted(bucket []AVTabEntry, e AVTabEntry) []AVTabEntry {
	specified := e.Specified &^ AVTabEnabled
	idx := len(bucket)
	for i, cur := range bucket {
		if e.Source == cur.Source && e.Target == cur.Target && e.Class == cur.Class &&
			specified&cur.Specified != 0 {
			// Extended permissions are not necessarily unique and go in
			// front of the existing entry; a plain duplicate entry cannot
			// occur in a valid policy.
			if specified&AVTabXPerms != 0 {
				idx = i
			}
			break
		}
		if e.Source < cur.Source ||
			(e.Source == cur.Source && e.Target < cur.Target) ||
			(e.Source == cur.Source && e.Target == cur.Target && e.Class < cur.Class) {
			idx = i
			break
		}
	}
	bucket = append(bucket, AVTabEntry{})
	copy(bucket[idx+1:], bucket[idx:])
	bucket[idx] = e
	return bucket
}
