package sego

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/elnx/sego/policy"
)

// XPermSet is a set of extended permission values (ioctl commands or netlink
// message types). Ranges are expanded into their individual values, as setools
// does, so that set operations and matching work on single values.
type XPermSet struct {
	values []uint32 // sorted, unique
}

// NewXPermSet builds a set from individual values.
func NewXPermSet(values ...uint32) *XPermSet {
	x := &XPermSet{}
	x.values = append(x.values, values...)
	x.normalize()
	return x
}

// ParseXPermSet parses a comma separated list of hexadecimal extended
// permissions and ranges, e.g. "0x08,0x30-0x40,0x55". Values outside the
// 16 bit extended permission range are rejected.
func ParseXPermSet(text string) (*XPermSet, error) {
	x := &XPermSet{}
	for item := range strings.SplitSeq(text, ",") {
		lowText, highText, isRange := strings.Cut(item, "-")
		low, err := parseHex(lowText)
		if err != nil {
			return nil, err
		}
		high := low
		if isRange {
			if strings.Contains(highText, "-") {
				return nil, fmt.Errorf("Unable to parse %q for xperms.", item)
			}
			if high, err = parseHex(highText); err != nil {
				return nil, err
			}
		}
		if high < low {
			low, high = high, low
		}
		for _, v := range []uint32{low, high} {
			if v > 0xffff {
				return nil, fmt.Errorf("0x%05x is not a valid ioctl.", v)
			}
		}
		for v := low; v <= high; v++ {
			x.values = append(x.values, v)
		}
	}
	x.normalize()
	return x, nil
}

// parseHex parses a hexadecimal value the way Python's int(text, 16) does: an
// optional 0x prefix and underscores between digits are allowed. The failure
// message is Python's, which is what the reference tool prints.
func parseHex(text string) (uint32, error) {
	digits := strings.ReplaceAll(strings.TrimSpace(text), "_", "")
	digits = strings.TrimPrefix(strings.TrimPrefix(digits, "0x"), "0X")
	v, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int() with base 16: '%s'", text)
	}
	return uint32(v), nil
}

// formatXPerm renders one extended permission value. Values are 16 bit wide,
// so the width matches Python's "{:#06x}" format specifier.
func formatXPerm(v uint32) string { return fmt.Sprintf("0x%04x", v) }

func (x *XPermSet) normalize() {
	slices.Sort(x.values)
	x.values = slices.Compact(x.values)
}

// Values returns the values of the set in ascending order.
func (x *XPermSet) Values() []uint32 {
	if x == nil {
		return nil
	}
	return x.values
}

// Len returns the number of values in the set.
func (x *XPermSet) Len() int {
	if x == nil {
		return 0
	}
	return len(x.values)
}

// Contains reports whether the set contains the value.
func (x *XPermSet) Contains(v uint32) bool {
	if x == nil {
		return false
	}
	i, found := slices.BinarySearch(x.values, v)
	_ = i
	return found
}

// Intersects reports whether the two sets share a value.
func (x *XPermSet) Intersects(other *XPermSet) bool {
	if x == nil || other == nil {
		return false
	}
	return slices.ContainsFunc(x.values, other.Contains)
}

// Equal reports whether the two sets contain the same values.
func (x *XPermSet) Equal(other *XPermSet) bool {
	if x.Len() != other.Len() {
		return false
	}
	for i, v := range x.values {
		if other.values[i] != v {
			return false
		}
	}
	return true
}

// Ranges returns the number of consecutive value runs in the set. Rules print
// their permissions in braces when there is more than one run.
func (x *XPermSet) Ranges() int {
	if x == nil || len(x.values) == 0 {
		return 0
	}
	runs := 1
	for i := 1; i < len(x.values); i++ {
		if x.values[i] != x.values[i-1]+1 {
			runs++
		}
	}
	return runs
}

// String renders the set as space separated value ranges, e.g.
// "0x0000-0x00ff 0x8910".
func (x *XPermSet) String() string {
	if x == nil || len(x.values) == 0 {
		return ""
	}
	var parts []string
	for i := 0; i < len(x.values); {
		j := i
		for j+1 < len(x.values) && x.values[j+1] == x.values[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, formatXPerm(x.values[i])+"-"+formatXPerm(x.values[j]))
		} else {
			parts = append(parts, formatXPerm(x.values[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, " ")
}

// xpermSet decodes the extended permission payload of an avtab entry. Values
// are expanded the way setools does: an ioctl function or netlink message type
// becomes driver<<8|bit, while an ioctl driver entry covers all 256 commands of
// that driver.
func (p *Policy) xpermSet(x *policy.ExtendedPerms) (*XPermSet, string) {
	set := &XPermSet{}
	for bit := range uint32(len(x.Perms) * 32) {
		if x.Perms[bit>>5]&(1<<(bit&0x1f)) == 0 {
			continue
		}
		switch x.Specified {
		case policy.XPermsIoctlFunction, policy.XPermsNLMsg:
			set.values = append(set.values, uint32(x.Driver)<<8|bit)
		case policy.XPermsIoctlDriver:
			base := bit << 8
			for v := base; v < base+0x100; v++ {
				set.values = append(set.values, v)
			}
		}
	}
	set.normalize()
	return set, xpermTypeName(x.Specified)
}

func xpermTypeName(specified uint32) string {
	if specified == policy.XPermsNLMsg {
		return "nlmsg"
	}
	return "ioctl"
}
