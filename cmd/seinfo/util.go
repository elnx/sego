package main

// Helpers for the seinfo command: name matching, range and network parsing,
// and the component bookkeeping that surrounds the section rendering.

import (
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
)

// constValue is what a bare query option stores, mirroring the reference's
// nargs='?', const=True.
const constValue = "True"

// usageError marks an error that exits 2 with the usage line, the way the
// reference's parser.error does for malformed range criteria.
type usageError struct{ msg string }

func (e *usageError) usageError() {}

func (e *usageError) Error() string { return e.msg }

// fileExists reports whether the path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// groupArgs returns the spelled option names of the two argument groups that
// were set, e.g. ["--fs_use"], in registration order.
func groupArgs(a *argparse.Args, first, second string) (firstArgs, secondArgs []string) {
	for _, o := range optionTable() {
		if o.Pos || a == nil {
			continue
		}
		switch o.Group {
		case first:
			if a.Given(o.Dest) {
				firstArgs = append(firstArgs, o.Names[0])
			}
		case second:
			if a.Given(o.Dest) {
				secondArgs = append(secondArgs, o.Names[0])
			}
		}
	}
	return firstArgs, secondArgs
}

// componentDestOrder lists the query option destinations in the order the
// reference tool checks them when it repairs a misparsed policy path.
var componentDestOrder = []string{
	"typeattrquery", "boolquery", "classquery", "rolequery", "typequery", "userquery",
	"mlscatsquery", "commonquery", "constraintquery", "defaultquery", "permissivequery",
	"polcapquery", "roletypesquery", "mlssensquery", "typeboundsquery", "validatetransquery",
	"all",
	"fsusequery", "genfsconquery", "ibpkeyconquery", "ibendportconquery", "initialsidquery",
	"netifconquery", "nodeconquery", "portconquery",
	"devicetreeconquery", "iomemconquery", "ioportconquery", "pcideviceconquery", "pirqconquery",
}

// matchName reports whether the name matches the criteria: everything matches
// an empty criteria, otherwise the strings must be equal.
func matchName(name, criteria string) bool {
	return criteria == "" || name == criteria
}

// matchAlias reports whether the name or any alias matches the criteria.
func matchAlias(name string, aliases []string, criteria string) bool {
	if matchName(name, criteria) {
		return true
	}
	return slices.Contains(aliases, criteria)
}

// renderSymbols renders a symbol section: names, or statements with --expand,
// filtered by name and sorted, as the reference sorts every symbol section by
// its rendered string.
func renderSymbols[T any](expand bool, criteria string, items []T,
	nameStatement func(T) (string, string)) []string {

	var out []string
	for _, item := range items {
		name, statement := nameStatement(item)
		if matchName(name, criteria) {
			if expand {
				out = append(out, statement)
			} else {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// renderSymbolsKeepOrder renders a symbol section that keeps the policy
// declaration order (the MLS categories and sensitivities), matching by name
// or alias.
func renderSymbolsKeepOrder[T any](expand bool, criteria string, items []T,
	nameStatement func(T) (string, string), aliases func(T) []string) []string {

	var out []string
	for _, item := range items {
		name, statement := nameStatement(item)
		if matchAlias(name, aliases(item), criteria) {
			if expand {
				out = append(out, statement)
			} else {
				out = append(out, name)
			}
		}
	}
	return out
}

// renderAliases renders a symbol section whose items match by name or alias
// (the types), sorted afterwards.
func renderAliases[T any](expand bool, criteria string, items []T,
	fields func(T) (string, []string, string)) []string {

	var out []string
	for _, item := range items {
		name, aliases, statement := fields(item)
		if matchAlias(name, aliases, criteria) {
			if expand {
				out = append(out, statement)
			} else {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// sortStrings sorts in place; a nil slice stays nil so that empty sections
// print nothing.
func sortStrings(items []string) {
	sort.Strings(items)
}

// expandAttribute renders a type attribute with its member types, the way the
// reference's expand_attr does: the statement, then the sorted member names
// indented with tabs.
func expandAttribute(t *sego.Type) string {
	var members []string
	for _, m := range t.Members() {
		members = append(members, m.Name)
	}
	sort.Strings(members)
	contents := strings.Join(members, "\n\t")
	if contents == "" {
		contents = "<empty attribute>"
	}
	return fmt.Sprintf("%s\n\t%s", t.AttributeStatement(), contents)
}

// parseHexRange16 parses "0x22" or "0x6000-0x6020" into two uint16 values.
func parseHexRange16(text string) (uint16, uint16, error) {
	low, high, err := parseRange(text, strconv.ParseUint, 16, 0xffff)
	if err != nil {
		return 0, 0, &usageError{"Enter a pkey number or range, e.g. 0x22 or 0x6000-0x6020"}
	}
	return uint16(low), uint16(high), nil
}

// parseHexRange32 parses a hex range into uint32 values.
func parseHexRange32(text string) (uint32, uint32, error) {
	low, high, err := parseRange(text, strconv.ParseUint, 16, 0xffffffff)
	if err != nil {
		return 0, 0, &usageError{"Enter an IO port number or range, e.g. 0x22 or 0x6000-0x6020"}
	}
	return uint32(low), uint32(high), nil
}

// parseHexRange64 parses a hex range into uint64 values.
func parseHexRange64(text string) (uint64, uint64, error) {
	low, high, err := parseRange(text, strconv.ParseUint, 16, 0xffff)
	if err != nil {
		return 0, 0, &usageError{"Enter an IO memory address or range, e.g. 0x22 or 0x6000-0x6020"}
	}
	return low, high, nil
}

// parseHex32 parses a single hexadecimal number, accepting the 0x prefix like
// Python's int(value, base=16).
func parseHex32(text string) (uint32, error) {
	s := text
	if len(s) > 2 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int() with base 16: '%s'", text)
	}
	return uint32(n), nil
}

// parseDecRange16 parses "22" or "6000-6020" into two uint16 values.
func parseDecRange16(text string) (uint16, uint16, error) {
	low, high, err := parseRange(text, strconv.ParseUint, 10, 0xffff)
	if err != nil {
		return 0, 0, &usageError{"Enter a port number or range, e.g. 22 or 6000-6020"}
	}
	return uint16(low), uint16(high), nil
}

// parseDec parses a single decimal number, with Python's int() diagnostic.
func parseDec(text string) (uint32, error) {
	n, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int() with base 10: '%s'", text)
	}
	return uint32(n), nil
}

// parseRange splits "N" or "low-high" and parses both ends with parse.
func parseRange(text string, parse func(string, int, int) (uint64, error), base, max uint64) (uint64, uint64, error) {
	// strconv does not accept the 0x prefix with an explicit base.
	trim := func(s string) string {
		if base == 16 {
			if len(s) > 2 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
				return s[2:]
			}
		}
		return s
	}
	parts := strings.SplitN(text, "-", 2)
	low, err := parse(trim(parts[0]), int(base), 64)
	if err != nil {
		return 0, 0, err
	}
	high := low
	if len(parts) == 2 {
		high, err = parse(trim(parts[1]), int(base), 64)
		if err != nil {
			return 0, 0, err
		}
	}
	if low > max || high > max {
		return 0, 0, fmt.Errorf("value out of range")
	}
	return low, high, nil
}

// ipNetwork is a parsed IP network: the masked address, the prefix length and
// the address family.
type ipNetwork struct {
	addr net.IP
	ones int
	ipv6 bool
}

// parseIPNetwork parses an address ("127.0.0.1") or network ("10.0.0.0/8")
// the way ipaddress.ip_network does: a bare address is a host network, and a
// network with host bits set is an error.
func parseIPNetwork(text string) (*ipNetwork, error) {
	if text == "" {
		return nil, nil
	}
	ip, ipnet, err := net.ParseCIDR(text)
	if err == nil {
		ones, _ := ipnet.Mask.Size()
		if !ipnet.IP.Equal(ip.Mask(ipnet.Mask)) {
			return nil, fmt.Errorf("%s has host bits set", text)
		}
		return &ipNetwork{addr: ipnet.IP, ones: ones, ipv6: strings.Contains(text, ":")}, nil
	}
	parsed := net.ParseIP(text)
	if parsed == nil {
		return nil, fmt.Errorf("%s does not appear to be an IPv4 or IPv6 network", text)
	}
	if parsed.To4() != nil {
		return &ipNetwork{addr: parsed.To4(), ones: 32}, nil
	}
	return &ipNetwork{addr: parsed.To16(), ones: 128, ipv6: true}, nil
}

// matches reports whether the address and netmask of a nodecon statement
// describe the same network.
func (n *ipNetwork) matches(addrText, maskText string) bool {
	addr := net.ParseIP(addrText)
	mask := net.ParseIP(maskText)
	if addr == nil || mask == nil {
		return false
	}
	ones, _ := net.IPMask(mask).Size()
	if (ones == 32) == n.ipv6 {
		// Different address family.
		return false
	}
	return n.ones == ones && n.addr.Equal(addr.Mask(net.IPMask(mask)))
}
