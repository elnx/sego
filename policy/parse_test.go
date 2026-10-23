package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestParseFixtures parses every compiled policy in testdata and checks that
// the decoded structure is self consistent. The fixtures are compiled from the
// setools test suite sources at several policy versions, so parsing them
// exercises the version dependent parts of the format.
func TestParseFixtures(t *testing.T) {
	for _, path := range fixtureFiles(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			p, err := Open(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.Version < VersionMin || p.Version > VersionMax {
				t.Errorf("version %d out of range", p.Version)
			}
			if p.Target != targetSELinux {
				t.Errorf("target = %q, want %q", p.Target, targetSELinux)
			}
			if len(p.Types) == 0 || len(p.Classes) == 0 || len(p.Roles) == 0 {
				t.Fatalf("policy has %d types, %d classes, %d roles",
					len(p.Types), len(p.Classes), len(p.Roles))
			}
			checkSymbols(t, p)
			checkAVTab(t, p)
			checkAttrMaps(t, p)
		})
	}
}

// checkSymbols verifies that every symbol has a name and that lookups by name
// and value agree.
func checkSymbols(t *testing.T, p *Policy) {
	t.Helper()
	seen := make(map[string]bool)
	check := func(kind string, name string, value uint32) {
		if name == "" {
			t.Errorf("%s with value %d has no name", kind, value)
		}
		if value == 0 {
			t.Errorf("%s %q has value 0", kind, name)
		}
		key := kind + ":" + name
		if seen[key] {
			t.Errorf("duplicate %s %q", kind, name)
		}
		seen[key] = true
	}
	for _, ty := range p.Types {
		if ty == nil {
			t.Error("nil type in symbol table")
			continue
		}
		check("type", ty.Name, ty.Value)
		if got := p.TypeByName(ty.Name); got != ty {
			t.Errorf("TypeByName(%q) returned %v", ty.Name, got)
		}
	}
	for _, r := range p.Roles {
		if r != nil {
			check("role", r.Name, r.Value)
		}
	}
	for _, c := range p.Classes {
		if c != nil {
			check("class", c.Name, c.Value)
			wantNum := uint32(len(c.Perms))
			if c.Common != "" {
				for _, cm := range p.Commons {
					if cm != nil && cm.Name == c.Common {
						wantNum += uint32(len(cm.Perms))
						break
					}
				}
			}
			if c.NumPerms != wantNum {
				t.Errorf("class %s declares %d permissions, %d are defined",
					c.Name, c.NumPerms, wantNum)
			}
			for _, perm := range p.ClassPerms(c) {
				if perm.Name == "" || perm.Value == 0 {
					t.Errorf("class %s has a nameless permission %+v", c.Name, perm)
				}
			}
		}
	}
}

// checkAVTab verifies that every rule references existing symbols.
func checkAVTab(t *testing.T, p *Policy) {
	t.Helper()
	rules := []AVTabEntry{}
	rules = append(rules, p.AVTab...)
	for _, c := range p.Conditions {
		rules = append(rules, c.TrueRules...)
		rules = append(rules, c.FalseRules...)
	}
	for _, e := range rules {
		if p.TypeValue(e.Source) == nil {
			t.Errorf("rule references unknown source type %d", e.Source)
		}
		if p.TypeValue(e.Target) == nil {
			t.Errorf("rule references unknown target type %d", e.Target)
		}
		if p.ClassValue(e.Class) == nil {
			t.Errorf("rule references unknown class %d", e.Class)
		}
		if e.Specified&AVTabType != 0 && p.TypeValue(e.Data) == nil {
			t.Errorf("type rule references unknown default type %d", e.Data)
		}
	}
	for _, f := range p.FilenameTrans {
		if p.TypeValue(f.Target) == nil || p.TypeValue(f.Default) == nil {
			t.Errorf("filename transition references unknown types %d -> %d", f.Target, f.Default)
		}
		for _, src := range f.Sources {
			if p.TypeValue(src) == nil {
				t.Errorf("filename transition references unknown source type %d", src)
			}
		}
	}
}

// checkAttrMaps verifies that the on-disk per-type attribute map and the
// inverse member map derived from it agree. A type is recorded as its own
// attribute, so that self reference is skipped; empty attributes have no
// members at all.
func checkAttrMaps(t *testing.T, p *Policy) {
	t.Helper()
	if len(p.TypeAttrMap) != len(p.Types) {
		t.Fatalf("attribute map has %d entries for %d types", len(p.TypeAttrMap), len(p.Types))
	}
	for i, attrs := range p.TypeAttrMap {
		typeValue := uint32(i + 1)
		if p.TypeValue(typeValue) == nil {
			continue
		}
		for _, attr := range attrs {
			if p.TypeValue(attr) == nil {
				t.Errorf("type %d references unknown attribute %d", typeValue, attr)
				continue
			}
			if attr == typeValue {
				continue
			}
			if !contains(p.AttrTypeMap[attr-1], typeValue) {
				t.Errorf("type %d is listed under attribute %d, but the inverse map disagrees",
					typeValue, attr)
			}
		}
	}
	for i, members := range p.AttrTypeMap {
		attrValue := uint32(i + 1)
		if p.TypeValue(attrValue) == nil {
			continue
		}
		for _, member := range members {
			if member == attrValue {
				t.Errorf("attribute %d lists itself as a member", attrValue)
			}
			if p.TypeValue(member) == nil {
				t.Errorf("attribute %d references unknown member %d", attrValue, member)
				continue
			}
			if !contains(p.TypeAttrMap[member-1], attrValue) {
				t.Errorf("attribute %d lists member %d, but the inverse map disagrees",
					attrValue, member)
			}
		}
	}
}

func contains(values []uint32, want uint32) bool {
	return slices.Contains(values, want)
}

// TestParseRejects checks that malformed policies are rejected with an error
// rather than a panic or a silently truncated result.
func TestParseRejects(t *testing.T) {
	valid, err := os.ReadFile(fixtureFiles(t)[0])
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short", valid[:6]},
		{"wrong magic", append([]byte{0xde, 0xad, 0xbe, 0xef}, valid[4:]...)},
		{"module magic", append([]byte{0xd8, 0x28, 0x7f, 0xf2}, valid[4:]...)},
		{"truncated header", valid[:20]},
		{"truncated body", valid[:len(valid)/2]},
		{"trailing data", append(append([]byte{}, valid...), 0, 0, 0, 0)},
		{"bad version", versionOverridden(valid, 12)},
		{"bad target", targetOverridden(valid, "SE LinuxXYZ")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.data)
			if err == nil {
				t.Fatalf("parsed malformed policy: version %d, %d types", p.Version, len(p.Types))
			}
			if tc.name == "module magic" && !errors.Is(err, ErrNotKernelPolicy) {
				t.Errorf("err = %v, want ErrNotKernelPolicy", err)
			}
		})
	}
}

// versionOverridden returns policy bytes with the version field replaced.
func versionOverridden(data []byte, version uint32) []byte {
	out := append([]byte{}, data...)
	offset := 8 + int(binaryUint32(data[4:]))
	putUint32(out[offset:], version)
	return out
}

// targetOverridden returns policy bytes with the target string replaced.
func targetOverridden(data []byte, target string) []byte {
	out := append([]byte{}, data...)
	length := int(binaryUint32(data[4:]))
	if length != len(target) {
		out = append(out[:8], append([]byte(target), out[8+length:]...)...)
		putUint32(out[4:], uint32(len(target)))
		return out
	}
	copy(out[8:], target)
	return out
}

func binaryUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// FuzzParse checks that no input makes the parser panic or allocate wildly.
func FuzzParse(f *testing.F) {
	for _, path := range fixtureFiles(f) {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		if p.Version < VersionMin || p.Version > VersionMax {
			t.Fatalf("accepted policy version %d", p.Version)
		}
	})
}

// fixtureFiles returns every compiled policy available to the tests: the ones
// shipped with this package and the project's own fixtures, which cover the
// constructs the setools test policies do not (filename transitions, extended
// permissions in conditionals, neveraudit types).
func fixtureFiles(t testing.TB) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{"testdata/*.pol", "../testdata/policies/*.pol"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		t.Skip("no test policies available")
	}
	return files
}

// TestNoGarbageStrings guards against accepting a stream whose symbol names
// contain control characters: that would mean the decoder lost alignment.
func TestNoGarbageStrings(t *testing.T) {
	for _, path := range fixtureFiles(t) {
		p, err := Open(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var names []string
		for _, ty := range p.Types {
			if ty != nil {
				names = append(names, ty.Name)
			}
		}
		for _, c := range p.Classes {
			if c != nil {
				names = append(names, c.Name)
			}
		}
		for _, name := range names {
			if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				t.Errorf("%s: symbol name %q contains control characters", path, name)
			}
		}
	}
}
