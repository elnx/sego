package sego

// Permission maps and the information flow model, mirroring setools'
// permmap and infoflow modules.
//
// The default permission map (perm_map.txt, embedded below) is the standard
// SELinux permission map data distributed with setools/apol; see NOTICE.md.
// It maps each object class permission to a flow direction (read, write,
// both, none or unmapped) and a weight from 1 to 10.

import (
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// defaultPermMap is the permission map used when no file is named.
//
//go:embed perm_map.txt
var defaultPermMap string

// Flow directions.
const (
	FlowRead     = 'r'
	FlowWrite    = 'w'
	FlowBoth     = 'b'
	FlowNone     = 'n'
	FlowUnmapped = 'u'
)

// PermMapping is the mapping of one class permission.
type PermMapping struct {
	Direction byte
	Weight    int
	Enabled   bool
}

// PermissionMap maps object class permissions to flow directions and weights.
type PermissionMap struct {
	classes map[string]map[string]*PermMapping
}

// NewPermissionMap loads the permission map from path. An empty path loads
// the embedded default map.
func NewPermissionMap(path string) (*PermissionMap, error) {
	m := &PermissionMap{classes: make(map[string]map[string]*PermMapping)}
	if path == "" {
		if err := m.load("perm_map", defaultPermMap); err != nil {
			return nil, err
		}
		return m, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := m.load(path, string(data)); err != nil {
		return nil, err
	}
	return m, nil
}

// load parses the permission map format: a class count, then for each class a
// "class <name> <perm count>" line followed by "<perm> <direction> <weight>"
// lines.
func (m *PermissionMap) load(path, data string) error {
	// State machine: 1 = class count, 2 = class declaration, 3 = permissions.
	state := 1
	classCount, numClasses := 0, 0
	var class string
	var numPerms, permCount int

	lines := strings.Split(data, "\n")
	for i, line := range lines {
		lineNum := i + 1
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch state {
		case 1:
			n, err := strconv.Atoi(fields[0])
			if err != nil {
				return fmt.Errorf("%s:%d:Invalid number of classes: %s", path, lineNum, fields[0])
			}
			if n < 1 {
				return fmt.Errorf("%s:%d:Number of classes must be positive: %d", path, lineNum, n)
			}
			numClasses = n
			state = 2
		case 2:
			if len(fields) != 3 || fields[0] != "class" {
				return fmt.Errorf("%s:%d:Invalid class declaration: %v", path, lineNum, fields)
			}
			class = fields[1]
			n, err := strconv.Atoi(fields[2])
			if err != nil {
				return fmt.Errorf("%s:%d:Invalid number of permissions: %s", path, lineNum, fields[2])
			}
			if n < 1 {
				return fmt.Errorf("%s:%d:Number of permissions must be positive: %d", path, lineNum, n)
			}
			classCount++
			if classCount > numClasses {
				return fmt.Errorf("%s:%d:Extra class found: %s", path, lineNum, class)
			}
			m.classes[class] = make(map[string]*PermMapping)
			numPerms = n
			permCount = 0
			state = 3
		case 3:
			perm := fields[0]
			if len(fields) < 3 {
				return fmt.Errorf("%s:%d:Invalid permission mapping: %v", path, lineNum, fields)
			}
			var direction byte
			switch fields[1] {
			case "r":
				direction = FlowRead
			case "w":
				direction = FlowWrite
			case "b":
				direction = FlowBoth
			case "n":
				direction = FlowNone
			case "u":
				direction = FlowUnmapped
			default:
				return fmt.Errorf("%s:%d:Invalid information flow direction: %s", path, lineNum, fields[1])
			}
			weight, err := strconv.Atoi(fields[2])
			if err != nil {
				return fmt.Errorf("%s:%d:Invalid permission weight: %s", path, lineNum, fields[2])
			}
			if weight < 1 || weight > 10 {
				return fmt.Errorf("%s:%d:Permission weight must be 1-10: %d", path, lineNum, weight)
			}
			m.classes[class][perm] = &PermMapping{Direction: direction, Weight: weight, Enabled: true}
			permCount++
			if permCount >= numPerms {
				state = 2
			}
		}
	}
	return nil
}

// MapPolicy adds every class and permission of the policy that the map does
// not know yet, as unmapped with weight 1.
func (m *PermissionMap) MapPolicy(p *Policy) {
	for _, class := range p.Classes() {
		perms := m.classes[class.Name]
		if perms == nil {
			perms = make(map[string]*PermMapping)
			m.classes[class.Name] = perms
		}
		for _, perm := range class.Perms() {
			if _, ok := perms[perm]; !ok {
				perms[perm] = &PermMapping{Direction: FlowUnmapped, Weight: 1, Enabled: true}
			}
		}
	}
}

// RuleWeight returns the read and write weights of an allow rule: the maximum
// weight of the mapped permissions in each direction. The n and u directions
// do not flow.
func (m *PermissionMap) RuleWeight(rule *AVRule) (read, write int) {
	perms := m.classes[rule.Class.Name]
	for _, name := range rule.Perms {
		mapping := perms[name]
		if mapping == nil || !mapping.Enabled {
			continue
		}
		switch mapping.Direction {
		case FlowRead:
			read = max(read, mapping.Weight)
		case FlowWrite:
			write = max(write, mapping.Weight)
		case FlowBoth:
			read = max(read, mapping.Weight)
			write = max(write, mapping.Weight)
		}
	}
	return read, write
}
