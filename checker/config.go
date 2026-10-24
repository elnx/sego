package checker

// The INI configuration reader, following Python's configparser defaults:
// sections in square brackets, "key = value" or "key: value" pairs, lowercase
// option names, whitespace-indented continuation lines, full-line comments
// starting with # or ;, and DEFAULT section inheritance.

import (
	"fmt"
	"os"
	"strings"
)

// defaultSection is configparser's DEFAULT section name.
const defaultSection = "DEFAULT"

// configSection is one section with its effective values (the DEFAULT section
// merged in) and the option names in file order.
type configSection struct {
	name   string
	values map[string]string
}

// parseConfig reads the configuration file and returns its sections in file
// order, with DEFAULT merged into every section.
func parseConfig(path string) ([]*configSection, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	// configparser requires a section header before the first option.
	lines := strings.Split(content, "\n")

	var sections []*configSection
	byName := make(map[string]*configSection)
	defaults := make(map[string]string)
	var current *configSection
	var lastKey string

	for i, raw := range lines {
		lineNum := i + 1
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Continuation lines are indented and extend the previous value.
		if (line[0] == ' ' || line[0] == '\t') && current != nil && lastKey != "" {
			target := current.values
			if current.name == defaultSection {
				target = defaults
			}
			if old, ok := target[lastKey]; ok {
				target[lastKey] = old + "\n" + trimmed
			} else {
				target[lastKey] = trimmed
			}
			continue
		}

		if strings.HasPrefix(trimmed, "[") {
			end := strings.Index(trimmed, "]")
			if end < 0 {
				return nil, fmt.Errorf("File contains no section headers.\nfile: '%s', line: %d\n%s",
					path, lineNum, raw)
			}
			name := trimmed[1:end]
			if _, exists := byName[name]; exists {
				return nil, fmt.Errorf("While reading from '%s' [line %2d]: section '%s' already exists",
					path, lineNum, name)
			}
			current = &configSection{name: name, values: make(map[string]string)}
			if name == defaultSection {
				current.values = defaults
			}
			byName[name] = current
			sections = append(sections, current)
			lastKey = ""
			continue
		}

		// An option line: split on the first = or :.
		sep := strings.IndexAny(line, "=:")
		if sep < 0 {
			return nil, fmt.Errorf("Source contains parsing errors: '%s'\n\t[line %2d]: '%s'",
				path, lineNum, raw)
		}
		if current == nil {
			return nil, fmt.Errorf("File contains no section headers.\nfile: '%s', line: %d\n%s",
				path, lineNum, raw)
		}
		key := strings.ToLower(strings.TrimSpace(line[:sep]))
		value := strings.TrimSpace(line[sep+1:])
		if _, exists := current.values[key]; exists {
			return nil, fmt.Errorf(
				"While reading from '%s' [line %2d]: option '%s' in section '%s' already exists",
				path, lineNum, key, current.name)
		}
		current.values[key] = value
		lastKey = key
	}

	// Merge the DEFAULT section into every other section.
	if len(defaults) > 0 {
		for _, section := range sections {
			if section.name == defaultSection {
				continue
			}
			for key, value := range defaults {
				if _, ok := section.values[key]; !ok {
					section.values[key] = value
				}
			}
		}
	}
	return sections, nil
}
