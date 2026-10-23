package main

// This file implements the command line handling of sesearch.
//
// The parser is hand-rolled rather than built on flag or a third party
// argument library, because sesearch has to reproduce Python's argparse
// byte for byte: the usage line, the grouped and wrapped --help output (TE
// Rule Types / RBAC Rule Types / MLS Rule Types / Expressions / Search
// options), the wording of every usage error and the split between usage
// errors (exit 2) and runtime errors (exit 1). No Go flag package formats or
// groups options that way. Only the parts of argparse that sesearch exercises
// are implemented; the wrapping and column layout follow argparse's
// HelpFormatter so that the output matches the reference tool at any terminal
// width.

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/elnx/sego"
)

// Text used by the reference tool.
const (
	description = "SELinux policy rule search tool."
	epilog      = "TE/MLS rule searches cannot be mixed with RBAC rule searches."
)

// Argument group headings, in the order argparse prints them. "options" is the
// heading modern argparse uses; Python 3.9 and older said "optional arguments".
const (
	groupPositional = "positional arguments"
	groupOptional   = "options"

	groupTE      = "TE Rule Types"
	groupRBAC    = "RBAC Rule Types"
	groupMLS     = "MLS Rule Types"
	groupExpr    = "Expressions"
	groupOptions = "Search options"
)

// option is a single command line option or positional argument. It carries
// everything the parser, the usage line and the help text need, mirroring the
// argparse Action attributes that affect them.
type option struct {
	names    []string      // option strings; the first is used in the usage line
	metavar  string        // value name; empty for options that take no value
	dest     string        // key the parsed value is stored under
	help     string        // one line help text
	group    string        // argument group heading
	pos      bool          // positional argument
	nargsOpt bool          // positional argument declared with nargs='?'
	ruleType sego.RuleType // rule type for the append_const rule type options
	family   string        // rule type family: "ter", "rbac" or "mls"
}

// isFlag reports whether the option takes no value.
func (o *option) isFlag() bool { return !o.pos && o.metavar == "" }

// nameList renders the option strings the way argparse names an argument in an
// error message, e.g. "-s/--source".
func (o *option) nameList() string { return strings.Join(o.names, "/") }

// optionTable returns every option in registration order, which is also the
// order they appear in the usage line and in the help text.
func optionTable() []option {
	return []option{
		{names: []string{"-h", "--help"}, dest: "help",
			help: "show this help message and exit"},
		{names: []string{"--version"}, dest: "version",
			help: "show program's version number and exit"},
		{names: []string{"-v", "--verbose"}, dest: "verbose",
			help: "Print extra informational messages"},
		{names: []string{"--debug"}, dest: "debug", help: "Enable debugging."},

		{names: []string{"-A"}, dest: "A", group: groupTE,
			help: "Search allow and allowxperm rules."},
		{names: []string{"--allow"}, dest: "allow", group: groupTE,
			family: "ter", ruleType: sego.Allow, help: "Search allow rules."},
		{names: []string{"--allowxperm"}, dest: "allowxperm", group: groupTE,
			family: "ter", ruleType: sego.AllowXPerm, help: "Search allowxperm rules."},
		{names: []string{"--auditallow"}, dest: "auditallow", group: groupTE,
			family: "ter", ruleType: sego.AuditAllow, help: "Search auditallow rules."},
		{names: []string{"--auditallowxperm"}, dest: "auditallowxperm", group: groupTE,
			family: "ter", ruleType: sego.AuditAllowXPerm, help: "Search auditallowxperm rules."},
		{names: []string{"--dontaudit"}, dest: "dontaudit", group: groupTE,
			family: "ter", ruleType: sego.DontAudit, help: "Search dontaudit rules."},
		{names: []string{"--dontauditxperm"}, dest: "dontauditxperm", group: groupTE,
			family: "ter", ruleType: sego.DontAuditXPerm, help: "Search dontauditxperm rules."},
		{names: []string{"-T", "--type_transition"}, dest: "type_transition", group: groupTE,
			family: "ter", ruleType: sego.TypeTransition, help: "Search type_transition rules."},
		{names: []string{"--type_change"}, dest: "type_change", group: groupTE,
			family: "ter", ruleType: sego.TypeChange, help: "Search type_change rules."},
		{names: []string{"--type_member"}, dest: "type_member", group: groupTE,
			family: "ter", ruleType: sego.TypeMember, help: "Search type_member rules."},

		{names: []string{"--role_allow"}, dest: "role_allow", group: groupRBAC,
			family: "rbac", ruleType: sego.RuleRoleAllow, help: "Search role allow rules."},
		{names: []string{"--role_transition"}, dest: "role_transition", group: groupRBAC,
			family: "rbac", ruleType: sego.RuleRoleTransition, help: "Search role_transition rules."},

		{names: []string{"--range_transition"}, dest: "range_transition", group: groupMLS,
			family: "mls", ruleType: sego.RuleRangeTransition, help: "Search range_transition rules."},

		{names: []string{"-s", "--source"}, metavar: "SOURCE", dest: "source", group: groupExpr,
			help: "Source type/role of the TE/RBAC rule."},
		{names: []string{"-t", "--target"}, metavar: "TARGET", dest: "target", group: groupExpr,
			help: "Target type/role of the TE/RBAC rule."},
		{names: []string{"-c", "--class"}, metavar: "TCLASS", dest: "tclass", group: groupExpr,
			help: "Comma separated list of object classes"},
		{names: []string{"-p", "--perms"}, metavar: "PERMS", dest: "perms", group: groupExpr,
			help: "Comma separated list of permissions. (TE rule searches only.)"},
		{names: []string{"-x", "--xperms"}, metavar: "XPERMS", dest: "xperms", group: groupExpr,
			help: "Comma separated list of extended permissions. (TE rule searches only.)"},
		{names: []string{"-D", "--default"}, metavar: "DEFAULT", dest: "default", group: groupExpr,
			help: "Default of the rule. (type/role/range transition rules)"},
		{names: []string{"-b", "--bool"}, metavar: "BOOL", dest: "boolean", group: groupExpr,
			help: "Comma separated list of Booleans in the conditional expression. " +
				"(TE rule searches only.)"},

		{names: []string{"-eb"}, dest: "boolean_equal", group: groupOptions,
			help: "Match Boolean list exactly instead of matching any listed Boolean."},
		{names: []string{"-ep"}, dest: "perms_equal", group: groupOptions,
			help: "Match permission set exactly instead of matching any listed permission."},
		{names: []string{"-ex"}, dest: "xperms_equal", group: groupOptions,
			help: "Match extended permission set exactly instead of matching any listed permission."},
		{names: []string{"-Sp"}, dest: "perms_subset", group: groupOptions,
			help: "Match rules where the listed permissions are a subset of the rule permissions."},
		{names: []string{"-ds"}, dest: "source_direct", group: groupOptions,
			help: "Match source attributes directly instead of matching member types/roles."},
		{names: []string{"-dt"}, dest: "target_direct", group: groupOptions,
			help: "Match target attributes directly instead of matching member types/roles."},
		{names: []string{"-rs"}, dest: "source_regex", group: groupOptions,
			help: "Use regular expression matching for the source type/role."},
		{names: []string{"-rt"}, dest: "target_regex", group: groupOptions,
			help: "Use regular expression matching for the target type/role."},
		{names: []string{"-rc"}, dest: "tclass_regex", group: groupOptions,
			help: "Use regular expression matching for the object class."},
		{names: []string{"-rd"}, dest: "default_regex", group: groupOptions,
			help: "Use regular expression matching for the default type/role."},
		{names: []string{"-rb"}, dest: "boolean_regex", group: groupOptions,
			help: "Use regular expression matching for Booleans."},

		{names: []string{"policy"}, dest: "policy", pos: true, nargsOpt: true,
			help: "Path to the SELinux policy to search."},
	}
}

// args are the parsed command line.
type args struct {
	policy    string
	hasPolicy bool
	verbose   bool
	debug     bool

	// help and version are handled as soon as they are parsed, as argparse
	// does, so they preempt any other error.
	showHelp    bool
	showVersion bool

	tertypes   []sego.RuleType
	rbacrtypes []sego.RuleType
	mlsrtypes  []sego.RuleType

	values map[string]string
	flags  map[string]bool
}

// value returns the value of a value-taking option, or "" when it was not
// given.
func (a *args) value(dest string) string { return a.values[dest] }

// flag returns whether a flag option was given.
func (a *args) flag(dest string) bool { return a.flags[dest] }

// usageError is a command line error: it makes sesearch print the usage line
// followed by an error message on stderr and exit with status 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// parser parses a command line and renders the usage and help text.
type parser struct {
	prog  string
	width int // wrapping width, as argparse derives it from the terminal
	opts  []option

	byName map[string]*option // exact option string lookup
	names  []string           // every option string, in registration order
}

// newParser returns a parser for the program named prog.
func newParser(prog string) *parser {
	opts := optionTable()
	p := &parser{prog: prog, opts: opts, width: terminalWidth(), byName: make(map[string]*option)}
	for i := range p.opts {
		for _, name := range p.opts[i].names {
			p.byName[name] = &p.opts[i]
			p.names = append(p.names, name)
		}
	}
	return p
}

// parse parses argv (without the program name). A non-nil error is always a
// usage error.
func (p *parser) parse(argv []string) (*args, error) {
	a := &args{values: make(map[string]string), flags: make(map[string]bool)}
	var extras []string

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		opt, explicit, hasValue, err := p.match(arg)
		if err != nil {
			return nil, err
		}
		if opt == nil {
			// A positional argument, or an unrecognized option.
			if !looksLikeOption(arg) && !a.hasPolicy {
				a.policy, a.hasPolicy = arg, true
				continue
			}
			extras = append(extras, arg)
			continue
		}

		if opt.isFlag() {
			if hasValue {
				return nil, &usageError{fmt.Sprintf(
					"argument %s: ignored explicit argument '%s'", opt.nameList(), explicit)}
			}
		} else if opt.pos {
			// The only positional is optional, so it never needs a value
			// taken from the following arguments.
			a.policy, a.hasPolicy = arg, true
			continue
		} else if !hasValue {
			if i+1 >= len(argv) || looksLikeOption(argv[i+1]) {
				return nil, &usageError{fmt.Sprintf(
					"argument %s: expected one argument", opt.nameList())}
			}
			i++
			explicit = argv[i]
		}

		p.apply(a, opt, explicit)
		if a.showHelp || a.showVersion {
			// argparse acts on --help/--version while parsing, before any
			// further validation.
			return a, nil
		}
	}

	if len(extras) > 0 {
		return nil, &usageError{"unrecognized arguments: " + strings.Join(extras, " ")}
	}
	return a, nil
}

// apply stores the parsed argument. Both flags and rule type options are
// boolean; rule type options additionally record their rule type.
func (p *parser) apply(a *args, opt *option, value string) {
	if opt.ruleType != 0 {
		switch opt.family {
		case "ter":
			a.tertypes = append(a.tertypes, opt.ruleType)
		case "rbac":
			a.rbacrtypes = append(a.rbacrtypes, opt.ruleType)
		case "mls":
			a.mlsrtypes = append(a.mlsrtypes, opt.ruleType)
		}
		return
	}
	if opt.isFlag() {
		switch opt.dest {
		case "help":
			a.showHelp = true
		case "version":
			a.showVersion = true
		case "verbose":
			a.verbose = true
		case "debug":
			a.debug = true
		case "A":
			// -A is --allow --allowxperm, as argparse extends the list after
			// parsing.
			a.tertypes = append(a.tertypes, sego.Allow, sego.AllowXPerm)
		default:
			a.flags[opt.dest] = true
		}
		return
	}
	a.values[opt.dest] = value
}

// match resolves an argument to an option. It reports a nil option when the
// argument is not an option at all, and a usage error when a long option is
// ambiguous. explicit is the value attached to the option string, as in
// --source=foo or -sfoo; hasValue reports whether one was attached.
func (p *parser) match(arg string) (opt *option, explicit string, hasValue bool, err error) {
	if o, ok := p.byName[arg]; ok {
		return o, "", false, nil
	}
	if !looksLikeOption(arg) {
		return nil, "", false, nil
	}
	// An option string followed by "=" carries its value explicitly.
	if name, value, found := strings.Cut(arg, "="); found {
		if o, ok := p.byName[name]; ok {
			return o, value, true, nil
		}
	}

	type candidate struct {
		opt      *option
		name     string
		explicit string
		hasValue bool
	}
	var candidates []candidate
	if strings.HasPrefix(arg, "--") {
		// A long option may be abbreviated as long as the prefix is
		// unambiguous.
		for _, name := range p.names {
			if strings.HasPrefix(name, arg) {
				candidates = append(candidates, candidate{p.byName[name], name, "", false})
			}
		}
	} else {
		// A short option may be followed directly by its value.
		if len(arg) > 2 {
			if o, ok := p.byName[arg[:2]]; ok {
				candidates = append(candidates, candidate{o, arg[:2], arg[2:], true})
			}
		}
		// An abbreviation may also be ambiguous, e.g. -e for -eb/-ep/-ex.
		for _, name := range p.names {
			if strings.HasPrefix(name, arg) {
				candidates = append(candidates, candidate{p.byName[name], name, "", false})
			}
		}
	}

	switch len(candidates) {
	case 0:
		return nil, "", false, nil
	case 1:
		c := candidates[0]
		return c.opt, c.explicit, c.hasValue, nil
	}
	names := make([]string, len(candidates))
	for i, c := range candidates {
		names[i] = c.name
	}
	return nil, "", false, &usageError{fmt.Sprintf(
		"ambiguous option: %s could match %s", arg, strings.Join(names, ", "))}
}

// negativeNumber is argparse's pattern for arguments that look like options
// but are meant to be negative numbers, and so are treated as values.
var negativeNumber = regexp.MustCompile(`^-\d+$|^-\d*\.\d+$`)

// looksLikeOption reports whether an argument is meant to be an option rather
// than a value or a positional argument. A single dash, a negative number and
// anything not starting with a dash are arguments.
func looksLikeOption(arg string) bool {
	if len(arg) < 2 || !strings.HasPrefix(arg, "-") || arg == "-" {
		return false
	}
	return !negativeNumber.MatchString(arg)
}

// validate applies the checks argparse performs after parsing.
func (a *args) validate() error {
	if len(a.tertypes) == 0 && len(a.rbacrtypes) == 0 && len(a.mlsrtypes) == 0 {
		return &usageError{"At least one rule type must be specified."}
	}
	if (a.value("perms") != "" || a.value("xperms") != "" || a.value("boolean") != "") &&
		(len(a.rbacrtypes) > 0 || len(a.mlsrtypes) > 0) {
		return &usageError{"-p/--perms, -x/--xperms, and -b/--bool options are only " +
			"supported with TE rule searches."}
	}
	return nil
}

// error writes the usage line and a usage error message to w, as argparse
// does, and returns the exit status.
func (p *parser) error(w io.Writer, err error) int {
	fmt.Fprint(w, p.usage())
	fmt.Fprintf(w, "%s: error: %s\n", p.prog, err)
	return 2
}

// usage renders the usage line, terminated by a newline.
func (p *parser) usage() string {
	var optionals, positionals []*option
	for i := range p.opts {
		if p.opts[i].pos {
			positionals = append(positionals, &p.opts[i])
		} else {
			optionals = append(optionals, &p.opts[i])
		}
	}

	optUsage := actionsUsage(optionals)
	posUsage := actionsUsage(positionals)
	prefix := "usage: "
	usage := p.prog
	if optUsage != "" {
		usage += " " + optUsage
	}
	if posUsage != "" {
		usage += " " + posUsage
	}

	textWidth := p.width
	if len(prefix)+len(usage) > textWidth {
		optParts := usageParts(optUsage)
		posParts := usageParts(posUsage)
		lines := p.wrapUsage(prefix, p.prog, optParts, posParts, textWidth)
		usage = strings.Join(lines, "\n")
	}
	return prefix + usage + "\n"
}

// wrapUsage wraps the usage line the way argparse's _format_usage does: the
// program name starts the first line, and options and positional arguments are
// wrapped independently so that a positional argument never shares the end of
// an option line unless it fits.
func (p *parser) wrapUsage(prefix, prog string, optParts, posParts []string, textWidth int) []string {
	// If the program name is short, follow it with the options; otherwise put
	// it on a line of its own.
	if len(prefix)+len(prog) <= int(0.75*float64(textWidth)) {
		indent := strings.Repeat(" ", len(prefix)+len(prog)+1)
		var lines []string
		if len(optParts) > 0 {
			lines = wrapParts(append([]string{prog}, optParts...), indent, prefix, textWidth)
			lines = append(lines, wrapParts(posParts, indent, "", textWidth)...)
		} else if len(posParts) > 0 {
			lines = wrapParts(append([]string{prog}, posParts...), indent, prefix, textWidth)
		} else {
			lines = []string{prog}
		}
		return lines
	}

	indent := strings.Repeat(" ", len(prefix))
	lines := wrapParts(append(append([]string{}, optParts...), posParts...), indent, "", textWidth)
	if len(lines) > 1 {
		lines = wrapParts(optParts, indent, "", textWidth)
		lines = append(lines, wrapParts(posParts, indent, "", textWidth)...)
	}
	return append([]string{prog}, lines...)
}

// wrapParts fills lines with parts, indenting every line, breaking before a
// part that does not fit. The first line is prefixed with prefix instead of
// the indent, again as argparse does.
func wrapParts(parts []string, indent, prefix string, textWidth int) []string {
	var lines []string
	var line []string
	lineLen := len(indent) - 1
	if prefix != "" {
		lineLen = len(prefix) - 1
	}
	for _, part := range parts {
		if lineLen+1+len(part) > textWidth && len(line) > 0 {
			lines = append(lines, indent+strings.Join(line, " "))
			line = nil
			lineLen = len(indent) - 1
		}
		line = append(line, part)
		lineLen += len(part) + 1
	}
	if len(line) > 0 {
		lines = append(lines, indent+strings.Join(line, " "))
	}
	if prefix != "" && len(lines) > 0 {
		lines[0] = lines[0][len(indent):]
	}
	return lines
}

// actionsUsage renders the usage text of a list of actions: the first option
// string of each action, followed by its value name, in brackets because every
// option is optional. The positional argument, itself optional, is rendered as
// [name] and comes last.
func actionsUsage(actions []*option) string {
	parts := make([]string, 0, len(actions))
	for _, o := range actions {
		var part string
		switch {
		case o.pos:
			part = o.dest
			if o.nargsOpt {
				part = "[" + part + "]"
			}
		case o.isFlag():
			part = o.names[0]
		default:
			part = o.names[0] + " " + o.metavar
		}
		if !o.pos {
			part = "[" + part + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// usageParts splits a usage string into the wrappable parts argparse matches:
// a bracketed or parenthesized group followed by whitespace, or a single
// non-space word. Such a group may contain spaces, e.g. "[-s SOURCE]".
func usageParts(s string) []string {
	var parts []string
	for i := 0; i < len(s); {
		if s[i] == ' ' {
			i++
			continue
		}
		if s[i] == '[' || s[i] == '(' {
			closer := byte(']')
			if s[i] == '(' {
				closer = ')'
			}
			if end := groupEnd(s, i, closer); end > i {
				parts = append(parts, s[i:end+1])
				i = end + 1
				continue
			}
		}
		j := i
		for j < len(s) && s[j] != ' ' {
			j++
		}
		parts = append(parts, s[i:j])
		i = j
	}
	return parts
}

// groupEnd returns the index of the closing bracket of the group starting at
// start, or -1 when the group is not terminated by whitespace.
func groupEnd(s string, start int, closer byte) int {
	for i := start + 1; i < len(s); i++ {
		if s[i] == closer && (i+1 == len(s) || s[i+1] == ' ') {
			return i
		}
	}
	return -1
}

// helpSection is one block of the help text: a heading and the options
// argparse prints underneath it, indented.
type helpSection struct {
	heading string
	actions []*option
}

// help renders the full --help text.
func (p *parser) help() string {
	var positional, optional []*option
	grouped := make(map[string][]*option)
	var groupOrder []string
	for i := range p.opts {
		o := &p.opts[i]
		switch {
		case o.pos:
			positional = append(positional, o)
		case o.group == "":
			optional = append(optional, o)
		default:
			if _, ok := grouped[o.group]; !ok {
				groupOrder = append(groupOrder, o.group)
			}
			grouped[o.group] = append(grouped[o.group], o)
		}
	}

	// argparse sizes the help column for the longest invocation of any action.
	actionMax := 0
	for i := range p.opts {
		if l := len(invocation(&p.opts[i])) + sectionIndent; l > actionMax {
			actionMax = l
		}
	}
	maxHelpPosition := min(24, max(p.width-20, 4))
	helpPosition := min(actionMax+2, maxHelpPosition)

	var b strings.Builder
	b.WriteString(p.usage())
	b.WriteString("\n")

	textWidth := max(p.width, 11)
	b.WriteString(fillText(description, textWidth))
	b.WriteString("\n\n")

	sections := []helpSection{
		{groupPositional, positional},
		{groupOptional, optional},
	}
	for _, heading := range groupOrder {
		sections = append(sections, helpSection{heading, grouped[heading]})
	}
	for _, section := range sections {
		if len(section.actions) == 0 {
			continue
		}
		b.WriteString("\n")
		b.WriteString(section.heading)
		b.WriteString(":\n")
		for _, o := range section.actions {
			b.WriteString(actionHelp(o, helpPosition, p.width))
		}
		b.WriteString("\n")
	}

	b.WriteString(fillText(epilog, textWidth))
	b.WriteString("\n\n")

	// argparse collapses runs of blank lines and trims the result.
	help := collapseBlankLines(b.String())
	return strings.Trim(help, "\n") + "\n"
}

// sectionIndent is the indentation argparse applies to the entries of a help
// section, which is also why the help column is measured from there.
const sectionIndent = 2

// actionHelp renders one help entry: the option invocation padded to the help
// column, or on a line of its own when the invocation is too long, followed by
// the wrapped help text.
func actionHelp(o *option, helpPosition, width int) string {
	helpWidth := max(width-helpPosition, 11)
	actionWidth := helpPosition - sectionIndent - 2

	indent := strings.Repeat(" ", sectionIndent)
	header := invocation(o)
	indentFirst := 0
	if len(header) <= actionWidth {
		header = header + strings.Repeat(" ", actionWidth-len(header)) + "  "
	} else {
		header += "\n"
		indentFirst = helpPosition
	}

	var b strings.Builder
	b.WriteString(indent)
	b.WriteString(header)
	lines := wrapText(o.help, helpWidth)
	b.WriteString(strings.Repeat(" ", indentFirst))
	b.WriteString(lines[0])
	b.WriteString("\n")
	for _, line := range lines[1:] {
		b.WriteString(strings.Repeat(" ", helpPosition))
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// invocation renders the ways an option can be spelled, e.g. "-s SOURCE,
// --source SOURCE" or "-v, --verbose".
func invocation(o *option) string {
	if o.pos {
		return o.dest
	}
	if o.isFlag() {
		return strings.Join(o.names, ", ")
	}
	parts := make([]string, len(o.names))
	for i, name := range o.names {
		parts[i] = name + " " + o.metavar
	}
	return strings.Join(parts, ", ")
}

// wrapText wraps text to width, collapsing whitespace, the way argparse's
// _split_lines does through textwrap.wrap.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := ""
	for _, word := range words {
		// Break a word too long for a line of its own, as textwrap does.
		for len(word) > width {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}
		if word == "" {
			continue
		}
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	return append(lines, line)
}

// fillText reflows text to width, the way argparse's _fill_text does for the
// description and the epilog. Both are rendered at the top level, so no indent
// is involved.
func fillText(text string, width int) string {
	return strings.Join(wrapText(text, width), "\n")
}

// collapseBlankLines replaces runs of two or more blank lines by a single
// blank line, mirroring argparse's \n\n\n+ substitution.
func collapseBlankLines(s string) string {
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return s
}

// terminalWidth returns the wrapping width argparse would use: the terminal
// width from the COLUMNS environment variable, minus the two columns it
// reserves, and 78 columns otherwise, which is what shutil.get_terminal_size
// falls back to when the output is not a terminal.
func terminalWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 2 {
			return n - 2
		}
	}
	return 80 - 2
}
