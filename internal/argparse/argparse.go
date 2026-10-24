// Package argparse is a hand-rolled reimplementation of the parts of Python's
// argparse that the sego tools exercise.
//
// The tools have to reproduce the reference CLIs byte for byte: the usage
// line, the grouped and wrapped --help output, the wording of every usage
// error and the split between usage errors (exit 2) and runtime errors
// (exit 1). No Go flag package formats or groups options that way, so the
// parser is written against argparse's behavior instead: option abbreviation
// with ambiguity detection, --opt=value, short options with attached values,
// optional-value options (nargs='?'), positional argument assignment,
// required-argument reporting, int conversion and the exact help layout.
//
// The wrapping and column layout follow argparse's HelpFormatter so that the
// output matches the reference tool at any terminal width.
package argparse

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Option is a single command line option or positional argument. It carries
// everything the parser, the usage line and the help text need, mirroring the
// argparse Action attributes that affect them.
type Option struct {
	Names    []string // option strings; the first is used in the usage line
	Metavar  string   // value name; empty for options that take no value
	Dest     string   // key the parsed value is stored under; positional name
	Help     string   // one line help text
	Group    string   // argument group heading
	Pos      bool     // positional argument
	Nargs    string   // "", "?" or "*": positional arity; "?" also allows an option value to be omitted
	Required bool     // the argument must be given (argparse required=True)
	Default  string   // value reported when the option was not given
	Int      bool     // type=int: the value is parsed as an integer
	Version  bool     // action="version": print the version and stop
}

// isFlag reports whether the option takes no value.
func (o *Option) isFlag() bool { return !o.Pos && o.Metavar == "" }

// nameList renders the option strings the way argparse names an argument in an
// error message, e.g. "-s/--source".
func (o *Option) nameList() string { return strings.Join(o.Names, "/") }

// invocation renders the ways an option can be spelled, e.g. "-s SOURCE,
// --source SOURCE", "-a [ATTR], --attribute [ATTR]" or "-v, --verbose".
func (o *Option) invocation() string {
	if o.Pos {
		return o.Dest
	}
	if o.isFlag() {
		return strings.Join(o.Names, ", ")
	}
	parts := make([]string, len(o.Names))
	for i, name := range o.Names {
		if o.nargsOpt() {
			parts[i] = name + " [" + o.Metavar + "]"
		} else {
			parts[i] = name + " " + o.Metavar
		}
	}
	return strings.Join(parts, ", ")
}

// nargsOpt reports whether a value may be omitted (nargs='?').
func (o *Option) nargsOpt() bool { return o.Nargs == "?" }

// args are the parsed command line.
type Args struct {
	showHelp    bool
	showVersion bool

	flags    map[string]bool
	values   map[string]string
	lists    map[string][]string
	position map[string]bool // dest -> the argument was given at all
}

// Flag returns whether a flag option was given.
func (a *Args) Flag(dest string) bool { return a.flags[dest] }

// Value returns the value of a value-taking option, its default, or "".
func (a *Args) Value(dest string) string {
	if v, ok := a.values[dest]; ok {
		return v
	}
	return ""
}

// Int returns the value of an int option parsed from Value. The parser has
// already validated the syntax for values it parsed; a missing option yields
// 0.
func (a *Args) Int(dest string) int {
	n, err := strconv.Atoi(a.Value(dest))
	if err != nil {
		return 0
	}
	return n
}

// List returns the values collected by a positional declared with nargs="*".
func (a *Args) List(dest string) []string { return a.lists[dest] }

// Given reports whether the option or positional was given at all (with or
// without a value).
func (a *Args) Given(dest string) bool { return a.position[dest] }

// SetValue records a value for an option after parsing, as if it had been
// given on the command line.
func (a *Args) SetValue(dest, value string) {
	a.position[dest] = true
	a.values[dest] = value
}

// SetConst records a bare option occurrence (nargs='?', const=True).
func (a *Args) SetConst(dest string) {
	a.position[dest] = true
	a.flags[dest] = true
	a.values[dest] = "True"
}

// HelpRequested reports whether --help was given. argparse acts on --help
// while parsing, so the caller must check this before any other validation.
func (a *Args) HelpRequested() bool { return a.showHelp }

// VersionRequested reports whether --version was given.
func (a *Args) VersionRequested() bool { return a.showVersion }

// UsageError is a command line error: it makes the tool print the usage line
// followed by an error message on stderr and exit with status 2.
type UsageError struct{ msg string }

// NewUsageError builds a usage error with a message of the caller's choosing.
func NewUsageError(msg string) error { return &UsageError{msg} }

func (e *UsageError) Error() string { return e.msg }

// Parser parses a command line and renders the usage and help text.
type Parser struct {
	prog        string
	description string
	epilog      string
	width       int // wrapping width, as argparse derives it from the terminal
	opts        []Option

	byName      map[string]*Option // exact option string lookup
	names       []string           // every option string, in registration order
	positionals []*Option
}

// New returns a parser for the program named prog. description and epilog are
// rendered above and below the option list in --help.
func New(prog, description, epilog string, opts []Option) *Parser {
	p := &Parser{prog: prog, description: description, epilog: epilog, opts: opts,
		width: terminalWidth(), byName: make(map[string]*Option)}
	for i := range p.opts {
		o := &p.opts[i]
		if o.Pos {
			p.positionals = append(p.positionals, o)
		}
		for _, name := range o.Names {
			p.byName[name] = o
			p.names = append(p.names, name)
		}
	}
	return p
}

// Parse parses argv (without the program name). A non-nil error is always a
// usage error.
func (p *Parser) Parse(argv []string) (*Args, error) {
	a := &Args{flags: make(map[string]bool), values: make(map[string]string),
		lists: make(map[string][]string), position: make(map[string]bool)}
	// Defaults are reported by Value but do not count as given.
	for i := range p.opts {
		if o := &p.opts[i]; !o.Pos && o.Default != "" {
			a.values[o.Dest] = o.Default
		}
	}
	var extras []string
	var positionalArgs []string
	posIndex := 0
	onlyPositionals := false

	// assignChunk matches a run of positional arguments against the
	// remaining positional options, the way argparse matches each
	// positional chunk it encounters.
	assignChunk := func(chunk []string) {
		rest := chunk
		for posIndex < len(p.positionals) && len(rest) > 0 {
			o := p.positionals[posIndex]
			switch o.Nargs {
			case "*":
				a.position[o.Dest] = true
				a.lists[o.Dest] = append(a.lists[o.Dest], rest...)
				rest = nil
				posIndex++
			case "?":
				a.position[o.Dest] = true
				a.values[o.Dest] = rest[0]
				rest = rest[1:]
				posIndex++
			default:
				a.position[o.Dest] = true
				a.values[o.Dest] = rest[0]
				rest = rest[1:]
				posIndex++
			}
		}
		extras = append(extras, rest...)
	}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if onlyPositionals {
			positionalArgs = append(positionalArgs, arg)
			continue
		}
		if arg == "--" {
			// argparse treats the first -- as a separator between options
			// and positional arguments.
			onlyPositionals = true
			continue
		}

		opt, explicit, hasValue, err := p.match(arg)
		if err != nil {
			return nil, err
		}
		if opt == nil {
			// A positional argument, or an unrecognized option.
			if !looksLikeOption(arg) {
				// Collect this positional chunk and assign it, so that a
				// later chunk cannot fill a positional that has already
				// been matched (argparse's chunked matching).
				chunk := []string{arg}
				for i+1 < len(argv) && !looksLikeOption(argv[i+1]) && argv[i+1] != "--" {
					i++
					chunk = append(chunk, argv[i])
				}
				assignChunk(chunk)
			} else {
				extras = append(extras, arg)
			}
			continue
		}

		if opt.isFlag() {
			if hasValue {
				return nil, &UsageError{fmt.Sprintf(
					"argument %s: ignored explicit argument '%s'", opt.nameList(), explicit)}
			}
			a.position[opt.Dest] = true
			switch {
			case opt.Version:
				a.showVersion = true
			case opt.Dest == "help":
				a.showHelp = true
			default:
				a.flags[opt.Dest] = true
			}
		} else if opt.Pos {
			positionalArgs = append(positionalArgs, arg)
		} else if opt.nargsOpt() {
			// An optional value: the value is the next argument unless it
			// looks like an option, or a value was attached with =.
			if hasValue {
				if err := a.store(p, opt, explicit); err != nil {
					return nil, err
				}
			} else if i+1 < len(argv) && !looksLikeOption(argv[i+1]) {
				i++
				if err := a.store(p, opt, argv[i]); err != nil {
					return nil, err
				}
			} else {
				// Bare: store the const value, which argparse spells True.
				a.position[opt.Dest] = true
				a.flags[opt.Dest] = true
				a.values[opt.Dest] = "True"
			}
		} else {
			if !hasValue {
				if i+1 >= len(argv) || looksLikeOption(argv[i+1]) {
					return nil, &UsageError{fmt.Sprintf(
						"argument %s: expected one argument", opt.nameList())}
				}
				i++
				explicit = argv[i]
			}
			if err := a.store(p, opt, explicit); err != nil {
				return nil, err
			}
		}

		if a.showHelp || a.showVersion {
			// argparse acts on --help/--version while parsing, before any
			// further validation.
			return a, nil
		}
	}

	// Assign a trailing positional chunk (the arguments after --).
	if len(positionalArgs) > 0 {
		assignChunk(positionalArgs)
	}

	// Positional options that are required but never given.
	var missing []string
	for _, o := range p.positionals {
		if o.Nargs == "" && o.Dest != "" && !a.position[o.Dest] {
			missing = append(missing, o.Dest)
		}
	}

	// Required options that were never given.
	for i := range p.opts {
		o := &p.opts[i]
		if !o.Required || o.Pos || a.position[o.Dest] {
			continue
		}
		missing = append(missing, o.nameList())
	}
	if len(missing) > 0 {
		return nil, &UsageError{"the following arguments are required: " + strings.Join(missing, ", ")}
	}

	if len(extras) > 0 {
		return nil, &UsageError{"unrecognized arguments: " + strings.Join(extras, " ")}
	}
	return a, nil
}

// store records a value option, converting ints.
func (a *Args) store(p *Parser, opt *Option, value string) error {
	if opt.Int {
		if _, err := strconv.Atoi(value); err != nil {
			return &UsageError{fmt.Sprintf(
				"argument %s: invalid int value: '%s'", opt.nameList(), value)}
		}
	}
	a.position[opt.Dest] = true
	a.values[opt.Dest] = value
	return nil
}

// match resolves an argument to an option. It reports a nil option when the
// argument is not an option at all, and a usage error when a long option is
// ambiguous. explicit is the value attached to the option string, as in
// --source=foo or -sfoo; hasValue reports whether one was attached.
func (p *Parser) match(arg string) (opt *Option, explicit string, hasValue bool, err error) {
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
		opt      *Option
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
	return nil, "", false, &UsageError{fmt.Sprintf(
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

// Error writes the usage line and a usage error message to w, as argparse
// does, and returns the exit status.
func (p *Parser) Error(w io.Writer, err error) int {
	fmt.Fprint(w, p.Usage())
	fmt.Fprintf(w, "%s: error: %s\n", p.prog, err)
	return 2
}
