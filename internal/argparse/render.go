package argparse

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Usage renders the usage line, terminated by a newline.
func (p *Parser) Usage() string {
	var optionals, positionals []*Option
	for i := range p.opts {
		if p.opts[i].Pos {
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
func (p *Parser) wrapUsage(prefix, prog string, optParts, posParts []string, textWidth int) []string {
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
// option is optional. Positional arguments come last: a plain one is rendered
// as its name, an optional one (nargs='?') as [name] and a many one
// (nargs='*') as [name ...].
func actionsUsage(actions []*Option) string {
	parts := make([]string, 0, len(actions))
	for _, o := range actions {
		var part string
		switch {
		case o.Pos:
			part = o.destUsage()
		case o.isFlag():
			part = o.Names[0]
		default:
			if o.nargsOpt() {
				part = o.Names[0] + " [" + o.Metavar + "]"
			} else {
				part = o.Names[0] + " " + o.Metavar
			}
		}
		if !o.Pos && !o.Required {
			part = "[" + part + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// destUsage renders a positional argument in the usage line.
func (o *Option) destUsage() string {
	switch o.Nargs {
	case "?":
		return "[" + o.Dest + "]"
	case "*":
		return "[" + o.Dest + " ...]"
	default:
		return o.Dest
	}
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
	actions []*Option
}

// Help renders the full --help text.
func (p *Parser) Help() string {
	var positional, optional []*Option
	grouped := make(map[string][]*Option)
	var groupOrder []string
	for i := range p.opts {
		o := &p.opts[i]
		switch {
		case o.Pos:
			positional = append(positional, o)
		case o.Group == "":
			optional = append(optional, o)
		default:
			if _, ok := grouped[o.Group]; !ok {
				groupOrder = append(groupOrder, o.Group)
			}
			grouped[o.Group] = append(grouped[o.Group], o)
		}
	}

	// argparse sizes the help column for the longest invocation of any action.
	actionMax := 0
	for i := range p.opts {
		if l := len(p.opts[i].invocation()) + sectionIndent; l > actionMax {
			actionMax = l
		}
	}
	maxHelpPosition := min(24, max(p.width-20, 4))
	helpPosition := min(actionMax+2, maxHelpPosition)

	var b strings.Builder
	b.WriteString(p.Usage())
	b.WriteString("\n")

	textWidth := max(p.width, 11)
	b.WriteString(fillText(p.description, textWidth))
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

	if p.epilog != "" {
		b.WriteString(fillText(p.epilog, textWidth))
		b.WriteString("\n\n")
	}

	// argparse collapses runs of blank lines and trims the result.
	help := collapseBlankLines(b.String())
	return strings.Trim(help, "\n") + "\n"
}

// Help prints the --help text to w.
func (p *Parser) HelpTo(w io.Writer) {
	fmt.Fprint(w, p.Help())
}

// Argument group headings, in the order argparse prints them. "options" is the
// heading modern argparse uses; Python 3.9 and older said "optional arguments".
const (
	groupPositional = "positional arguments"
	groupOptional   = "options"
)

// sectionIndent is the indentation argparse applies to the entries of a help
// section, which is also why the help column is measured from there.
const sectionIndent = 2

// actionHelp renders one help entry: the option invocation padded to the help
// column, or on a line of its own when the invocation is too long, followed by
// the wrapped help text.
func actionHelp(o *Option, helpPosition, width int) string {
	helpWidth := max(width-helpPosition, 11)
	actionWidth := helpPosition - sectionIndent - 2

	indent := strings.Repeat(" ", sectionIndent)
	header := o.invocation()
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
	lines := wrapText(o.Help, helpWidth)
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
