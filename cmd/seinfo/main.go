// Command seinfo reports the components of an SELinux binary kernel policy:
// statistics and the listings of symbols, rules and labeling statements the
// reference tool prints. It is the sego reimplementation of setools' seinfo
// and reproduces the reference tool's output, exit statuses and diagnostics.
//
// Usage errors (bad usage of the command line, invalid range criteria) are
// printed to stderr with the usage line, and exit with status 2. Runtime
// errors (a policy that cannot be opened, an invalid network) print only the
// error message, to stdout, and exit with status 1, exactly as the reference
// tool does.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	sego "github.com/elnx/sego"
	"github.com/elnx/sego/internal/argparse"
	"github.com/elnx/sego/policy"
)

// version is the version --version prints. Plain builds report "dev"; release
// builds inject the real version:
//
//	go build -ldflags "-X main.version=$(VERSION)" ./cmd/seinfo
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes seinfo with argv (argv[0] is the program name) and returns the
// process exit status.
func run(argv []string, stdout, stderr io.Writer) int {
	prog := "seinfo"
	if len(argv) > 0 {
		if base := filepath.Base(argv[0]); base != "" && base != "." {
			prog = base
		}
	}
	p := argparse.New(prog, description, epilog, optionTable())

	a, err := p.Parse(argv[1:])
	if err != nil {
		return p.Error(stderr, err)
	}
	if a.VersionRequested() {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if a.HelpRequested() {
		p.HelpTo(stdout)
		return 0
	}

	// The SELinux and Xen query groups are mutually exclusive; the check
	// happens before the policy is loaded, as in the reference tool.
	selArgs, xenArgs := groupArgs(a, groupSELinux, groupXen)
	if len(selArgs) > 0 && len(xenArgs) > 0 {
		return p.Error(stderr, argparse.NewUsageError(fmt.Sprintf(
			"SELinux arguments (%s) cannot be combined with Xen arguments (%s).",
			strings.Join(selArgs, ", "), strings.Join(xenArgs, ", "))))
	}

	// When no policy was named, a query option may have swallowed the policy
	// path: a value that exists as a file is moved back to the policy.
	if a.Value("policy") == "" {
		for _, dest := range componentDestOrder {
			if v := a.Value(dest); v != "" && v != constValue && fileExists(v) {
				a.SetConst(dest)
				a.SetValue("policy", v)
				break
			}
		}
	}

	out := bufio.NewWriter(stdout)
	err = seinfo(a, out, stderr, selArgs, xenArgs)
	out.Flush()
	if err != nil {
		var usage *usageError
		if errors.As(err, &usage) {
			return p.Error(stderr, argparse.NewUsageError(usage.msg))
		}
		if a.Flag("debug") {
			// The reference tool re-raises the exception under --debug: it
			// exits 1 with a traceback on stderr instead of the message on
			// stdout.
			fmt.Fprintf(stderr, "%s%s\n", debug.Stack(), err)
			return 1
		}
		fmt.Fprintln(out, err)
		out.Flush()
		return 1
	}
	return 0
}

// verbosef prints an informational message for -v/--verbose. The reference
// tool logs these through the logging module, which writes to stderr.
func verbosef(a *argparse.Args, stderr io.Writer, format string, args ...any) {
	if a.Flag("verbose") || a.Flag("debug") {
		fmt.Fprintf(stderr, format+"\n", args...)
	}
}

// seinfo loads the policy and prints the statistics block and every selected
// component section.
func seinfo(a *argparse.Args, out, stderr io.Writer, selArgs, xenArgs []string) error {
	path := a.Value("policy")
	if path == "" {
		verbosef(a, stderr, "Attempting to locate current running policy.")
		found, err := sego.FindPolicyPath()
		if err != nil {
			return err
		}
		path = found
	}
	verbosef(a, stderr, "Opening SELinux policy %q", path)
	pol, err := sego.Open(path)
	if err != nil {
		return err
	}
	verbosef(a, stderr, "Successfully opened SELinux policy %q", path)

	// A query group that does not match the policy's target platform is a
	// runtime error, as in the reference tool.
	isXen := pol.DB().Target == policy.TargetXen
	if !isXen && len(xenArgs) > 0 {
		return fmt.Errorf("error: Xen queries specified (%s), but %s is an SELinux policy.",
			strings.Join(xenArgs, ", "), pol.Path())
	}
	if isXen && len(selArgs) > 0 {
		return fmt.Errorf("error: SELinux queries specified (%s), but %s is a Xen policy.",
			strings.Join(selArgs, ", "), pol.Path())
	}

	components, err := buildComponents(a, pol, isXen)
	if err != nil {
		return err
	}

	// The statistics block is printed when no component was selected or
	// --all was given, and never with --flat.
	if (len(components) == 0 || a.Flag("all")) && !a.Flag("flat") {
		writeStats(out, pol)
	}

	for _, c := range components {
		if !a.Flag("flat") {
			fmt.Fprintf(out, "\n%s: %d\n", c.desc, len(c.items))
		}
		for _, item := range c.items {
			if a.Flag("flat") {
				fmt.Fprintln(out, item)
			} else {
				fmt.Fprintln(out, "   "+item)
			}
		}
	}
	return nil
}

// component is one output block: its header text and the rendered lines.
type component struct {
	desc  string
	items []string
}

// render returns the text of one item: the statement with --expand, the name
// otherwise, as setools' PolicySymbol and PolicyObject str() do.
func render(expand bool, name, statement string) string {
	if expand {
		return statement
	}
	return name
}

// buildComponents assembles the selected sections in the fixed order of the
// reference tool.
func buildComponents(a *argparse.Args, pol *sego.Policy, isXen bool) ([]component, error) {
	all := a.Flag("all")
	expand := a.Flag("expand")
	var out []component

	// A bare query option stores the constant "True"; a valued one stores
	// the filter text. selected reports whether the option was given (or
	// --all was given), and returns its filter name ("" when every
	// component is wanted).
	selected := func(dest string) (string, bool) {
		v := a.Value(dest)
		if v == "" {
			return "", all
		}
		if v == constValue {
			return "", true
		}
		return v, true
	}

	if v, on := selected("boolquery"); on {
		out = append(out, component{"Booleans", renderSymbols(expand, v, pol.Booleans(),
			func(b *sego.Boolean) (string, string) { return b.Name, b.Statement() })})
	}

	if v, on := selected("mlscatsquery"); on {
		// Categories keep their declaration order, whatever the filter is.
		items := renderSymbolsKeepOrder(expand, v, pol.Categories(),
			func(c *sego.Category) (string, string) { return c.Name, c.Statement() },
			func(c *sego.Category) []string { return c.Aliases() })
		out = append(out, component{"Categories", items})
	}

	if v, on := selected("classquery"); on {
		out = append(out, component{"Classes", renderSymbols(expand, v, pol.Classes(),
			func(c *sego.Class) (string, string) { return c.Name, c.Statement() })})
	}

	if v, on := selected("commonquery"); on {
		out = append(out, component{"Commons", renderSymbols(expand, v, pol.Commons(),
			func(c *sego.Common) (string, string) { return c.Name, c.Statement() })})
	}

	if v, on := selected("constraintquery"); on {
		var items []string
		for _, c := range pol.Constraints() {
			if v == "" || c.Class.Name == v {
				items = append(items, c.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Constraints", items})
	}

	if v, on := selected("defaultquery"); on {
		var items []string
		for _, d := range pol.Defaults() {
			if v == "" || d.Class.Name == v {
				items = append(items, d.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Default rules", items})
	}

	if v, on := selected("permissivequery"); on {
		out = append(out, component{"Permissive Types", renderSymbols(expand, v, pol.PermissiveTypes(),
			func(t *sego.Type) (string, string) { return t.Name, t.Statement() })})
	}

	if v, on := selected("polcapquery"); on {
		out = append(out, component{"Polcap", renderSymbols(expand, v, pol.PolicyCaps(),
			func(c sego.PolicyCap) (string, string) { return c.Name, c.Statement() })})
	}

	if v, on := selected("rolequery"); on {
		out = append(out, component{"Roles", renderSymbols(expand, v, pol.Roles(),
			func(r *sego.Role) (string, string) { return r.Name, r.Statement() })})
	}

	if v := a.Value("roletypesquery"); v != "" {
		var items []string
		for _, r := range pol.Roles() {
			for _, t := range r.Types() {
				if t.Name == v {
					items = append(items, render(expand, r.Name, r.Statement()))
					break
				}
			}
		}
		sortStrings(items)
		out = append(out, component{"Roles", items})
	}

	if v, on := selected("mlssensquery"); on {
		items := renderSymbolsKeepOrder(expand, v, pol.Sensitivities(),
			func(s *sego.Sensitivity) (string, string) { return s.Name, s.Statement() },
			func(s *sego.Sensitivity) []string { return s.Aliases() })
		out = append(out, component{"Sensitivities", items})
	}

	if v, on := selected("typeboundsquery"); on {
		var items []string
		for _, b := range pol.TypeBounds() {
			if v == "" || b.Child.Name == v {
				items = append(items, b.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Typebounds", items})
	}

	if v, on := selected("typequery"); on {
		// The types section lists concrete types only; the attributes have
		// their own section.
		var types []*sego.Type
		for _, t := range pol.Types() {
			if !t.IsAttribute {
				types = append(types, t)
			}
		}
		out = append(out, component{"Types", renderAliases(expand, v, types,
			func(t *sego.Type) (string, []string, string) { return t.Name, t.Aliases(), t.Statement() })})
	}

	if v, on := selected("typeattrquery"); on {
		var items []string
		for _, t := range pol.TypeAttributes() {
			if matchName(t.Name, v) {
				if expand {
					items = append(items, expandAttribute(t))
				} else {
					items = append(items, t.Name)
				}
			}
		}
		sortStrings(items)
		out = append(out, component{"Type Attributes", items})
	}

	if v, on := selected("userquery"); on {
		out = append(out, component{"Users", renderSymbols(expand, v, pol.Users(),
			func(u *sego.User) (string, string) { return u.Name, u.Statement() })})
	}

	if v, on := selected("validatetransquery"); on {
		var items []string
		for _, c := range pol.Validatetrans() {
			if v == "" || c.Class.Name == v {
				items = append(items, c.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Validatetrans", items})
	}

	if !isXen {
		components, err := selinuxComponents(a, pol, expand)
		if err != nil {
			return nil, err
		}
		out = append(out, components...)
	} else {
		components, err := xenComponents(a, pol)
		if err != nil {
			return nil, err
		}
		out = append(out, components...)
	}
	return out, nil
}

// selinuxComponents builds the SELinux-specific labeling statement sections.
func selinuxComponents(a *argparse.Args, pol *sego.Policy, expand bool) ([]component, error) {
	var out []component
	all := a.Flag("all")

	selected := func(dest string) (string, bool) {
		v := a.Value(dest)
		if v == "" {
			return "", all
		}
		if v == constValue {
			return "", true
		}
		return v, true
	}

	if v, on := selected("fsusequery"); on {
		var items []string
		for _, f := range pol.FSUses() {
			if v == "" || f.FSType == v {
				items = append(items, f.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Fs_use", items})
	}

	if v, on := selected("genfsconquery"); on {
		var items []string
		for _, g := range pol.Genfscons() {
			if v == "" || g.FSType == v {
				items = append(items, g.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Genfscon", items})
	}

	if v, on := selected("ibendportconquery"); on {
		var items []string
		for _, i := range pol.Ibendportcons() {
			if v == "" || i.DeviceName == v {
				items = append(items, i.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Ibendportcon", items})
	}

	if v, on := selected("ibpkeyconquery"); on {
		var low, high uint16
		if v != "" {
			lo, hi, err := parseHexRange16(v)
			if err != nil {
				return nil, err
			}
			low, high = lo, hi
		}
		var items []string
		for _, i := range pol.Ibpkeycons() {
			if v != "" && (i.LowPKey != low || i.HighPKey != high) {
				continue
			}
			items = append(items, i.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Ibpkeycon", items})
	}

	if v, on := selected("initialsidquery"); on {
		var items []string
		for _, s := range pol.InitialSIDs() {
			if v == "" || s.Name == v {
				// The initial SID is one of the few objects whose plain
				// rendering is its name, not its statement.
				items = append(items, render(expand, s.Name, s.Statement()))
			}
		}
		sortStrings(items)
		out = append(out, component{"Initial SIDs", items})
	}

	if v, on := selected("netifconquery"); on {
		var items []string
		for _, n := range pol.Netifcons() {
			if v == "" || n.Device == v {
				items = append(items, n.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Netifcon", items})
	}

	if v, on := selected("nodeconquery"); on {
		crit, err := parseIPNetwork(v)
		if err != nil {
			return nil, err
		}
		var items []string
		for _, n := range pol.Nodecons() {
			if crit != nil {
				addr, mask := n.AddrStrings()
				if !crit.matches(addr, mask) {
					continue
				}
			}
			items = append(items, n.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Nodecon", items})
	}

	if v, on := selected("portconquery"); on {
		var low, high uint16
		if v != "" {
			lo, hi, err := parseDecRange16(v)
			if err != nil {
				return nil, err
			}
			low, high = lo, hi
		}
		var items []string
		for _, pc := range pol.Portcons() {
			// The portcon query matches when the criteria range is contained
			// in the statement's range (ports_subset in the reference).
			if v != "" && !(pc.LowPort <= low && high <= pc.HighPort) {
				continue
			}
			items = append(items, pc.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Portcon", items})
	}

	return out, nil
}

// xenComponents builds the Xen-specific labeling statement sections.
func xenComponents(a *argparse.Args, pol *sego.Policy) ([]component, error) {
	var out []component
	all := a.Flag("all")

	selected := func(dest string) (string, bool) {
		v := a.Value(dest)
		if v == "" {
			return "", all
		}
		if v == constValue {
			return "", true
		}
		return v, true
	}

	if v, on := selected("devicetreeconquery"); on {
		var items []string
		for _, d := range pol.XenDeviceTreecons() {
			if v == "" || d.Path == v {
				items = append(items, d.Statement())
			}
		}
		sortStrings(items)
		out = append(out, component{"Devicetreecon", items})
	}

	if v, on := selected("iomemconquery"); on {
		var low, high uint64
		if v != "" {
			lo, hi, err := parseHexRange64(v)
			if err != nil {
				return nil, err
			}
			low, high = lo, hi
		}
		var items []string
		for _, m := range pol.XenIOMemcons() {
			if v != "" && (m.Low != low || m.High != high) {
				continue
			}
			items = append(items, m.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Iomemcon", items})
	}

	if v, on := selected("ioportconquery"); on {
		var low, high uint32
		if v != "" {
			lo, hi, err := parseHexRange32(v)
			if err != nil {
				return nil, err
			}
			low, high = lo, hi
		}
		var items []string
		for _, o := range pol.XenIOPortcons() {
			// Like portcon, the ioportcon query uses subset matching.
			if v != "" && !(o.Low <= low && high <= o.High) {
				continue
			}
			items = append(items, o.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Ioportcon", items})
	}

	if v, on := selected("pcideviceconquery"); on {
		var device uint32
		if v != "" {
			n, err := parseHex32(v)
			if err != nil {
				return nil, err
			}
			device = n
		}
		var items []string
		for _, d := range pol.XenPCIDevicecons() {
			if v != "" && d.Device != device {
				continue
			}
			items = append(items, d.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Pcidevicecon", items})
	}

	if v, on := selected("pirqconquery"); on {
		var irq uint16
		if v != "" {
			n, err := parseDec(v)
			if err != nil {
				return nil, err
			}
			irq = uint16(n)
		}
		var items []string
		for _, q := range pol.XenPirqcons() {
			if v != "" && q.IRQ != irq {
				continue
			}
			items = append(items, q.Statement())
		}
		sortStrings(items)
		out = append(out, component{"Pirqcon", items})
	}

	return out, nil
}
