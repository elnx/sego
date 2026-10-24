package sego

// Domain transition analysis, mirroring setools' dta module: a domain
// transition graph is built from the allow and type_transition rules, edges
// are validated against the entrypoint requirements, and paths or single
// transitions are enumerated with networkx' traversal orderings.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// DomainEntrypoint is the entrypoint data of one domain transition edge.
type DomainEntrypoint struct {
	Name           string
	Entrypoint     []Rule
	Execute        []Rule
	TypeTransition []Rule
}

// DomainTransition is one step of a domain transition path, or one transition
// in the single transition modes.
type DomainTransition struct {
	Source string
	Target string

	Transition    []Rule
	Setexec       []Rule
	Dyntransition []Rule
	Setcurrent    []Rule
	Entrypoints   []DomainEntrypoint
}

// DomainTransitionAnalysis builds the domain transition graph of a policy.
type DomainTransitionAnalysis struct {
	policy *Policy

	reverse bool
	exclude []string

	graph   *DiGraph
	attrs   map[graphEdge]*dtaEdge
	sub     *DiGraph
	subAttr map[graphEdge]*dtaEdge

	logf func(format string, args ...any)
}

// SetLogger sets the informational log sink used by -v/--verbose.
func (a *DomainTransitionAnalysis) SetLogger(logf func(string, ...any)) { a.logf = logf }

// log emits an informational message when a logger is set.
func (a *DomainTransitionAnalysis) log(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
	}
}

// dtaEdge is the rule data of one graph edge.
type dtaEdge struct {
	transition     []Rule
	setexec        []Rule
	dyntransition  []Rule
	setcurrent     []Rule
	entrypoint     map[string][]Rule
	execute        map[string][]Rule
	typeTransition map[string][]Rule
}

// NewDomainTransitionAnalysis returns the analysis for the policy, with the
// given excluded types. Unknown excluded types are reported as errors.
func NewDomainTransitionAnalysis(policy *Policy, exclude []string) (*DomainTransitionAnalysis, error) {
	a := &DomainTransitionAnalysis{policy: policy}
	for _, name := range exclude {
		if _, err := policy.LookupType(name); err != nil {
			return nil, err
		}
		a.exclude = append(a.exclude, name)
	}
	// The graph is built on first use, after the caller attached its logger.
	return a, nil
}

// fullGraph returns the full graph, building it first if needed.
func (a *DomainTransitionAnalysis) fullGraph() *DiGraph {
	if a.graph == nil {
		a.buildGraph()
	}
	return a.graph
}

// SetReverse selects the reverse analysis (transitions into the target).
func (a *DomainTransitionAnalysis) SetReverse(reverse bool) { a.reverse = reverse }

// buildGraph builds the validated domain transition graph.
func (a *DomainTransitionAnalysis) buildGraph() {
	a.log("Building domain transition graph from %s...", a.policy.Path())
	a.graph = NewDiGraph()
	a.attrs = make(map[graphEdge]*dtaEdge)

	setexec := make(map[string][]Rule)
	setcurrent := make(map[string][]Rule)
	execute := make(map[string]map[string][]Rule)
	entrypoint := make(map[string]map[string][]Rule)
	typeTrans := make(map[string]map[string]map[string][]Rule)

	appendNested := func(m map[string]map[string][]Rule, x, y string) {
		if m[x] == nil {
			m[x] = make(map[string][]Rule)
		}
		_ = y
	}
	for _, rule := range a.policy.TERules() {
		switch r := rule.(type) {
		case *AVRule:
			if r.Kind() != Allow {
				continue
			}
			switch r.Class.Name {
			case "process":
				if hasPerm(r.Perms, "transition") {
					for _, s := range r.Source.Expand() {
						for _, t := range r.Target.Expand() {
							if s.Name == t.Name {
								continue
							}
							e := a.edge(s.Name, t.Name, true)
							e.transition = append(e.transition, rule)
						}
					}
				}
				if hasPerm(r.Perms, "dyntransition") {
					for _, s := range r.Source.Expand() {
						for _, t := range r.Target.Expand() {
							if s.Name == t.Name {
								continue
							}
							e := a.edge(s.Name, t.Name, true)
							e.dyntransition = append(e.dyntransition, rule)
						}
					}
				}
				if hasPerm(r.Perms, "setexec") {
					for _, s := range r.Source.Expand() {
						setexec[s.Name] = append(setexec[s.Name], rule)
					}
				}
				if hasPerm(r.Perms, "setcurrent") {
					for _, s := range r.Source.Expand() {
						setcurrent[s.Name] = append(setcurrent[s.Name], rule)
					}
				}
			case "file":
				if hasPerm(r.Perms, "execute") {
					for _, s := range r.Source.Expand() {
						appendNested(execute, s.Name, "")
						for _, t := range r.Target.Expand() {
							execute[s.Name][t.Name] = append(execute[s.Name][t.Name], rule)
						}
					}
				}
				if hasPerm(r.Perms, "entrypoint") {
					for _, s := range r.Source.Expand() {
						appendNested(entrypoint, s.Name, "")
						for _, t := range r.Target.Expand() {
							entrypoint[s.Name][t.Name] = append(entrypoint[s.Name][t.Name], rule)
						}
					}
				}
			}
		case *TERule:
			if r.Kind() != TypeTransition || r.Class.Name != "process" {
				continue
			}
			d := r.Default.Name
			for _, s := range r.Source.Expand() {
				if typeTrans[s.Name] == nil {
					typeTrans[s.Name] = make(map[string]map[string][]Rule)
				}
				for _, t := range r.Target.Expand() {
					if typeTrans[s.Name][t.Name] == nil {
						typeTrans[s.Name][t.Name] = make(map[string][]Rule)
					}
					typeTrans[s.Name][t.Name][d] = append(typeTrans[s.Name][t.Name][d], rule)
				}
			}
		}
	}

	var invalid, clearTransition, clearDyntransition []graphEdge
	for _, e := range a.graph.Edges() {
		attr := a.attrs[e]
		invalidTrans, invalidDyntrans := false, false

		if len(attr.transition) > 0 {
			entry := ruleKeys(entrypoint[e.target])
			exe := ruleKeys(execute[e.source])
			match := stringIntersection(entry, exe)
			if len(match) == 0 {
				invalidTrans = true
			} else {
				for _, m := range match {
					if _, ok := setexec[e.source]; ok || len(typeTrans[e.source][m]) > 0 {
						attr.entrypoint[m] = append(attr.entrypoint[m], entrypoint[e.target][m]...)
						attr.execute[m] = append(attr.execute[m], execute[e.source][m]...)
					}
					if len(typeTrans[e.source][m][e.target]) > 0 {
						attr.typeTransition[m] = append(attr.typeTransition[m],
							typeTrans[e.source][m][e.target]...)
					}
				}
				if rules, ok := setexec[e.source]; ok {
					attr.setexec = append(attr.setexec, rules...)
				}
				if len(attr.setexec) == 0 && len(attr.typeTransition) == 0 {
					invalidTrans = true
				}
			}
		} else {
			invalidTrans = true
		}

		if len(attr.dyntransition) > 0 {
			if rules, ok := setcurrent[e.source]; ok {
				attr.setcurrent = append(attr.setcurrent, rules...)
			} else {
				invalidDyntrans = true
			}
		} else {
			invalidDyntrans = true
		}

		switch {
		case invalidTrans && invalidDyntrans:
			invalid = append(invalid, e)
		case invalidTrans:
			clearTransition = append(clearTransition, e)
		case invalidDyntrans:
			clearDyntransition = append(clearDyntransition, e)
		}
	}

	for _, e := range invalid {
		a.graph.RemoveEdge(e.source, e.target)
		delete(a.attrs, e)
	}
	for _, e := range clearTransition {
		attr := a.attrs[e]
		attr.transition = nil
		attr.execute = nil
		attr.entrypoint = nil
		attr.typeTransition = nil
		attr.setexec = nil
	}
	for _, e := range clearDyntransition {
		attr := a.attrs[e]
		attr.dyntransition = nil
		attr.setcurrent = nil
	}
	a.log("Completed building domain transition graph.")
}

// edge returns the attribute record of an edge, creating the edge when create
// is set.
func (a *DomainTransitionAnalysis) edge(source, target string, create bool) *dtaEdge {
	e := graphEdge{source, target}
	if attr, ok := a.attrs[e]; ok {
		return attr
	}
	if !create {
		return &dtaEdge{}
	}
	a.graph.AddEdge(source, target)
	attr := &dtaEdge{
		entrypoint:     make(map[string][]Rule),
		execute:        make(map[string][]Rule),
		typeTransition: make(map[string][]Rule),
	}
	a.attrs[e] = attr
	return attr
}

// hasPerm reports whether the permission list contains the permission.
func hasPerm(perms []string, perm string) bool {
	return slices.Contains(perms, perm)
}

func ruleKeys(m map[string][]Rule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stringIntersection(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if inB[s] {
			out = append(out, s)
		}
	}
	return out
}

// buildSubgraph builds the reversed and excluded subgraph.
func (a *DomainTransitionAnalysis) buildSubgraph() {
	full := a.fullGraph()
	a.log("Building domain transition subgraph.")
	var sub *DiGraph
	if a.reverse {
		sub = full.Reverse()
	} else {
		sub = full.Copy()
	}
	a.sub = sub
	a.subAttr = make(map[graphEdge]*dtaEdge)

	// Copy the edge data; the reversed graph's (u, v) edge carries the data
	// of the forward (v, u) edge, and excluded entrypoints are pruned from
	// the copy only.
	for _, e := range sub.Edges() {
		var forward graphEdge
		if a.reverse {
			forward = graphEdge{e.target, e.source}
		} else {
			forward = e
		}
		a.subAttr[e] = cloneDTAEdge(a.attrs[forward])
	}
	if len(a.exclude) > 0 {
		for _, name := range a.exclude {
			sub.RemoveNode(name)
		}
		a.removeExcludedEntrypoints()
	}
	a.log("Completed building domain transition subgraph.")
}

// cloneDTAEdge copies an edge's rule lists.
func cloneDTAEdge(src *dtaEdge) *dtaEdge {
	if src == nil {
		return &dtaEdge{}
	}
	out := &dtaEdge{
		transition:     append([]Rule(nil), src.transition...),
		setexec:        append([]Rule(nil), src.setexec...),
		dyntransition:  append([]Rule(nil), src.dyntransition...),
		setcurrent:     append([]Rule(nil), src.setcurrent...),
		entrypoint:     make(map[string][]Rule, len(src.entrypoint)),
		execute:        make(map[string][]Rule, len(src.execute)),
		typeTransition: make(map[string][]Rule, len(src.typeTransition)),
	}
	for k, v := range src.entrypoint {
		out.entrypoint[k] = append([]Rule(nil), v...)
	}
	for k, v := range src.execute {
		out.execute[k] = append([]Rule(nil), v...)
	}
	for k, v := range src.typeTransition {
		out.typeTransition[k] = append([]Rule(nil), v...)
	}
	return out
}

// removeExcludedEntrypoints prunes excluded entrypoint types from the
// subgraph's edges.
func (a *DomainTransitionAnalysis) removeExcludedEntrypoints() {
	excluded := make(map[string]bool, len(a.exclude))
	for _, name := range a.exclude {
		excluded[name] = true
	}
	var invalid []graphEdge
	for _, e := range a.sub.Edges() {
		attr := a.subAttr[e]
		if attr == nil {
			continue
		}
		var hits []string
		for name := range attr.entrypoint {
			if excluded[name] {
				hits = append(hits, name)
			}
		}
		if len(hits) == 0 {
			continue
		}
		for _, name := range hits {
			delete(attr.entrypoint, name)
			delete(attr.execute, name)
			delete(attr.typeTransition, name)
		}
		if len(attr.entrypoint) == 0 && len(attr.dyntransition) == 0 {
			invalid = append(invalid, e)
		}
	}
	for _, e := range invalid {
		a.sub.RemoveEdge(e.source, e.target)
		delete(a.subAttr, e)
	}
}

// subgraph returns the subgraph, building it first if needed.
func (a *DomainTransitionAnalysis) subgraph() *DiGraph {
	if a.sub == nil {
		a.buildSubgraph()
	}
	return a.sub
}

// step builds the DomainTransition of one subgraph edge.
func (a *DomainTransitionAnalysis) step(source, target string) DomainTransition {
	attr := a.subAttr[graphEdge{source, target}]
	if attr == nil {
		attr = &dtaEdge{}
	}
	realSource, realTarget := source, target
	if a.reverse {
		realSource, realTarget = target, source
	}
	return DomainTransition{
		Source:        realSource,
		Target:        realTarget,
		Transition:    attr.transition,
		Setexec:       attr.setexec,
		Dyntransition: attr.dyntransition,
		Setcurrent:    attr.setcurrent,
		Entrypoints:   entrypointsOf(attr),
	}
}

// entrypointsOf lists the entrypoint data of an edge, sorted by name.
func entrypointsOf(attr *dtaEdge) []DomainEntrypoint {
	out := make([]DomainEntrypoint, 0, len(attr.entrypoint))
	for name, rules := range attr.entrypoint {
		out = append(out, DomainEntrypoint{
			Name:           name,
			Entrypoint:     rules,
			Execute:        attr.execute[name],
			TypeTransition: attr.typeTransition[name],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TransitionsOut returns the direct transitions out of the source domain, in
// BFS order.
func (a *DomainTransitionAnalysis) TransitionsOut(source string) []DomainTransition {
	sub := a.subgraph()
	a.log("Generating domain transition results from %s", a.policy.Path())
	a.log("Generating all domain transitions out of %s", source)
	var out []DomainTransition
	for _, e := range sub.BFSEdges(source, 1, false) {
		out = append(out, a.step(e.source, e.target))
	}
	return out
}

// TransitionsIn returns the direct transitions into the target domain, in BFS
// order.
func (a *DomainTransitionAnalysis) TransitionsIn(target string) []DomainTransition {
	sub := a.subgraph()
	a.log("Generating domain transition results from %s", a.policy.Path())
	a.log("Generating all domain transitions into %s", target)
	var out []DomainTransition
	for _, e := range sub.BFSEdges(target, 1, true) {
		out = append(out, a.step(e.target, e.source))
	}
	return out
}

// ShortestPaths returns every shortest transition path from source to target.
func (a *DomainTransitionAnalysis) ShortestPaths(source, target string) [][]DomainTransition {
	sub := a.subgraph()
	a.log("Generating domain transition results from %s", a.policy.Path())
	a.log("Generating all shortest domain transition paths from %s to %s...", source, target)
	var out [][]DomainTransition
	for _, path := range sub.AllShortestPaths(source, target) {
		out = append(out, a.steps(path))
	}
	return out
}

// AllPaths returns every transition path from source to target with at most
// maxSteps transitions.
func (a *DomainTransitionAnalysis) AllPaths(source, target string, maxSteps int) [][]DomainTransition {
	sub := a.subgraph()
	a.log("Generating domain transition results from %s", a.policy.Path())
	a.log("Generating all domain transition paths from %s to %s, max length %d...", source, target, maxSteps)
	var out [][]DomainTransition
	for _, path := range sub.AllSimplePaths(source, target, maxSteps) {
		out = append(out, a.steps(path))
	}
	return out
}

// steps converts a node path into transition steps.
func (a *DomainTransitionAnalysis) steps(path []string) []DomainTransition {
	var out []DomainTransition
	for i := 0; i+1 < len(path); i++ {
		out = append(out, a.step(path[i], path[i+1]))
	}
	return out
}

// Stats renders the graph statistics block.
func (a *DomainTransitionAnalysis) Stats() string {
	g := a.fullGraph()
	return fmt.Sprintf("nx.number_of_nodes(self.G)=%d\nnx.number_of_edges(self.G)=%d\nlen(self.G)=%d\n",
		g.NodeCount(), g.EdgeCount(), g.NodeCount())
}

// Short renders the step as "source -> target" followed by a newline, which
// the commands print through their own print calls.
func (d *DomainTransition) Short() string {
	return fmt.Sprintf("%s -> %s\n", d.Source, d.Target)
}

// Full renders the step with its rule lists.
func (d *DomainTransition) Full() string {
	lines := []string{fmt.Sprintf("%s -> %s\n", d.Source, d.Target)}
	if len(d.Transition) > 0 {
		lines = append(lines, "Domain transition rule(s):")
		for _, rule := range sortedRules(d.Transition) {
			lines = append(lines, rule.String())
		}
		if len(d.Setexec) > 0 {
			lines = append(lines, "\nSet execution context rule(s):")
			for _, rule := range sortedRules(d.Setexec) {
				lines = append(lines, rule.String())
			}
		}
		for _, entry := range d.Entrypoints {
			lines = append(lines, entry.Full()+"\n")
		}
	}
	if len(d.Dyntransition) > 0 {
		lines = append(lines, "Dynamic transition rule(s):")
		for _, rule := range sortedRules(d.Dyntransition) {
			lines = append(lines, rule.String())
		}
		lines = append(lines, "\nSet current process context rule(s):")
		for _, rule := range sortedRules(d.Setcurrent) {
			lines = append(lines, rule.String())
		}
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// Full renders the entrypoint block.
func (e *DomainEntrypoint) Full() string {
	lines := []string{"\nEntrypoint " + e.Name + ":", "\tDomain entrypoint rule(s):"}
	for _, rule := range sortedRules(e.Entrypoint) {
		lines = append(lines, "\t"+rule.String())
	}
	lines = append(lines, "\n\tFile execute rule(s):")
	for _, rule := range sortedRules(e.Execute) {
		lines = append(lines, "\t"+rule.String())
	}
	if len(e.TypeTransition) > 0 {
		lines = append(lines, "\n\tType transition rule(s):")
		for _, rule := range sortedRules(e.TypeTransition) {
			lines = append(lines, "\t"+rule.String())
		}
	}
	return strings.Join(lines, "\n")
}

// GraphicalEdges returns the edges of the analysis result graph, for the
// graphical output: the union of the path edges for the path modes, and the
// BFS tree for the transition modes.
func (a *DomainTransitionAnalysis) GraphicalEdges(source, target string, mode string, maxSteps int) []GraphEdge {
	sub := a.subgraph()
	switch mode {
	case "shortest":
		var out []GraphEdge
		for _, path := range sub.AllShortestPaths(source, target) {
			for i := 0; i+1 < len(path); i++ {
				out = append(out, graphEdge{path[i], path[i+1]})
			}
		}
		return out
	case "all":
		var out []GraphEdge
		for _, path := range sub.AllSimplePaths(source, target, maxSteps) {
			for i := 0; i+1 < len(path); i++ {
				out = append(out, graphEdge{path[i], path[i+1]})
			}
		}
		return out
	case "out":
		return sub.BFSEdges(source, 1, false)
	default: // "in"
		var out []GraphEdge
		for _, e := range sub.BFSEdges(target, 1, true) {
			out = append(out, graphEdge{e.target, e.source})
		}
		return out
	}
}
