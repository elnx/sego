package sego

// Information flow analysis, mirroring setools' infoflow module: allow rules
// weighted by a permission map build the flow graph, the subgraph applies the
// weight floor, excluded types and Boolean states, and the flows are
// enumerated with networkx' traversal orderings.

import (
	"fmt"
	"strings"
)

// InfoFlowStep is one edge of an information flow path.
type InfoFlowStep struct {
	Source string
	Target string
	Rules  []Rule
	Weight int
}

// Short renders the step as "source -> target".
func (s *InfoFlowStep) Short() string {
	return fmt.Sprintf("%s -> %s", s.Source, s.Target)
}

// Full renders the step with its sorted rule list, each rule prefixed with
// three spaces.
func (s *InfoFlowStep) Full() string {
	lines := make([]string, 0, len(s.Rules))
	for _, rule := range sortedRules(s.Rules) {
		lines = append(lines, "   "+rule.String())
	}
	return fmt.Sprintf("%s -> %s\n%s", s.Source, s.Target, strings.Join(lines, "\n"))
}

// InfoFlowAnalysis builds the information flow graph of a policy.
type InfoFlowAnalysis struct {
	policy    *Policy
	permMap   *PermissionMap
	minWeight int

	// booleans holds the Boolean states to evaluate conditional rules with;
	// a nil map means both conditional branches count.
	booleans    map[string]bool
	useBooleans bool

	exclude []string

	graph   *DiGraph
	attrs   map[GraphEdge]*flowEdge
	sub     *DiGraph
	subAttr map[GraphEdge]*flowEdge

	logf func(format string, args ...any)
}

// SetLogger sets the informational log sink used by -v/--verbose.
func (a *InfoFlowAnalysis) SetLogger(logf func(string, ...any)) { a.logf = logf }

// log emits an informational message when a logger is set.
func (a *InfoFlowAnalysis) log(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
	}
}

// flowEdge is the rule data of one information flow graph edge.
type flowEdge struct {
	rules    []Rule
	capacity int
}

// NewInfoFlowAnalysis returns the analysis for the policy. The Boolean map,
// when useBooleans is set, evaluates the conditional rules as enabled() does;
// an empty map uses the policy's default Boolean states.
func NewInfoFlowAnalysis(pol *Policy, permMap *PermissionMap, minWeight int,
	exclude []string, booleans map[string]bool, useBooleans bool) (*InfoFlowAnalysis, error) {

	if minWeight < 1 || minWeight > 10 {
		return nil, fmt.Errorf("Min information flow weight must be an integer 1-10.")
	}
	a := &InfoFlowAnalysis{
		policy:      pol,
		permMap:     permMap,
		minWeight:   minWeight,
		booleans:    booleans,
		useBooleans: useBooleans,
	}
	for _, name := range exclude {
		if _, err := pol.LookupType(name); err != nil {
			return nil, err
		}
		a.exclude = append(a.exclude, name)
	}
	// The graph is built on first use, after the caller attached its logger.
	return a, nil
}

// fullGraph returns the full graph, building it first if needed.
func (a *InfoFlowAnalysis) fullGraph() *DiGraph {
	if a.graph == nil {
		a.buildGraph()
	}
	return a.graph
}

// buildGraph builds the full information flow graph.
func (a *InfoFlowAnalysis) buildGraph() {
	a.log("Building information flow graph from %s...", a.policy.Path())
	a.graph = NewDiGraph()
	a.attrs = make(map[GraphEdge]*flowEdge)

	a.permMap.MapPolicy(a.policy)
	for _, rule := range a.policy.TERules() {
		av, ok := rule.(*AVRule)
		if !ok || av.Kind() != Allow {
			continue
		}
		read, write := a.permMap.RuleWeight(av)
		for _, s := range av.Source.Expand() {
			for _, t := range av.Target.Expand() {
				if s.Name == t.Name {
					continue
				}
				if write > 0 {
					a.addFlow(s.Name, t.Name, rule, write)
				}
				if read > 0 {
					a.addFlow(t.Name, s.Name, rule, read)
				}
			}
		}
	}
	a.log("Completed building information flow graph.")
}

// addFlow adds the rule to an edge and raises the edge's capacity to the
// weight.
func (a *InfoFlowAnalysis) addFlow(source, target string, rule Rule, weight int) {
	e := GraphEdge{source, target}
	a.graph.AddEdge(source, target)
	attr := a.attrs[e]
	if attr == nil {
		attr = &flowEdge{}
		a.attrs[e] = attr
	}
	attr.rules = append(attr.rules, rule)
	attr.capacity = max(attr.capacity, weight)
}

// buildSubgraph applies the excluded types, the weight floor and the Boolean
// states.
func (a *InfoFlowAnalysis) buildSubgraph() {
	full := a.fullGraph()
	a.log("Building information flow subgraph...")
	excluded := make(map[string]bool, len(a.exclude))
	for _, name := range a.exclude {
		excluded[name] = true
	}

	sub := NewDiGraph()
	for _, node := range full.Nodes() {
		if !excluded[node] {
			sub.AddNode(node)
		}
	}
	// Adding the surviving edges in the original edge order rebuilds the
	// adjacency (and predecessor) lists the way networkx' subgraph copy does.
	for _, e := range full.Edges() {
		if !sub.HasNode(e.source) || !sub.HasNode(e.target) {
			continue
		}
		sub.AddEdge(e.source, e.target)
	}
	a.sub = sub
	a.subAttr = make(map[GraphEdge]*flowEdge)

	for _, e := range sub.Edges() {
		a.subAttr[e] = &flowEdge{
			rules:    append([]Rule(nil), a.attrs[e].rules...),
			capacity: a.attrs[e].capacity,
		}
	}

	if a.minWeight > 1 {
		var deleteList []GraphEdge
		for _, e := range sub.Edges() {
			if a.subAttr[e].capacity < a.minWeight {
				deleteList = append(deleteList, e)
			}
		}
		for _, e := range deleteList {
			sub.RemoveEdge(e.source, e.target)
			delete(a.subAttr, e)
		}
	}

	if a.useBooleans {
		var deleteList []GraphEdge
		for _, e := range sub.Edges() {
			attr := a.subAttr[e]
			var keep []Rule
			for _, rule := range attr.rules {
				if a.ruleEnabled(rule) {
					keep = append(keep, rule)
				}
			}
			attr.rules = keep
			if len(attr.rules) == 0 {
				deleteList = append(deleteList, e)
			}
		}
		for _, e := range deleteList {
			sub.RemoveEdge(e.source, e.target)
			delete(a.subAttr, e)
		}
	}
	a.log("Completed building information flow subgraph.")
}

// ruleEnabled evaluates a conditional rule under the configured Boolean
// states, the way setools' AVRule.enabled does.
func (a *InfoFlowAnalysis) ruleEnabled(rule Rule) bool {
	av, ok := rule.(*AVRule)
	if !ok || av.Conditional == nil {
		return true
	}
	result := av.Conditional.Evaluate(a.booleans)
	if av.ConditionalBlock {
		return result
	}
	return !result
}

// subgraph returns the subgraph, building it first if needed.
func (a *InfoFlowAnalysis) subgraph() *DiGraph {
	if a.sub == nil {
		a.buildSubgraph()
	}
	return a.sub
}

// step returns the flow step of one subgraph edge.
func (a *InfoFlowAnalysis) step(source, target string) InfoFlowStep {
	attr := a.subAttr[GraphEdge{source, target}]
	if attr == nil {
		attr = &flowEdge{}
	}
	return InfoFlowStep{Source: source, Target: target, Rules: attr.rules, Weight: attr.capacity}
}

// FlowsOut returns the direct information flows out of the source type, in BFS
// order.
func (a *InfoFlowAnalysis) FlowsOut(source string) []InfoFlowStep {
	sub := a.subgraph()
	a.log("Generating information flow results from %s", a.policy.Path())
	a.log("Generating all information flows out of %s, max depth %d", source, 1)
	var out []InfoFlowStep
	for _, e := range sub.BFSEdges(source, 1, false) {
		out = append(out, a.step(e.source, e.target))
	}
	return out
}

// FlowsIn returns the direct information flows into the target type, in BFS
// order.
func (a *InfoFlowAnalysis) FlowsIn(target string) []InfoFlowStep {
	sub := a.subgraph()
	a.log("Generating information flow results from %s", a.policy.Path())
	a.log("Generating all information flows into %s, max depth %d", target, 1)
	var out []InfoFlowStep
	for _, e := range sub.BFSEdges(target, 1, true) {
		out = append(out, a.step(e.target, e.source))
	}
	return out
}

// ShortestPaths returns every shortest information flow from source to
// target.
func (a *InfoFlowAnalysis) ShortestPaths(source, target string) [][]InfoFlowStep {
	sub := a.subgraph()
	a.log("Generating information flow results from %s", a.policy.Path())
	a.log("Generating all shortest information flow paths from %s to %s...", source, target)
	var out [][]InfoFlowStep
	for _, path := range sub.AllShortestPaths(source, target) {
		out = append(out, a.steps(path))
	}
	return out
}

// AllPaths returns every information flow from source to target with at most
// maxSteps steps.
func (a *InfoFlowAnalysis) AllPaths(source, target string, maxSteps int) [][]InfoFlowStep {
	sub := a.subgraph()
	a.log("Generating information flow results from %s", a.policy.Path())
	a.log("Generating all information flow paths from %s to %s, max length %d...", source, target, maxSteps)
	var out [][]InfoFlowStep
	for _, path := range sub.AllSimplePaths(source, target, maxSteps) {
		out = append(out, a.steps(path))
	}
	return out
}

// steps converts a node path into flow steps.
func (a *InfoFlowAnalysis) steps(path []string) []InfoFlowStep {
	out := make([]InfoFlowStep, 0, len(path)-1)
	for i := 0; i+1 < len(path); i++ {
		out = append(out, a.step(path[i], path[i+1]))
	}
	return out
}

// Stats renders the graph statistics block.
func (a *InfoFlowAnalysis) Stats() string {
	g := a.fullGraph()
	return fmt.Sprintf("nx.number_of_nodes(self.G)=%d\nnx.number_of_edges(self.G)=%d\nlen(self.G)=%d\n",
		g.NodeCount(), g.EdgeCount(), g.NodeCount())
}

// GraphicalEdges returns the edges of the analysis result graph, for the
// graphical output.
func (a *InfoFlowAnalysis) GraphicalEdges(source, target, mode string, maxSteps int) []GraphEdge {
	sub := a.subgraph()
	switch mode {
	case "shortest":
		var out []GraphEdge
		for _, path := range sub.AllShortestPaths(source, target) {
			for i := 0; i+1 < len(path); i++ {
				out = append(out, GraphEdge{path[i], path[i+1]})
			}
		}
		return out
	case "all":
		var out []GraphEdge
		for _, path := range sub.AllSimplePaths(source, target, maxSteps) {
			for i := 0; i+1 < len(path); i++ {
				out = append(out, GraphEdge{path[i], path[i+1]})
			}
		}
		return out
	case "out":
		return sub.BFSEdges(source, 1, false)
	default: // "in"
		var out []GraphEdge
		for _, e := range sub.BFSEdges(target, 1, true) {
			out = append(out, GraphEdge{e.target, e.source})
		}
		return out
	}
}
