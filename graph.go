package sego

// A small directed graph with deterministic ordering, implementing the subset
// of networkx' DiGraph semantics the graph analyses rely on: nodes and
// adjacency keep insertion order, edge iteration is grouped by source node in
// node order, and the traversal helpers reproduce networkx' orderings.

import "slices"

import "sort"

// GraphEdge is one directed edge.
type GraphEdge struct{ source, target string }

// Source returns the edge's source node.
func (e GraphEdge) Source() string { return e.source }

// Target returns the edge's target node.
func (e GraphEdge) Target() string { return e.target }

// graphEdge is the internal name of an edge.
type graphEdge = GraphEdge

// DiGraph is a directed graph with string nodes.
type DiGraph struct {
	nodes    []string
	nodeSet  map[string]bool
	success  map[string][]string
	predec   map[string][]string
	edgeList []graphEdge
	edgeSet  map[graphEdge]bool
}

// NewDiGraph returns an empty graph.
func NewDiGraph() *DiGraph {
	return &DiGraph{
		nodeSet: make(map[string]bool),
		success: make(map[string][]string),
		predec:  make(map[string][]string),
		edgeSet: make(map[graphEdge]bool),
	}
}

// AddNode adds a node if it is not present.
func (g *DiGraph) AddNode(name string) {
	if g.nodeSet[name] {
		return
	}
	g.nodeSet[name] = true
	g.nodes = append(g.nodes, name)
}

// AddEdge adds an edge, adding its endpoints first, in that order.
func (g *DiGraph) AddEdge(source, target string) {
	g.AddNode(source)
	g.AddNode(target)
	e := graphEdge{source, target}
	if g.edgeSet[e] {
		return
	}
	g.edgeSet[e] = true
	g.edgeList = append(g.edgeList, e)
	g.success[source] = append(g.success[source], target)
	g.predec[target] = append(g.predec[target], source)
}

// HasEdge reports whether the edge exists.
func (g *DiGraph) HasEdge(source, target string) bool {
	return g.edgeSet[graphEdge{source, target}]
}

// HasNode reports whether the node exists.
func (g *DiGraph) HasNode(name string) bool { return g.nodeSet[name] }

// Nodes returns the nodes in insertion order.
func (g *DiGraph) Nodes() []string { return g.nodes }

// NodeCount returns the number of nodes.
func (g *DiGraph) NodeCount() int { return len(g.nodes) }

// EdgeCount returns the number of edges.
func (g *DiGraph) EdgeCount() int { return len(g.edgeList) }

// Edges returns the edges grouped by source node in node order, which is the
// order networkx' DiGraph.edges() yields.
func (g *DiGraph) Edges() []graphEdge {
	out := make([]graphEdge, 0, len(g.edgeList))
	for _, source := range g.nodes {
		for _, target := range g.success[source] {
			out = append(out, graphEdge{source, target})
		}
	}
	return out
}

// Successors returns the successors of a node in insertion order.
func (g *DiGraph) Successors(name string) []string { return g.success[name] }

// Predecessors returns the predecessors of a node in edge insertion order.
func (g *DiGraph) Predecessors(name string) []string { return g.predec[name] }

// RemoveEdge removes an edge, keeping the relative order of the rest.
func (g *DiGraph) RemoveEdge(source, target string) {
	e := graphEdge{source, target}
	if !g.edgeSet[e] {
		return
	}
	delete(g.edgeSet, e)
	for i, edge := range g.edgeList {
		if edge == e {
			g.edgeList = append(g.edgeList[:i], g.edgeList[i+1:]...)
			break
		}
	}
	g.success[source] = removeString(g.success[source], target)
	g.predec[target] = removeString(g.predec[target], source)
}

// RemoveNode removes a node and every incident edge.
func (g *DiGraph) RemoveNode(name string) {
	if !g.nodeSet[name] {
		return
	}
	var keep []graphEdge
	for _, e := range g.edgeList {
		if e.source == name || e.target == name {
			delete(g.edgeSet, e)
			continue
		}
		keep = append(keep, e)
	}
	g.edgeList = keep
	for _, target := range g.success[name] {
		g.predec[target] = removeString(g.predec[target], name)
	}
	for _, source := range g.predec[name] {
		g.success[source] = removeString(g.success[source], name)
	}
	delete(g.success, name)
	delete(g.predec, name)
	delete(g.nodeSet, name)
	for i, n := range g.nodes {
		if n == name {
			g.nodes = append(g.nodes[:i], g.nodes[i+1:]...)
			break
		}
	}
}

// removeString removes the first occurrence of name from list.
func removeString(list []string, name string) []string {
	for i, v := range list {
		if v == name {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// Copy returns a copy of the graph. Like networkx' DiGraph.copy, the nodes
// keep their order and the edges are re-added in the order edges() iterates,
// which also rebuilds the predecessor lists in that order.
func (g *DiGraph) Copy() *DiGraph {
	out := NewDiGraph()
	for _, n := range g.nodes {
		out.AddNode(n)
	}
	for _, e := range g.Edges() {
		out.AddEdge(e.source, e.target)
	}
	return out
}

// Reverse returns the reversed graph: nodes keep their order and the edges are
// added in the order networkx' edges() iterates, which is what its
// reverse(copy=True) does.
func (g *DiGraph) Reverse() *DiGraph {
	out := NewDiGraph()
	for _, n := range g.nodes {
		out.AddNode(n)
	}
	for _, e := range g.Edges() {
		out.AddEdge(e.target, e.source)
	}
	return out
}

// BFSEdges yields the tree edges of a breadth-first search from source, in
// networkx' bfs_edges order. With reverse set the graph is traversed through
// the predecessors, yielding (node, predecessor) pairs. depthLimit is the
// number of levels to descend; 1 yields only the direct edges.
func (g *DiGraph) BFSEdges(source string, depthLimit int, reverse bool) []graphEdge {
	if !g.nodeSet[source] {
		return nil
	}
	neighbors := g.Successors
	if reverse {
		neighbors = g.Predecessors
	}

	var out []graphEdge
	seen := map[string]bool{source: true}
	depth := 0
	type parentChildren struct {
		parent   string
		children []string
	}
	current := []parentChildren{{source, neighbors(source)}}
	for len(current) > 0 && depth < depthLimit {
		var next []parentChildren
		for _, pc := range current {
			for _, child := range pc.children {
				if seen[child] {
					continue
				}
				seen[child] = true
				next = append(next, parentChildren{child, neighbors(child)})
				out = append(out, graphEdge{pc.parent, child})
			}
			if len(seen) == len(g.nodes) {
				return out
			}
		}
		current = next
		depth++
	}
	return out
}

// AllShortestPaths returns every shortest path from source to target, in
// networkx' all_shortest_paths order.
func (g *DiGraph) AllShortestPaths(source, target string) [][]string {
	if !g.nodeSet[source] || !g.nodeSet[target] {
		return nil
	}
	pred := g.bfsPredecessors(source)
	if _, ok := pred[target]; !ok {
		return nil
	}
	return buildPathsFromPredecessors(source, target, pred)
}

// bfsPredecessors returns the BFS predecessor lists of every reachable node,
// matching networkx' predecessor().
func (g *DiGraph) bfsPredecessors(source string) map[string][]string {
	seen := map[string]int{source: 0}
	pred := map[string][]string{source: nil}
	level := 0
	current := []string{source}
	for len(current) > 0 {
		level++
		var next []string
		for _, v := range current {
			for _, w := range g.Successors(v) {
				if _, ok := seen[w]; !ok {
					pred[w] = []string{v}
					seen[w] = level
					next = append(next, w)
				} else if seen[w] == level {
					pred[w] = append(pred[w], v)
				}
			}
		}
		current = next
	}
	return pred
}

// predFrame is one level of the backward path walk.
type predFrame struct {
	node string
	next int
}

// buildPathsFromPredecessors walks the predecessor lists back from the target,
// matching networkx' _build_paths_from_predecessors.
func buildPathsFromPredecessors(source, target string, pred map[string][]string) [][]string {
	type frame = predFrame
	var out [][]string
	path := []string{target}
	stack := []frame{{target, 0}}
	for len(stack) > 0 {
		node := path[len(path)-1]
		if node == source {
			reversed := make([]string, len(path))
			for i, n := range path {
				reversed[len(path)-1-i] = n
			}
			out = append(out, reversed)
		}
		advanced := false
		for stack[len(stack)-1].next < len(pred[node]) {
			p := pred[node][stack[len(stack)-1].next]
			stack[len(stack)-1].next++
			if onPath(stack, p) {
				continue
			}
			stack = append(stack, frame{p, 0})
			path = append(path, p)
			advanced = true
			break
		}
		if advanced {
			continue
		}
		stack = stack[:len(stack)-1]
		path = path[:len(path)-1]
	}
	return out
}

// onPath reports whether the node is on the current predecessor stack.
func onPath(stack []predFrame, node string) bool {
	for _, f := range stack {
		if f.node == node {
			return true
		}
	}
	return false
}

// AllSimplePaths returns every simple path from source to target with at most
// cutoff edges, in networkx' all_simple_paths order.
func (g *DiGraph) AllSimplePaths(source, target string, cutoff int) [][]string {
	if !g.nodeSet[source] || !g.nodeSet[target] {
		return nil
	}
	if cutoff < 1 {
		return nil
	}
	if source == target {
		// The trivial path, as networkx yields it.
		return [][]string{{source}}
	}
	type frame struct {
		node string
		next int
	}
	var out [][]string
	// path holds the nodes on the current path, entry the edge that led into
	// each of them; both in insertion order.
	path := []string{source}
	var stack []frame
	stack = append(stack, frame{source, 0})
	for len(stack) > 0 {
		frameTop := &stack[len(stack)-1]
		if frameTop.next >= len(g.Successors(frameTop.node)) {
			stack = stack[:len(stack)-1]
			path = path[:len(path)-1]
			continue
		}
		child := g.Successors(frameTop.node)[frameTop.next]
		frameTop.next++
		if pathHas(path, child) {
			continue
		}
		// The child is now visited: a path ending here is simple.
		if child == target {
			p := make([]string, len(path)+1)
			copy(p, path)
			p[len(path)] = child
			out = append(out, p)
			continue
		}
		// Expand while the current path has fewer nodes than the cutoff and
		// the target has not been visited yet; the last node before the
		// target may be pushed when the path has cutoff-1 nodes.
		if len(path) < cutoff && !pathHas(path, target) {
			path = append(path, child)
			stack = append(stack, frame{child, 0})
		}
	}
	return out
}

// pathHas reports whether the path contains the node.
func pathHas(path []string, node string) bool {
	return slices.Contains(path, node)
}

// sortedRules returns the rules sorted by their rendered statement, keeping
// the list stable.
func sortedRules(rules []Rule) []Rule {
	out := append([]Rule(nil), rules...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
