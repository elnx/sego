package sego

// Tests of the graph traversal semantics the analyses rely on: networkx'
// insertion-order iteration and its path enumeration orders.

import (
	"slices"
	"testing"
)

// TestBFSEdges checks the BFS edge order and the depth limit.
func TestBFSEdges(t *testing.T) {
	g := NewDiGraph()
	// Edges in insertion order; bfs_edges yields level by level, adjacency
	// order within a level.
	g.AddEdge("a", "b")
	g.AddEdge("a", "c")
	g.AddEdge("b", "d")
	g.AddEdge("c", "d")
	g.AddEdge("d", "e")

	got := edgesStrings(g.BFSEdges("a", 1, false))
	want := []string{"a->b", "a->c"}
	if !slices.Equal(got, want) {
		t.Errorf("depth 1 = %v, want %v", got, want)
	}

	got = edgesStrings(g.BFSEdges("a", 2, false))
	want = []string{"a->b", "a->c", "b->d"}
	if !slices.Equal(got, want) {
		t.Errorf("depth 2 = %v, want %v", got, want)
	}

	// The reverse traversal walks the predecessors.
	got = edgesStrings(g.BFSEdges("d", 1, true))
	want = []string{"d->b", "d->c"}
	if !slices.Equal(got, want) {
		t.Errorf("reverse depth 1 = %v, want %v", got, want)
	}

	if got := g.BFSEdges("missing", 1, false); got != nil {
		t.Errorf("BFS from a missing node = %v, want nothing", got)
	}
}

// edgesStrings renders edges as "source->target".
func edgesStrings(edges []GraphEdge) []string {
	out := make([]string, len(edges))
	for i, e := range edges {
		out[i] = e.source + "->" + e.target
	}
	return out
}

// TestAllShortestPaths checks the ordering of the shortest path enumeration.
func TestAllShortestPaths(t *testing.T) {
	g := NewDiGraph()
	// A diamond: two shortest paths from a to d, one through b, one through
	// c, in adjacency order.
	g.AddEdge("a", "b")
	g.AddEdge("a", "c")
	g.AddEdge("b", "d")
	g.AddEdge("c", "d")

	got := g.AllShortestPaths("a", "d")
	want := [][]string{{"a", "b", "d"}, {"a", "c", "d"}}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("shortest paths = %v, want %v", got, want)
	}

	// An unreachable target yields nothing, not an error.
	if got := g.AllShortestPaths("d", "a"); got != nil {
		t.Errorf("reverse paths = %v, want nothing", got)
	}
}

// TestAllSimplePaths checks the cutoff and enumeration order, mirroring
// networkx' documented example on a complete graph: the direct path is
// yielded after the longer paths through the earlier neighbours.
func TestAllSimplePaths(t *testing.T) {
	g := NewDiGraph()
	for _, e := range []GraphEdge{{"0", "1"}, {"0", "2"}, {"0", "3"},
		{"1", "2"}, {"1", "3"}, {"2", "1"}, {"2", "3"}, {"3", "1"}, {"3", "2"}} {
		g.AddEdge(e.source, e.target)
	}

	got := g.AllSimplePaths("0", "3", 2)
	want := [][]string{{"0", "1", "3"}, {"0", "2", "3"}, {"0", "3"}}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("paths = %v, want %v", got, want)
	}

	// cutoff 1 allows only the direct edge.
	got = g.AllSimplePaths("0", "3", 1)
	want = [][]string{{"0", "3"}}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("cutoff 1 paths = %v, want %v", got, want)
	}

	// A source that is also the target has the trivial path.
	got = g.AllSimplePaths("0", "0", 2)
	want = [][]string{{"0"}}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("trivial path = %v, want %v", got, want)
	}
}

// TestGraphCopyAndReverse checks the ordering of the copied and reversed
// graphs, which determines the BFS and path orders of the analyses.
func TestGraphCopyAndReverse(t *testing.T) {
	g := NewDiGraph()
	g.AddEdge("a", "b")
	g.AddEdge("b", "c")
	g.AddEdge("a", "c")

	// The copy re-adds the edges in edges() order: grouped by source node in
	// node order, so a's edges come before b's.
	c := g.Copy()
	if got, want := edgesStrings(c.Edges()), []string{"a->b", "a->c", "b->c"}; !slices.Equal(got, want) {
		t.Errorf("copy edges = %v, want %v", got, want)
	}

	// The reversed graph swaps every edge and keeps the copy's node order.
	r := g.Reverse()
	if got, want := edgesStrings(r.Edges()), []string{"b->a", "c->a", "c->b"}; !slices.Equal(got, want) {
		t.Errorf("reverse edges = %v, want %v", got, want)
	}

	// removeNode drops the incident edges and keeps the rest in order.
	g.RemoveNode("a")
	if got, want := edgesStrings(g.Edges()), []string{"b->c"}; !slices.Equal(got, want) {
		t.Errorf("edges after remove = %v, want %v", got, want)
	}
}
