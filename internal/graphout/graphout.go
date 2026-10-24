// Package graphout renders analysis result graphs as PNG images through
// graphviz, the way the reference tools' graphical output does.
package graphout

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// WritePNG renders the directed graph of the given nodes and edges as a PNG
// at path. It runs graphviz' dot, which the reference tools also require for
// their graphical output.
func WritePNG(path string, nodes []string, edges [][2]string) error {
	var dot strings.Builder
	dot.WriteString("digraph {\n")
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if seen[n] {
			continue
		}
		seen[n] = true
		fmt.Fprintf(&dot, "\t%q;\n", n)
	}
	for _, e := range edges {
		for _, n := range e {
			if !seen[n] {
				seen[n] = true
				fmt.Fprintf(&dot, "\t%q;\n", n)
			}
		}
		fmt.Fprintf(&dot, "\t%q -> %q;\n", e[0], e[1])
	}
	dot.WriteString("}\n")

	cmd := exec.Command("dot", "-Tpng", "-o", path)
	cmd.Stdin = strings.NewReader(dot.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("Unable to generate graphical results: %s", msg)
	}
	return nil
}
