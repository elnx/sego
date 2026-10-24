package sego

import (
	"strings"

	"github.com/elnx/sego/policy"
)

// Conditional is the boolean expression of a conditional rule block.
type Conditional struct {
	policy *Policy
	exprs  []policy.CondExpr
	bools  []*Boolean

	statement string
}

// Booleans returns the booleans the expression references.
func (c *Conditional) Booleans() []*Boolean { return c.bools }

// String renders the expression in infix notation.
//
// The operators are emitted right-operand first and parentheses follow
// setools' precedence bookkeeping, which compares each operator's precedence
// against the operator processed before it. Reproducing that keeps the output
// identical, including the over-parenthesised cases.
func (c *Conditional) String() string {
	if c.statement != "" {
		return c.statement
	}
	type node struct {
		text  string
		group bool // renders as a parenthesised sub-expression
	}
	var stack []node
	prevPrecedence := 5 // highest: NOT

	for _, e := range c.exprs {
		switch e.ExprType {
		case policy.CondBool:
			name := c.policy.boolName(e.Boolean)
			stack = append(stack, node{text: name})
		case policy.CondNot:
			if len(stack) == 0 {
				continue
			}
			operand := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if operand.group {
				stack = append(stack, node{text: "! ( " + operand.text + " )", group: true})
			} else {
				stack = append(stack, node{text: "! " + operand.text, group: true})
			}
			prevPrecedence = 5
		default:
			if len(stack) < 2 {
				continue
			}
			first := stack[len(stack)-1]
			second := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			op, precedence := condOperator(e.ExprType)
			if precedence == 0 {
				continue
			}
			text := first.text + " " + op + " " + second.text
			group := true
			if prevPrecedence > precedence {
				group = false
			} else {
				text = "( " + text + " )"
			}
			stack = append(stack, node{text: text, group: group})
			prevPrecedence = precedence
		}
	}

	parts := make([]string, 0, len(stack))
	for _, n := range stack {
		parts = append(parts, n.text)
	}
	c.statement = strings.Join(parts, " ")
	return c.statement
}

// Evaluate evaluates the conditional expression. Booleans that the states map
// does not carry use the policy's default state, as setools does.
func (c *Conditional) Evaluate(states map[string]bool) bool {
	var stack []bool
	// value returns the Boolean's state, from the map or the policy default.
	value := func(v uint32) bool {
		name := c.policy.boolName(v)
		if state, ok := states[name]; ok {
			return state
		}
		if b := c.policy.boolValue(v); b != nil {
			return b.State()
		}
		return false
	}
	pop := func() bool {
		if len(stack) == 0 {
			return false
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v
	}
	for _, e := range c.exprs {
		switch e.ExprType {
		case policy.CondBool:
			stack = append(stack, value(e.Boolean))
		case policy.CondNot:
			stack = append(stack, !pop())
		case policy.CondOr:
			b, a := pop(), pop()
			stack = append(stack, a || b)
		case policy.CondAnd:
			b, a := pop(), pop()
			stack = append(stack, a && b)
		case policy.CondXor:
			b, a := pop(), pop()
			stack = append(stack, a != b)
		case policy.CondEq:
			b, a := pop(), pop()
			stack = append(stack, a == b)
		case policy.CondNeq:
			b, a := pop(), pop()
			stack = append(stack, a != b)
		}
	}
	return pop()
}

func condOperator(exprType uint32) (string, int) {
	switch exprType {
	case policy.CondOr:
		return "||", 1
	case policy.CondXor:
		return "^", 2
	case policy.CondAnd:
		return "&&", 3
	case policy.CondEq:
		return "==", 4
	case policy.CondNeq:
		return "!=", 4
	}
	return "", 0
}

// conditional converts an on-disk conditional block into its object form.
func (p *Policy) conditional(c *policy.Condition) *Conditional {
	cond := &Conditional{policy: p, exprs: c.Exprs}
	seen := make(map[uint32]bool)
	for _, e := range c.Exprs {
		if e.ExprType != policy.CondBool || seen[e.Boolean] {
			continue
		}
		seen[e.Boolean] = true
		if b := p.boolValue(e.Boolean); b != nil {
			cond.bools = append(cond.bools, b)
		}
	}
	return cond
}
