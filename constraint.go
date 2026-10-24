package sego

// Constraint and validatetrans statement rendering, matching setools'
// constraint.pxi: the postfix expression of the binary policy is rendered as
// an infix expression with precedence-driven parentheses.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/elnx/sego/policy"
)

// Constraint is a constraint or validatetrans statement.
type Constraint struct {
	Kind   string // "constrain", "mlsconstrain", "validatetrans" or "mlsvalidatetrans"
	Class  *Class
	Perms  []string // constraint statements only
	Exprs  []policy.CExpr
	policy *Policy
}

// Statement renders the constraint as a policy statement.
func (c *Constraint) Statement() string {
	var b strings.Builder
	b.WriteString(c.Kind)
	b.WriteByte(' ')
	b.WriteString(c.Class.Name)
	if c.Kind == "constrain" || c.Kind == "mlsconstrain" {
		b.WriteByte(' ')
		b.WriteString(formatPerms(c.Perms, ""))
	}
	fmt.Fprintf(&b, " (%s);", c.renderExpr())
	return b.String()
}

// Constraints returns the constraint statements of the policy (the constrain
// family), in class order.
func (p *Policy) Constraints() []*Constraint {
	return p.constraints(false)
}

// Validatetrans returns the validatetrans statements of the policy, in class
// order.
func (p *Policy) Validatetrans() []*Constraint {
	return p.constraints(true)
}

func (p *Policy) constraints(validatetrans bool) []*Constraint {
	var out []*Constraint
	for _, c := range p.classes {
		raw := p.db.Classes[c.Value-1]
		list := raw.Constraints
		kind1, kind2 := "constrain", "mlsconstrain"
		if validatetrans {
			list = raw.Validatetrans
			kind1, kind2 = "validatetrans", "mlsvalidatetrans"
		}
		for _, cons := range list {
			perms := c.permVector(cons.Permissions)
			expr := constraintExpression{policy: p, exprs: cons.Exprs}
			for _, e := range cons.Exprs {
				if e.Attr >= policy.CExprL1L2 {
					expr.mls = true
					break
				}
			}
			kind := kind1
			if expr.mls {
				kind = kind2
			}
			out = append(out, &Constraint{
				Kind: kind, Class: c, Perms: perms, Exprs: cons.Exprs, policy: p,
			})
		}
	}
	return out
}

// renderExpr converts the postfix expression to infix notation.
func (c *Constraint) renderExpr() string {
	e := constraintExpression{policy: c.policy, exprs: c.Exprs}
	return e.infixString()
}

// constraintExpression converts a postfix constraint expression to infix
// notation, mirroring setools' ConstraintExpression.infix().
type constraintExpression struct {
	policy *Policy
	exprs  []policy.CExpr
	mls    bool
}

// constraint operand names, indexed by the attribute value. The oddities are
// setools': every non-target operand of the L1H2/H1L2/L1H1/H1H2 pairs is
// spelled l1/h1/l2/h2 by the mapping below, which the reference tool uses.
var constraintOperandNames = map[uint32]string{
	policy.CExprUser: "u1", policy.CExprRole: "r1", policy.CExprType: "t1",
	policy.CExprUser | policy.CExprTarget:  "u2",
	policy.CExprRole | policy.CExprTarget:  "r2",
	policy.CExprType | policy.CExprTarget:  "t2",
	policy.CExprUser | policy.CExprXTarget: "u3",
	policy.CExprRole | policy.CExprXTarget: "r3",
	policy.CExprType | policy.CExprXTarget: "t3",
	policy.CExprL1L2:                       "l1",
	policy.CExprL1H2:                       "l1",
	policy.CExprH1L2:                       "h1",
	policy.CExprH1H2:                       "h1",
	policy.CExprL1H1:                       "l1",
	policy.CExprL2H2:                       "l2",
	policy.CExprL1L2 | policy.CExprTarget:  "l2",
	policy.CExprL1H2 | policy.CExprTarget:  "h2",
	policy.CExprH1L2 | policy.CExprTarget:  "l2",
	policy.CExprH1H2 | policy.CExprTarget:  "h2",
	policy.CExprL1H1 | policy.CExprTarget:  "h1",
	policy.CExprL2H2 | policy.CExprTarget:  "h2",
}

// constraintOperatorNames maps the expression operators to their text.
var constraintOperatorNames = map[uint32]string{
	policy.CExprEQ:     "==",
	policy.CExprNEQ:    "!=",
	policy.CExprDom:    "dom",
	policy.CExprDomBy:  "domby",
	policy.CExprIncomp: "incomp",
}

// infixString renders the expression.
func (e *constraintExpression) infixString() string {
	const maxPrecedence = 4
	precedence := map[string]int{
		"not": 4, "and": 2, "or": 1,
		"==": 3, "!=": 3, "dom": 3, "domby": 3, "incomp": 3,
	}

	type stackObj struct {
		precedence int
		items      []string
	}
	var stack []stackObj

	operand := func(text string) { stack = append(stack, stackObj{maxPrecedence, []string{text}}) }

	for i := range e.exprs {
		expr := e.exprs[i]
		switch expr.ExprType {
		case policy.CExprNot, policy.CExprAnd, policy.CExprOr:
			var op string
			switch expr.ExprType {
			case policy.CExprNot:
				op = "not"
			case policy.CExprAnd:
				op = "and"
			case policy.CExprOr:
				op = "or"
			}
			opPrec := precedence[op]
			if op == "not" {
				if len(stack) == 0 {
					continue
				}
				operandInfo := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				var items []string
				if operandInfo.precedence < opPrec {
					items = []string{"not", "(", strings.Join(operandInfo.items, " "), ")"}
				} else {
					items = []string{"not", strings.Join(operandInfo.items, " ")}
				}
				stack = append(stack, stackObj{opPrec, items})
				continue
			}
			if len(stack) < 2 {
				continue
			}
			operand2 := stack[len(stack)-1]
			operand1 := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			o1 := operand1.items
			if operand1.precedence < opPrec {
				o1 = []string{"(", strings.Join(o1, " "), ")"}
			}
			o2 := operand2.items
			if operand2.precedence < opPrec {
				o2 = []string{"(", strings.Join(o2, " "), ")"}
			}
			items := append(append([]string{}, o1...), op)
			items = append(items, o2...)
			stack = append(stack, stackObj{opPrec, items})

		case policy.CExprAttr:
			// A comparison between two attributes, e.g. u1 == u2.
			operand1 := constraintOperandNames[expr.Attr]
			operand2 := constraintOperandNames[expr.Attr|policy.CExprTarget]
			op := constraintOperatorNames[expr.Op]
			operand(operand1)
			operand(operand2)
			// Combine immediately: the node itself is one postfix unit.
			o2 := stack[len(stack)-1]
			o1 := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			items := append(append([]string{}, o1.items...), op)
			items = append(items, o2.items...)
			stack = append(stack, stackObj{precedence[op], items})

		case policy.CExprNames:
			// A comparison against a set of named symbols, e.g.
			// t1 == { data_t log_t } or t1 == data_attr. Sets with more
			// than one name render with a trailing space, as setools'
			// frozenset rendering does, so a set that is followed by
			// another token or the closing parenthesis produces two
			// spaces there.
			operand1 := constraintOperandNames[expr.Attr]
			set := e.renderNames(expr)
			var operand2 string
			switch {
			case len(set) > 1:
				operand2 = "{ " + strings.Join(set, " ") + " } "
			case len(set) == 1:
				operand2 = set[0]
			default:
				// No named symbols; a valid policy never has an empty
				// set, so this only guards the stack bookkeeping.
				operand2 = "<empty>"
			}
			op := constraintOperatorNames[expr.Op]
			operand(operand1)
			operand(operand2)
			o2 := stack[len(stack)-1]
			o1 := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			items := append(append([]string{}, o1.items...), op)
			items = append(items, o2.items...)
			stack = append(stack, stackObj{precedence[op], items})
		}
	}

	var items []string
	for _, s := range stack {
		items = append(items, s.items...)
	}
	return strings.Join(items, " ")
}

// renderNames resolves the named symbols of a CEXPR_NAMES node: the set of
// attributes and types as named in the source policy (the type_names bitmap),
// falling back to the expanded type set. User and role expressions use the
// names bitmap.
func (e *constraintExpression) renderNames(expr policy.CExpr) []string {
	attr := expr.Attr &^ policy.CExprTarget
	var values []uint32
	switch attr {
	case policy.CExprUser, policy.CExprRole:
		values = expr.Names
	default:
		// Types: prefer the names as written (types and attributes) over
		// the expanded set, which is what the reference tool renders.
		if len(expr.Types) > 0 {
			values = expr.Types
		} else {
			values = expr.Names
		}
	}
	db := e.policy.db
	var out []string
	for _, bit := range values {
		v := bit + 1
		switch attr {
		case policy.CExprUser:
			if name := e.policy.userName(v); name != "" {
				out = append(out, name)
			}
		case policy.CExprRole:
			if int(v) <= len(db.Roles) && db.Roles[v-1] != nil {
				out = append(out, db.Roles[v-1].Name)
			}
		default:
			if t := e.policy.typeValue(v); t != nil {
				out = append(out, t.Name)
			}
		}
	}
	// The reference renders these sets in libsepol's hash table order, which
	// is not reproducible; this project renders them in value order.
	if attr == policy.CExprUser || attr == policy.CExprRole {
		sort.Strings(out)
	}
	return out
}
