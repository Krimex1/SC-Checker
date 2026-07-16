package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sc-checker-go/internal/model"
	"strconv"
	"strings"
)

type DSLv2Result struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Condition string `json:"condition,omitempty"`
}

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokNumber
	tokDollar
	tokEquals
	tokNotEquals
	tokGT
	tokLT
	tokGTE
	tokLTE
	tokContains
	tokAssign
	tokIf
	tokThen
	tokElse
	tokEnd
	tokFor
	tokIn
	tokAssert
	tokCapture
	tokFrom
	tokRequest
	tokCheck
	tokResponse
	tokHTTPTime
	tokReturn
	tokAnd
	tokOr
	tokNot
	tokLParen
	tokRParen
	tokComma
	tokTrue
	tokFalse
	tokLBracket
	tokRBracket
)

type token struct {
	kind  tokenKind
	value string
}

type lexer struct {
	input []rune
	pos   int
}

func (l *lexer) next() token {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return token{tokEOF, ""}
	}

	ch := l.input[l.pos]

	switch {
	case ch == '"' || ch == '\'':
		return l.readString(ch)
	case ch >= '0' && ch <= '9':
		return l.readNumber()
	case ch == '$':
		l.pos++
		id := l.readIdent()
		return token{tokDollar, id}
	case ch == '=':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{tokEquals, "=="}
		}
		return token{tokAssign, "="}
	case ch == '!':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{tokNotEquals, "!="}
		}
		return token{tokEOF, ""}
	case ch == '>':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{tokGTE, ">="}
		}
		return token{tokGT, ">"}
	case ch == '<':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{tokLTE, "<="}
		}
		return token{tokLT, "<"}
	case ch == '(':
		l.pos++
		return token{tokLParen, "("}
	case ch == ')':
		l.pos++
		return token{tokRParen, ")"}
	case ch == ',':
		l.pos++
		return token{tokComma, ","}
	case ch == '[':
		l.pos++
		return token{tokLBracket, "["}
	case ch == ']':
		l.pos++
		return token{tokRBracket, "]"}
	case isAlpha(ch):
		return l.readKeyword()
	default:
		l.pos++
		return l.next()
	}
}

func (l *lexer) readString(quote rune) token {
	l.pos++
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != quote {
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			l.pos += 2
			continue
		}
		l.pos++
	}
	end := l.pos
	if l.pos < len(l.input) {
		l.pos++
	}
	return token{tokString, string(l.input[start:end])}
}

func (l *lexer) readNumber() token {
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
		l.pos++
	}
	if l.pos < len(l.input) && l.input[l.pos] == '.' {
		l.pos++
		for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
			l.pos++
		}
	}
	return token{tokNumber, string(l.input[start:l.pos])}
}

func (l *lexer) readIdent() string {
	start := l.pos
	for l.pos < len(l.input) && (isAlpha(l.input[l.pos]) || l.input[l.pos] >= '0' && l.input[l.pos] <= '9' || l.input[l.pos] == '_') {
		l.pos++
	}
	return string(l.input[start:l.pos])
}

func (l *lexer) readKeyword() token {
	word := strings.ToUpper(l.readIdent())
	switch word {
	case "IF":
		return token{tokIf, word}
	case "THEN":
		return token{tokThen, word}
	case "ELSE":
		return token{tokElse, word}
	case "END":
		return token{tokEnd, word}
	case "FOR":
		return token{tokFor, word}
	case "IN":
		return token{tokIn, word}
	case "ASSERT":
		return token{tokAssert, word}
	case "CAPTURE":
		return token{tokCapture, word}
	case "FROM":
		return token{tokFrom, word}
	case "REQUEST":
		return token{tokRequest, word}
	case "CHECK":
		return token{tokCheck, word}
	case "RESPONSE":
		return token{tokResponse, word}
	case "HTTP_TIME":
		return token{tokHTTPTime, word}
	case "RETURN":
		return token{tokReturn, word}
	case "AND":
		return token{tokAnd, word}
	case "OR":
		return token{tokOr, word}
	case "NOT":
		return token{tokNot, word}
	case "CONTAINS":
		return token{tokContains, word}
	case "TRUE":
		return token{tokTrue, word}
	case "FALSE":
		return token{tokFalse, word}
	default:
		return token{tokIdent, word}
	}
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			l.pos++
			continue
		}
		if ch == '#' {
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		break
	}
}

func isAlpha(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

type ASTNode interface{}

type Program struct {
	Statements []ASTNode
}

type IfNode struct {
	Condition ExprNode
	ThenBlock []ASTNode
	ElseBlock []ASTNode
}

type ForNode struct {
	VarName  string
	ListExpr ExprNode
	Body     []ASTNode
}

type AssignNode struct {
	VarName string
	Value   ExprNode
}

type AssertNode struct {
	Condition ExprNode
}

type CaptureNode struct {
	Pattern string
	Field   ExprNode
}

type RequestNode struct {
	URL      string
	Contains string
}

type HTTPTimeNode struct {
	URL       string
	Op        string
	Threshold int
}

type ReturnNode struct{}

type CondNode struct {
	Condition ExprNode
}

type ExprNode interface{}

type BinaryExpr struct {
	Left  ExprNode
	Op    string
	Right ExprNode
}

type UnaryExpr struct {
	Op   string
	Expr ExprNode
}

type VarExprNode struct {
	Name string
}

type FieldExprNode struct {
	Name    string
	IsCount bool
}

type LiteralExprNode struct {
	Value any
}

type ListExprNode struct {
	Items []ExprNode
}

type parser struct {
	lexer *lexer
	tok   token
}

func newParser(input string) *parser {
	l := &lexer{input: []rune(input)}
	p := &parser{lexer: l}
	p.tok = l.next()
	return p
}

func (p *parser) eat(kind tokenKind) {
	if p.tok.kind == kind {
		p.tok = p.lexer.next()
	} else {
		panic(fmt.Sprintf("unexpected token %v, expected %v", p.tok, kind))
	}
}

func (p *parser) parseProgram() *Program {
	prog := &Program{}
	for p.tok.kind != tokEOF {
		stmt := p.parseStatement()
		if stmt != nil {
			prog.Statements = append(prog.Statements, stmt)
		}
	}
	return prog
}

func (p *parser) parseStatement() ASTNode {
	switch p.tok.kind {
	case tokDollar:
		return p.parseAssign()
	case tokIf:
		return p.parseIf()
	case tokFor:
		return p.parseFor()
	case tokAssert:
		return p.parseAssert()
	case tokCapture:
		return p.parseCapture()
	case tokRequest:
		return p.parseRequest()
	case tokHTTPTime:
		return p.parseHTTPTime()
	case tokReturn:
		p.eat(tokReturn)
		return &ReturnNode{}
	case tokEnd, tokElse, tokThen:
		p.tok = p.lexer.next()
		return nil
	default:
		return p.parseCondition()
	}
}

func (p *parser) parseAssign() *AssignNode {
	p.eat(tokDollar)
	name := p.tok.value
	p.eat(tokIdent)
	p.eat(tokAssign)
	val := p.parsePrimary()
	return &AssignNode{VarName: name, Value: val}
}

func (p *parser) parseIf() *IfNode {
	p.eat(tokIf)
	cond := p.parseConditionExpr()
	p.eat(tokThen)

	var thenBlock []ASTNode
	for {
		if p.tok.kind == tokElse || p.tok.kind == tokEnd || p.tok.kind == tokEOF {
			break
		}
		stmt := p.parseStatement()
		if stmt != nil {
			thenBlock = append(thenBlock, stmt)
		}
	}

	var elseBlock []ASTNode
	if p.tok.kind == tokElse {
		p.eat(tokElse)
		for {
			if p.tok.kind == tokEnd || p.tok.kind == tokEOF {
				break
			}
			stmt := p.parseStatement()
			if stmt != nil {
				elseBlock = append(elseBlock, stmt)
			}
		}
	}
	p.eat(tokEnd)
	return &IfNode{Condition: cond, ThenBlock: thenBlock, ElseBlock: elseBlock}
}

func (p *parser) parseFor() *ForNode {
	p.eat(tokFor)
	p.eat(tokDollar)
	varName := p.tok.value
	p.eat(tokIdent)
	p.eat(tokIn)
	listExpr := p.parsePrimary()

	var body []ASTNode
	for {
		if p.tok.kind == tokEnd || p.tok.kind == tokEOF {
			break
		}
		stmt := p.parseStatement()
		if stmt != nil {
			body = append(body, stmt)
		}
	}
	p.eat(tokEnd)
	return &ForNode{VarName: varName, ListExpr: listExpr, Body: body}
}

func (p *parser) parseAssert() *AssertNode {
	p.eat(tokAssert)
	cond := p.parseConditionExpr()
	return &AssertNode{Condition: cond}
}

func (p *parser) parseCapture() *CaptureNode {
	p.eat(tokCapture)
	pattern := p.tok.value
	p.eat(tokString)
	p.eat(tokFrom)
	field := p.parsePrimary()
	return &CaptureNode{Pattern: pattern, Field: field}
}

func (p *parser) parseRequest() *RequestNode {
	p.eat(tokRequest)
	url := p.tok.value
	p.eat(tokString)
	p.eat(tokCheck)
	p.eat(tokResponse)
	p.eat(tokContains)
	text := p.tok.value
	p.eat(tokString)
	return &RequestNode{URL: url, Contains: text}
}

func (p *parser) parseHTTPTime() *HTTPTimeNode {
	p.eat(tokHTTPTime)
	url := p.tok.value
	p.eat(tokString)
	op := p.tok.value
	p.eat(p.tok.kind)
	threshold, _ := strconv.Atoi(p.tok.value)
	p.eat(tokNumber)
	return &HTTPTimeNode{URL: url, Op: op, Threshold: threshold}
}

func (p *parser) parseCondition() *CondNode {
	cond := p.parseConditionExpr()
	return &CondNode{Condition: cond}
}

func (p *parser) parseConditionExpr() ExprNode {
	return p.parseOr()
}

func (p *parser) parseOr() ExprNode {
	left := p.parseAnd()
	for p.tok.kind == tokOr {
		p.eat(tokOr)
		right := p.parseAnd()
		left = &BinaryExpr{Left: left, Op: "OR", Right: right}
	}
	return left
}

func (p *parser) parseAnd() ExprNode {
	left := p.parseNot()
	for p.tok.kind == tokAnd {
		p.eat(tokAnd)
		right := p.parseNot()
		left = &BinaryExpr{Left: left, Op: "AND", Right: right}
	}
	return left
}

func (p *parser) parseNot() ExprNode {
	if p.tok.kind == tokNot {
		p.eat(tokNot)
		expr := p.parseNot()
		return &UnaryExpr{Op: "NOT", Expr: expr}
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() ExprNode {
	left := p.parsePrimary()

	if p.tok.kind == tokEquals || p.tok.kind == tokNotEquals || p.tok.kind == tokGT || p.tok.kind == tokLT || p.tok.kind == tokGTE || p.tok.kind == tokLTE || p.tok.kind == tokContains {
		op := p.tok.value
		p.tok = p.lexer.next()
		right := p.parsePrimary()
		return &BinaryExpr{Left: left, Op: op, Right: right}
	}

	return left
}

func (p *parser) parsePrimary() ExprNode {
	switch p.tok.kind {
	case tokDollar:
		name := p.tok.value
		p.eat(tokDollar)
		return &VarExprNode{Name: name}
	case tokIdent:
		val := p.tok.value
		p.eat(tokIdent)
		if strings.HasSuffix(val, "_count") {
			return &FieldExprNode{Name: strings.TrimSuffix(val, "_count"), IsCount: true}
		}
		return &FieldExprNode{Name: val}
	case tokString:
		val := p.tok.value
		p.eat(tokString)
		return &LiteralExprNode{Value: val}
	case tokNumber:
		val := p.tok.value
		p.eat(tokNumber)
		if strings.Contains(val, ".") {
			f, _ := strconv.ParseFloat(val, 64)
			return &LiteralExprNode{Value: f}
		}
		n, _ := strconv.Atoi(val)
		return &LiteralExprNode{Value: n}
	case tokTrue:
		p.eat(tokTrue)
		return &LiteralExprNode{Value: true}
	case tokFalse:
		p.eat(tokFalse)
		return &LiteralExprNode{Value: false}
	case tokLBracket:
		p.eat(tokLBracket)
		var items []ExprNode
		for p.tok.kind != tokRBracket && p.tok.kind != tokEOF {
			items = append(items, p.parsePrimary())
			if p.tok.kind == tokComma {
				p.eat(tokComma)
			}
		}
		p.eat(tokRBracket)
		return &ListExprNode{Items: items}
	default:
		panic(fmt.Sprintf("unexpected token in expression: %v", p.tok))
	}
}

func dslv2Parse(input string) (*Program, error) {
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	parser := newParser(input)
	return parser.parseProgram(), nil
}

func validateAST(node ASTNode) error {
	switch n := node.(type) {
	case *Program:
		for _, s := range n.Statements {
			if err := validateAST(s); err != nil {
				return err
			}
		}
	case *IfNode:
		if err := validateExpr(n.Condition); err != nil {
			return err
		}
		for _, s := range n.ThenBlock {
			if err := validateAST(s); err != nil {
				return err
			}
		}
		for _, s := range n.ElseBlock {
			if err := validateAST(s); err != nil {
				return err
			}
		}
	case *ForNode:
		if err := validateExpr(n.ListExpr); err != nil {
			return err
		}
		for _, s := range n.Body {
			if err := validateAST(s); err != nil {
				return err
			}
		}
	case *AssignNode:
		if err := validateExpr(n.Value); err != nil {
			return err
		}
	case *AssertNode:
		if err := validateExpr(n.Condition); err != nil {
			return err
		}
	case *CaptureNode:
		if err := validateExpr(n.Field); err != nil {
			return err
		}
		if n.Pattern == "" {
			return fmt.Errorf("empty capture pattern")
		}
		if _, err := regexp.Compile(n.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", n.Pattern, err)
		}
	case *RequestNode:
		if n.URL == "" {
			return fmt.Errorf("empty REQUEST URL")
		}
		if strings.HasPrefix(n.URL, "http://localhost") || strings.HasPrefix(n.URL, "http://127.") || strings.Contains(n.URL, "@") {
			return fmt.Errorf("potentially unsafe URL: %s", n.URL)
		}
	case *HTTPTimeNode:
		if n.URL == "" {
			return fmt.Errorf("empty HTTP_TIME URL")
		}
		if strings.HasPrefix(n.URL, "http://localhost") || strings.HasPrefix(n.URL, "http://127.") || strings.Contains(n.URL, "@") {
			return fmt.Errorf("potentially unsafe URL: %s", n.URL)
		}
	case *CondNode:
		if err := validateExpr(n.Condition); err != nil {
			return err
		}
	case *ReturnNode:
	default:
		return fmt.Errorf("unknown AST node type: %T", node)
	}
	return nil
}

func validateExpr(expr ExprNode) error {
	switch e := expr.(type) {
	case *BinaryExpr:
		if err := validateExpr(e.Left); err != nil {
			return err
		}
		if err := validateExpr(e.Right); err != nil {
			return err
		}
		validOps := map[string]bool{"==": true, "!=": true, ">": true, "<": true, ">=": true, "<=": true, "contains": true, "AND": true, "OR": true}
		if !validOps[e.Op] {
			return fmt.Errorf("unknown operator: %s", e.Op)
		}
	case *UnaryExpr:
		if err := validateExpr(e.Expr); err != nil {
			return err
		}
		if e.Op != "NOT" {
			return fmt.Errorf("unknown unary operator: %s", e.Op)
		}
	case *FieldExprNode:
		validFields := []string{
			"critical_paths", "open_ports", "subdomains", "sql_errors", "cors_issues",
			"cookie_issues", "missing_security_headers", "discovered_paths", "cve_findings",
			"cvss_scores", "ssti_results", "graphql_vulns", "dsl_results", "jwt_tokens",
			"admin_panels", "source_leak", "backup_files", "emails_found", "waf_detected",
			"anomaly_hints", "screenshots", "hsts_enabled", "http_to_https_redirect",
			"clickjacking_protected", "xss_reflection", "trace_enabled", "ssl_weak_cipher",
			"ssl_expiry_days", "mixed_content", "server_node", "open_redirect", "host_header_inject",
			"risk_score", "risk_level", "status_code", "target", "ip", "host", "server_banner",
			"port", "normalized_url", "response_time_ms", "scan_duration_ms", "directory_listing",
		}
		valid := false
		for _, f := range validFields {
			if f == e.Name {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown field: %s", e.Name)
		}
	case *VarExprNode, *LiteralExprNode, *ListExprNode:
	default:
		return fmt.Errorf("unknown expression type: %T", expr)
	}
	return nil
}

func DSLv2Evaluate(r *model.Report) []model.DSLResult {
	dslPath := "dsl_rules.json"
	data, err := os.ReadFile(dslPath)
	if err != nil {
		return nil
	}

	var allResults []model.DSLResult

	var plainLines []string
	if json.Unmarshal(data, &plainLines) == nil && len(plainLines) > 0 {
		prog, err := dslv2Parse(strings.Join(plainLines, "\n"))
		if err == nil {
			if err := validateAST(prog); err == nil {
				results := dslv2Execute(prog, r, make(map[string]any))
				allResults = append(allResults, results...)
				return allResults
			}
		}
	}

	allResults = append(allResults, dslv2ParseJSON(data, r)...)
	return allResults
}

func dslv2ParseJSON(data []byte, r *model.Report) []model.DSLResult {
	var programs []json.RawMessage
	if err := json.Unmarshal(data, &programs); err != nil {
		var single json.RawMessage
		if json.Unmarshal(data, &single) == nil {
			programs = append(programs, single)
		}
	}

	var allResults []model.DSLResult
	for _, prog := range programs {
		var lines []string
		if json.Unmarshal(prog, &lines) == nil {
			ast, err := dslv2Parse(strings.Join(lines, "\n"))
			if err == nil {
				if err := validateAST(ast); err == nil {
					results := dslv2Execute(ast, r, make(map[string]any))
					allResults = append(allResults, results...)
				}
			}
			continue
		}

		var single map[string]any
		if json.Unmarshal(prog, &single) == nil {
			if cond, ok := single["condition"].(string); ok && cond != "" {
				ast, err := dslv2Parse(cond)
				if err == nil {
					if err := validateAST(ast); err == nil {
						condExpr := &CondNode{Condition: nil}
						if len(ast.Statements) > 0 {
							if cn, ok := ast.Statements[0].(*CondNode); ok {
								condExpr = cn
							}
						}
						if dslv2EvalBool(condExpr.Condition, make(map[string]any), r) {
							allResults = append(allResults, model.DSLResult{
								Rule:      fmt.Sprintf("%v", single["name"]),
								Severity:  fmt.Sprintf("%v", single["severity"]),
								Detail:    fmt.Sprintf("%v", single["message"]),
								Condition: cond,
							})
						}
					}
				}
			}
		}
	}
	return allResults
}

func dslv2Execute(node ASTNode, r *model.Report, vars map[string]any) []model.DSLResult {
	var results []model.DSLResult

	switch n := node.(type) {
	case *Program:
		for _, s := range n.Statements {
			results = append(results, dslv2Execute(s, r, vars)...)
		}
	case *IfNode:
		if dslv2EvalBool(n.Condition, vars, r) {
			for _, s := range n.ThenBlock {
				results = append(results, dslv2Execute(s, r, vars)...)
			}
		} else {
			for _, s := range n.ElseBlock {
				results = append(results, dslv2Execute(s, r, vars)...)
			}
		}
	case *ForNode:
		items := dslv2EvalList(n.ListExpr, r)
		for _, item := range items {
			varsCopy := make(map[string]any)
			for k, v := range vars {
				varsCopy[k] = v
			}
			varsCopy[n.VarName] = item
			for _, s := range n.Body {
				results = append(results, dslv2Execute(s, r, varsCopy)...)
			}
		}
	case *AssignNode:
		vars[n.VarName] = dslv2EvalValue(n.Value, vars, r)
	case *AssertNode:
		if !dslv2EvalBool(n.Condition, vars, r) {
			results = append(results, model.DSLResult{
				Rule: "ASSERT", Severity: "HIGH",
				Detail:    fmt.Sprintf("Assertion failed: %s", dslv2ExprToString(n.Condition)),
				Condition: dslv2ExprToString(n.Condition),
			})
		}
	case *CaptureNode:
		fieldVal := dslv2EvalValue(n.Field, vars, r)
		re := regexp.MustCompile(n.Pattern)
		matches := re.FindAllString(fmt.Sprintf("%v", fieldVal), -1)
		if len(matches) > 0 {
			maxShow := len(matches)
			if maxShow > 5 {
				maxShow = 5
			}
			results = append(results, model.DSLResult{
				Rule: fmt.Sprintf("CAPTURE %s", n.Pattern), Severity: "INFO",
				Detail: fmt.Sprintf("Found %d matches in field: %s", len(matches), strings.Join(matches[:maxShow], ", ")),
			})
		}
	case *RequestNode:
		client, _ := NewHTTPClient("", 5)
		if client != nil {
			resp, _, err := client.Get(n.URL, nil)
			if err == nil && resp != nil {
				buf := make([]byte, 10000)
				bn, _ := resp.Body.Read(buf)
				if strings.Contains(string(buf[:bn]), n.Contains) {
					results = append(results, model.DSLResult{
						Rule: fmt.Sprintf("REQUEST %s", n.URL), Severity: "INFO",
						Detail: fmt.Sprintf("Response contains '%s'", n.Contains),
					})
				}
			}
			client.Close()
		}
	case *HTTPTimeNode:
		client, _ := NewHTTPClient("", 5)
		if client != nil {
			_, elapsed, err := client.Get(n.URL, nil)
			if err == nil {
				ms := int(elapsed.Milliseconds())
				triggered := false
				if n.Op == "<" && ms > n.Threshold {
					triggered = true
				}
				if n.Op == ">" && ms < n.Threshold {
					triggered = true
				}
				if triggered {
					results = append(results, model.DSLResult{
						Rule: fmt.Sprintf("HTTP_TIME %s", n.URL), Severity: "MEDIUM",
						Detail: fmt.Sprintf("Response time %dms %s %dms threshold", ms, n.Op, n.Threshold),
					})
				}
			}
			client.Close()
		}
	case *ReturnNode:
		return results
	case *CondNode:
		if dslv2EvalBool(n.Condition, vars, r) {
			results = append(results, model.DSLResult{
				Rule: "condition", Severity: "INFO",
				Detail:    fmt.Sprintf("Condition met: %s", dslv2ExprToString(n.Condition)),
				Condition: dslv2ExprToString(n.Condition),
			})
		}
	}
	return results
}

func dslv2EvalBool(expr ExprNode, vars map[string]any, r *model.Report) bool {
	if expr == nil {
		return false
	}

	switch e := expr.(type) {
	case *BinaryExpr:
		switch e.Op {
		case "AND":
			return dslv2EvalBool(e.Left, vars, r) && dslv2EvalBool(e.Right, vars, r)
		case "OR":
			return dslv2EvalBool(e.Left, vars, r) || dslv2EvalBool(e.Right, vars, r)
		default:
			left := dslv2EvalValue(e.Left, vars, r)
			right := dslv2EvalValue(e.Right, vars, r)
			return dslv2Compare(left, e.Op, right)
		}
	case *UnaryExpr:
		return !dslv2EvalBool(e.Expr, vars, r)
	case *FieldExprNode:
		val := dslv2GetField(e.Name, r)
		if e.IsCount {
			val = dslv2GetListLen(e.Name, r)
		}
		switch v := val.(type) {
		case bool:
			return v
		case int:
			return v != 0
		case string:
			return v != "" && v != "false" && v != "0"
		}
		return val != nil
	default:
		val := dslv2EvalValue(expr, vars, r)
		switch v := val.(type) {
		case bool:
			return v
		default:
			return val != nil && fmt.Sprintf("%v", val) != "" && fmt.Sprintf("%v", val) != "0" && fmt.Sprintf("%v", val) != "false"
		}
	}
}

func dslv2EvalValue(expr ExprNode, vars map[string]any, r *model.Report) any {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case *BinaryExpr:
		left := dslv2EvalValue(e.Left, vars, r)
		right := dslv2EvalValue(e.Right, vars, r)
		return dslv2Compare(left, e.Op, right)
	case *UnaryExpr:
		return !dslv2EvalBool(e.Expr, vars, r)
	case *VarExprNode:
		if val, ok := vars[e.Name]; ok {
			return val
		}
		return nil
	case *FieldExprNode:
		if e.IsCount {
			return dslv2GetListLen(e.Name, r)
		}
		return dslv2GetField(e.Name, r)
	case *LiteralExprNode:
		return e.Value
	case *ListExprNode:
		var items []string
		for _, item := range e.Items {
			val := dslv2EvalValue(item, vars, r)
			items = append(items, fmt.Sprintf("%v", val))
		}
		return items
	}
	return nil
}

func dslv2EvalList(expr ExprNode, r *model.Report) []any {
	switch e := expr.(type) {
	case *FieldExprNode:
		return dslv2GetList(e.Name, r)
	case *ListExprNode:
		var items []any
		for _, item := range e.Items {
			if lit, ok := item.(*LiteralExprNode); ok {
				items = append(items, lit.Value)
			}
		}
		return items
	}
	return nil
}

func dslv2ExprToString(expr ExprNode) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *BinaryExpr:
		if e.Op == "AND" || e.Op == "OR" {
			return fmt.Sprintf("%s %s %s", dslv2ExprToString(e.Left), e.Op, dslv2ExprToString(e.Right))
		}
		return fmt.Sprintf("%s %s %s", dslv2ExprToString(e.Left), e.Op, dslv2ExprToString(e.Right))
	case *UnaryExpr:
		return fmt.Sprintf("NOT %s", dslv2ExprToString(e.Expr))
	case *VarExprNode:
		return "$" + e.Name
	case *FieldExprNode:
		if e.IsCount {
			return e.Name + "_count"
		}
		return e.Name
	case *LiteralExprNode:
		return fmt.Sprintf("%v", e.Value)
	}
	return ""
}

func dslv2Compare(left any, op string, right any) bool {
	leftFloat := dslv2ToFloat(left)
	rightFloat := dslv2ToFloat(right)
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	switch op {
	case "==":
		if leftStr == rightStr {
			return true
		}
		return leftFloat == rightFloat
	case "!=":
		return leftStr != rightStr && leftFloat != rightFloat
	case ">":
		return leftFloat > rightFloat
	case "<":
		return leftFloat < rightFloat
	case ">=":
		return leftFloat >= rightFloat
	case "<=":
		return leftFloat <= rightFloat
	case "contains":
		return strings.Contains(leftStr, rightStr)
	}
	return false
}

func dslv2ToFloat(v any) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case float64:
		return val
	case bool:
		if val {
			return 1
		}
		return 0
	case string:
		n, _ := strconv.ParseFloat(val, 64)
		return n
	}
	return 0
}

func dslv2GetField(field string, r *model.Report) any {
	switch field {
	case "target":
		return r.Target
	case "ip":
		return r.IP
	case "host":
		return r.Host
	case "status_code":
		return r.StatusCode
	case "risk_score":
		return r.RiskScore
	case "risk_level":
		return r.RiskLevel
	case "hsts_enabled":
		return r.HSTSEnabled
	case "http_to_https_redirect":
		return r.HTTPToHTTPSRedirect
	case "clickjacking_protected":
		return r.ClickjackingProtected
	case "xss_reflection":
		return r.XSSReflection
	case "trace_enabled":
		return r.TraceEnabled
	case "ssl_weak_cipher":
		return r.SSLWeakCipher
	case "ssl_expiry_days":
		return r.SSLExpiryDays
	case "mixed_content":
		return r.MixedContent
	case "server_node":
		return r.ServerNode
	case "server_banner":
		return r.ServerBanner
	case "waf_detected":
		return strings.Join(r.WAFDetected, ", ")
	case "open_redirect":
		return strings.Join(r.OpenRedirect, ", ")
	case "host_header_inject":
		return r.HostHeaderInject
	case "response_time_ms":
		return r.ResponseTimeMs
	case "scan_duration_ms":
		return r.ScanDurationMs
	case "port":
		return r.Port
	case "normalized_url":
		return r.NormalizedURL
	case "directory_listing":
		return len(r.DirectoryListing) > 0
	default:
		return nil
	}
}

func dslv2GetListLen(field string, r *model.Report) int {
	switch field {
	case "critical_paths":
		return len(r.CriticalPaths)
	case "open_ports":
		return len(r.OpenPorts)
	case "subdomains":
		return len(r.Subdomains)
	case "sql_errors":
		return len(r.SQLErrors)
	case "cors_issues":
		return len(r.CORSIssues)
	case "cookie_issues":
		return len(r.CookieIssues)
	case "missing_security_headers":
		return len(r.MissingSecurityHeaders)
	case "discovered_paths":
		return len(r.DiscoveredPaths)
	case "cve_findings":
		return len(r.CVEFindings)
	case "cvss_scores":
		return len(r.CVSSScores)
	case "ssti_results":
		return len(r.SSTIResults)
	case "graphql_vulns":
		return len(r.GraphQLVulns)
	case "dsl_results":
		return len(r.DSLResults)
	case "jwt_tokens":
		return len(r.JWTTokens)
	case "admin_panels":
		return len(r.AdminPanels)
	case "source_leak":
		return len(r.SourceLeak)
	case "backup_files":
		return len(r.BackupFiles)
	case "emails_found":
		return len(r.EmailsFound)
	case "screenshots":
		return len(r.Screenshots)
	case "waf_detected":
		return len(r.WAFDetected)
	case "anomaly_hints":
		return len(r.AnomalyHints)
	}
	return 0
}

func dslv2GetList(field string, r *model.Report) []any {
	switch field {
	case "open_ports":
		var items []any
		for _, p := range r.OpenPorts {
			items = append(items, p)
		}
		return items
	case "subdomains":
		var items []any
		for _, s := range r.Subdomains {
			items = append(items, s)
		}
		return items
	case "critical_paths":
		var items []any
		for _, p := range r.CriticalPaths {
			items = append(items, p)
		}
		return items
	case "missing_security_headers":
		var items []any
		for _, h := range r.MissingSecurityHeaders {
			items = append(items, h)
		}
		return items
	case "cve_findings":
		var items []any
		for _, c := range r.CVEFindings {
			items = append(items, c.CVE)
		}
		return items
	case "emails_found":
		var items []any
		for _, e := range r.EmailsFound {
			items = append(items, e)
		}
		return items
	case "waf_detected":
		var items []any
		for _, w := range r.WAFDetected {
			items = append(items, w)
		}
		return items
	case "discovered_paths":
		var items []any
		for _, p := range r.DiscoveredPaths {
			items = append(items, p.Path)
		}
		return items
	default:
		return nil
	}
}
