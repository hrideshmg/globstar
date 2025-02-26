package javascript

import (
	sitter "github.com/smacker/go-tree-sitter"
	"globstar.dev/analysis"
)

var SQLInjection = analysis.Analyzer{
	Name:        "sql-injection",
	Language:    analysis.LangJs,
	Description: "Detects potential SQL injection vulnerabilities in JavaScript code",
	Category:    analysis.CategorySecurity,
	Severity:    analysis.SeverityCritical,
	Run:         detectSQLInjection,
}

func detectSQLInjection(pass *analysis.Pass) (interface{}, error) {
	// Map of vulnerable function names to watch for
	vulnerableFunctions := map[string]bool{
		"query":             true,
		"raw":               true,
		"$queryRawUnsafe":   true,
		"$executeRawUnsafe": true,
	}

	// Map to track variable definitions
	varDefinitions := make(map[string]*sitter.Node)

	// First pass: collect all variable definitions
	analysis.Preorder(pass, func(node *sitter.Node) {
		if node == nil || node.Type() != "variable_declarator" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")

		// Ensure that the variable definition is valid
		if nameNode != nil && nameNode.Type() == "identifier" && valueNode != nil {
			varName := getNodeText(nameNode, pass.FileContext.Source)
			if varName != "" {
				varDefinitions[varName] = valueNode
			}
		}
	})

	// Second pass: detect SQL injection vulnerabilities
	analysis.Preorder(pass, func(node *sitter.Node) {
		if node == nil || node.Type() != "call_expression" {
			return
		}

		funcNode := node.ChildByFieldName("function")
		if funcNode == nil {
			return
		}

		// Extract the function name
		var funcName string
		if funcNode.Type() == "member_expression" {
			propertyNode := funcNode.ChildByFieldName("property")

			if propertyNode != nil {
				funcName = getNodeText(propertyNode, pass.FileContext.Source)
			}
		}

		// Check if this is a function we care about
		if !vulnerableFunctions[funcName] {
			return
		}

		// Get the arguments of the function
		args := node.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() == 0 {
			return
		}

		// Check the first argument
		firstArg := args.NamedChild(0)
		if firstArg == nil {
			return
		}

		// If its a variable, look up its definition
		if firstArg.Type() == "identifier" {
			varName := getNodeText(firstArg, pass.FileContext.Source)
			if defNode, exists := varDefinitions[varName]; exists {
				firstArg = defNode
			}
		}

		// Check if the argument is vulnerable
		if isSQLInjectionVulnerable(firstArg, pass.FileContext.Source, varDefinitions) {
			pass.Report(pass, node, "Potential SQL injection vulnerability detected, use parameterized queries instead")
		}
	})

	return nil, nil
}

func isSQLInjectionVulnerable(node *sitter.Node, sourceCode []byte, varDefs map[string]*sitter.Node) bool {
	if node == nil {
		return false
	}

	switch node.Type() {
	case "binary_expression":
		// Check for string concatenation
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")

		// If either side is an identifier, this could be user input
		if (left != nil && left.Type() == "identifier") ||
			(right != nil && right.Type() == "identifier") {
			return true
		}

		// Recursively check both sides
		return isSQLInjectionVulnerable(left, sourceCode, varDefs) ||
			isSQLInjectionVulnerable(right, sourceCode, varDefs)

	case "template_string":
		// Check for template strings with interpolation
		for i := range int(node.NamedChildCount()) {
			child := node.NamedChild(i)
			if child != nil && child.Type() == "template_substitution" {
				return true
			}
		}

	case "identifier":
		// If it's a variable, check its definition (required due to recursion)
		varName := getNodeText(node, sourceCode)
		if defNode, exists := varDefs[varName]; exists {
			return isSQLInjectionVulnerable(defNode, sourceCode, varDefs)
		}
	}

	return false
}

// --- Helper Functions ---

func getNodeText(node *sitter.Node, source []byte) string {
	start := node.StartByte()
	end := node.EndByte()

	return string(source[start:end])
}
