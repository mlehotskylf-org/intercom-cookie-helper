// Package httpx provides HTTP handlers and middleware for the authentication flow.
package httpx

import (
	_ "embed"
	"html/template"
)

// Embedded template content

//go:embed templates/error.tmpl
var errorContent string

// ParsedTemplates holds pre-parsed templates
var (
	ErrorTmpl *template.Template
)

func init() {
	var err error
	ErrorTmpl, err = template.New("error").Parse(errorContent)
	if err != nil {
		panic("failed to parse error template: " + err.Error())
	}
}
