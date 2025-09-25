// Package httpx provides HTTP handlers and middleware for the authentication flow.
package httpx

import (
	_ "embed"
	"html/template"
)

// Embedded template content

//go:embed templates/callback-ok.tmpl
var callbackSuccessContent string

//go:embed templates/error.tmpl
var errorContent string

// ParsedTemplates holds pre-parsed templates
var (
	CallbackSuccessTmpl *template.Template
	ErrorTmpl           *template.Template
)

func init() {
	var err error
	CallbackSuccessTmpl, err = template.New("callback-ok").Parse(callbackSuccessContent)
	if err != nil {
		panic("failed to parse callback-ok template: " + err.Error())
	}

	ErrorTmpl, err = template.New("error").Parse(errorContent)
	if err != nil {
		panic("failed to parse error template: " + err.Error())
	}
}
