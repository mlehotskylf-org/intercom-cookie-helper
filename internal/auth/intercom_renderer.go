package auth

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/identify_intercom.tmpl
var intercomTemplateContent string

// Pre-parse the template at startup
var intercomTemplate *template.Template

func init() {
	var err error
	intercomTemplate, err = template.New("identify_intercom").Parse(intercomTemplateContent)
	if err != nil {
		panic(fmt.Sprintf("failed to parse Intercom template: %v", err))
	}
}

// IntercomRenderer implements IdentifyRenderer for Intercom authentication.
type IntercomRenderer struct {
	AppID  string
	Secret []byte
	TTL    time.Duration
}

// intercomTemplateData holds the data for the Intercom HTML template.
type intercomTemplateData struct {
	AppID    string
	JWT      string
	UserID   string
	Email    string
	Name     string
	ReturnTo string
}

// Render creates an Intercom JWT and renders HTML that boots the Messenger and redirects.
func (r *IntercomRenderer) Render(w http.ResponseWriter, p IdentifyPayload) error {
	// Validate required fields
	if r.AppID == "" {
		return fmt.Errorf("intercom app ID is required")
	}
	if len(r.Secret) == 0 {
		return fmt.Errorf("intercom secret is required")
	}
	if p.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if p.ReturnTo == "" {
		return fmt.Errorf("return URL is required")
	}

	// Create JWT claims
	now := time.Now()
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute // Default TTL
	}

	claims := IntercomClaims{
		UserID: p.Subject,
		Email:  p.Email,
		Name:   p.Name,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
	}

	// Mint the JWT
	token, err := MintIntercomJWT(r.Secret, claims)
	if err != nil {
		return fmt.Errorf("failed to mint JWT: %w", err)
	}

	// Prepare template data
	data := intercomTemplateData{
		AppID:    r.AppID,
		JWT:      token,
		UserID:   p.Subject,
		Email:    p.Email,
		Name:     p.Name,
		ReturnTo: p.ReturnTo,
	}

	// Set headers
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")

	// Execute template
	if err := intercomTemplate.Execute(w, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}
