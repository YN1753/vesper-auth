package server

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/web"
)

// Renderer renders embedded HTML templates and serves embedded static files.
type Renderer struct {
	templates *template.Template
	staticFS  http.Handler
}

// NewRenderer parses embedded HTML templates and prepares the static asset handler.
func NewRenderer() (*Renderer, error) {
	tmpl, err := template.ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	return &Renderer{
		templates: tmpl,
		staticFS:  http.FileServer(http.FS(sub)),
	}, nil
}

// StaticHandler serves /static/* assets from embed.FS.
func (r *Renderer) StaticHandler() http.Handler {
	return http.StripPrefix("/static/", r.staticFS)
}

// SetupViewData supplies template data for /setup.
type SetupViewData struct {
	IssuerHost   string
	DefaultUser  string
	DefaultEmail string
}

// LoginViewData supplies template data for /login.
type LoginViewData struct {
	IssuerHost    string
	PendingClient string
	LoggedOut     bool
	ReqIDJSON     template.JS
	NextURLJSON   template.JS
}

// AdminViewData supplies template data for /.
type AdminViewData struct {
	Issuer        string
	Username      string
	Email         string
	DisplayName   string
	IssuerJSON    template.JS
	CSRFTokenJSON template.JS
}

// ErrorViewData supplies template data for error pages.
type ErrorViewData struct {
	Status  int
	Title   string
	Message string
}

// RenderSetup renders the first-boot administrator initialization page.
func (r *Renderer) RenderSetup(w http.ResponseWriter, data SetupViewData) {
	r.exec(w, http.StatusOK, "setup.html", data)
}

// RenderLogin renders the login page.
func (r *Renderer) RenderLogin(w http.ResponseWriter, data LoginViewData) {
	r.exec(w, http.StatusOK, "login.html", data)
}

// RenderConsent implements oidc.TemplateRenderer for OAuth2 consent.
func (r *Renderer) RenderConsent(w http.ResponseWriter, data oidc.ConsentViewData) {
	r.exec(w, http.StatusOK, "consent.html", data)
}

// RenderError implements oidc.TemplateRenderer and renders general error screens.
func (r *Renderer) RenderError(w http.ResponseWriter, status int, title, message string) {
	r.exec(w, status, "error.html", ErrorViewData{
		Status:  status,
		Title:   title,
		Message: message,
	})
}

// RenderAdmin renders the main management console.
func (r *Renderer) RenderAdmin(w http.ResponseWriter, data AdminViewData) {
	r.exec(w, http.StatusOK, "admin.html", data)
}

func (r *Renderer) exec(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = r.templates.ExecuteTemplate(w, name, data)
}

func toJSString(s string) template.JS {
	b, _ := json.Marshal(s)
	return template.JS(b)
}
