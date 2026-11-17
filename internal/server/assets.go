package server

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/web"
)

// Renderer renders embedded HTML templates and serves content-fingerprinted static files.
type Renderer struct {
	templates   *template.Template
	staticFS    http.Handler
	assetHashes map[string]string
}

// NewRenderer computes SHA-256 fingerprints for embedded static files and parses HTML templates.
func NewRenderer() (*Renderer, error) {
	hashes := make(map[string]string)
	err := fs.WalkDir(web.FS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rErr := fs.ReadFile(web.FS, path)
		if rErr != nil {
			return rErr
		}
		sum := sha256.Sum256(raw)
		urlPath := "/" + strings.TrimLeft(path, "/")
		hashes[urlPath] = hex.EncodeToString(sum[:])[:10]
		return nil
	})
	if err != nil {
		return nil, err
	}

	sub, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}

	r := &Renderer{
		staticFS:    http.FileServer(http.FS(sub)),
		assetHashes: hashes,
	}

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"asset": r.AssetURL,
	}).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	r.templates = tmpl
	return r, nil
}

// AssetURL appends the embedded content hash query parameter to a /static/ path.
func (r *Renderer) AssetURL(urlPath string) string {
	if h, ok := r.assetHashes[urlPath]; ok {
		return urlPath + "?v=" + h
	}
	return urlPath
}

// StaticHandler serves /static/* assets with immutable caching when ?v= matches the content hash.
func (r *Renderer) StaticHandler() http.Handler {
	stripped := http.StripPrefix("/static/", r.staticFS)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expectedHash, ok := r.assetHashes[req.URL.Path]
		if ok {
			w.Header().Set("ETag", `"`+expectedHash+`"`)
			if v := req.URL.Query().Get("v"); v != "" && v == expectedHash {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "public, max-age=60")
			}
		}
		stripped.ServeHTTP(w, req)
	})
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
	Reauth        bool
	ReqID         string
	NextURL       string
}

// AdminViewData supplies template data for /.
type AdminViewData struct {
	Issuer      string
	Username    string
	Email       string
	DisplayName string
	CSRFToken   string
	Version     string
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

// RenderLogoutConfirm implements oidc.TemplateRenderer for anti-CSRF OIDC logout confirmation.
func (r *Renderer) RenderLogoutConfirm(w http.ResponseWriter, data oidc.LogoutConfirmViewData) {
	r.exec(w, http.StatusOK, "logout.html", data)
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
