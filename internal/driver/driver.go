// Package driver defines how platform drivers are described and constructed.
package driver

import (
	"context"
	"net/http"

	"github.com/c0dn/ctfx/internal/config"
	"github.com/c0dn/ctfx/pkg/ctf"
)

// Env is what a driver gets at construction time.
type Env struct {
	Config *config.Config
	Client *http.Client
}

// Spec describes a driver.
type Spec struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Kind        string `json:"kind"` // builtin or exec
	Path        string `json:"path,omitempty"`
	// Example is the env-file template written by `ctfx init`.
	Example string                             `json:"-"`
	New     func(env *Env) (ctf.Driver, error) `json:"-"`
	// Detect probes a URL the user pasted and reports whether it is this
	// platform. It must be read-only, unauthenticated, and cheap (a couple of
	// GETs at most). Optional.
	Detect func(ctx context.Context, c *http.Client, rawURL string) (*Detection, bool) `json:"-"`
}

// Detection is a successful probe: the normalized base URL and any extra
// profile values derived from the URL (eg a game or event ID).
type Detection struct {
	BaseURL string            `json:"base_url"`
	Values  map[string]string `json:"values,omitempty"`
}
