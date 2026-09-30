// Package drivers is the driver registry: built-ins plus exec plugins.
package drivers

import (
	"context"
	"net/http"
	"sort"

	"github.com/c0dn/ctfx/internal/driver"
	"github.com/c0dn/ctfx/internal/drivers/ctfd"
	"github.com/c0dn/ctfx/internal/drivers/exec"
	"github.com/c0dn/ctfx/internal/drivers/gzctf"
	"github.com/c0dn/ctfx/internal/drivers/htb"
	"github.com/c0dn/ctfx/internal/drivers/rctf"
)

var builtin = []driver.Spec{ctfd.Spec, rctf.Spec, gzctf.Spec, htb.Spec}

// Builtin returns the built-in driver names.
func Builtin() []string {
	names := make([]string, len(builtin))
	for i, s := range builtin {
		names[i] = s.Name
	}
	return names
}

// Detect probes rawURL against each built-in driver that supports detection
// and returns the first match.
func Detect(ctx context.Context, c *http.Client, rawURL string) (driver.Spec, *driver.Detection, bool) {
	for _, s := range builtin {
		if s.Detect == nil {
			continue
		}
		if det, ok := s.Detect(ctx, c, rawURL); ok {
			return s, det, true
		}
	}
	return driver.Spec{}, nil, false
}

// Lookup finds a driver by name. Built-ins win over plugins of the same name.
func Lookup(root, name string) (driver.Spec, bool) {
	for _, s := range builtin {
		if s.Name == name {
			return s, true
		}
	}
	if p := exec.Find(root, name); p != "" {
		return exec.Spec(name, p), true
	}
	return driver.Spec{}, false
}

// All lists built-ins and discoverable plugins.
func All(root string) []driver.Spec {
	out := append([]driver.Spec(nil), builtin...)
	seen := map[string]bool{}
	for _, s := range builtin {
		seen[s.Name] = true
	}
	var plugins []driver.Spec
	for name, p := range exec.List(root) {
		if !seen[name] {
			plugins = append(plugins, exec.Spec(name, p))
		}
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Name < plugins[j].Name })
	return append(out, plugins...)
}
