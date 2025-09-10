package plugin

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("simple_rest_rbac", parseCaddyfile)
}

// extractResource extracts the resource name from the URL path
// E.g. "/foo/bar/baz" returns "foo"
func extractResource(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// extractRecordID extracts the record ID from the URL path
// E.g. "/foo/bar/baz" returns "bar"
func extractRecordID(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}
	return ""
}

// getActionFromRequest determines the action based on the HTTP request
func getActionFromRequest(r *http.Request) string {
	recordID := extractRecordID(r.URL.Path)
	hasRecordID := recordID != ""
	
	switch r.Method {
	case "GET":
		if hasRecordID {
			return "show"
		}
		return "list"
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "edit"
	case "DELETE":
		return "delete"
	default:
		return ""
	}
}

// Middleware implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type Middleware struct {
	Role          string          `json:"role,omitempty"`
	RolesFilePath string          `json:"roles_file,omitempty"`
	roles         RoleDefinitions
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.simple_rest_rbac",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	file, err := os.ReadFile(m.RolesFilePath)
	if err != nil {
		return err
	}
  var rd RoleDefinitions
	if err := rd.UnmarshalJSON(file); err != nil {
		return err
	}
	m.roles = rd

	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.roles == nil {
		return fmt.Errorf("no role permissions defined")
	}
	if m.Role == "" {
		return fmt.Errorf("no role defined")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
  // Retrieve the replacer from the request context
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Extract resource from URL path
	resource := extractResource(r.URL.Path)
	if resource == "" {
		// No resource in path, allow request to continue
		return next.ServeHTTP(w, r)
	}
	
	// Determine action from HTTP request
	action := getActionFromRequest(r)
	if action == "" {
		// Unknown method, deny access
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Resolve placeholders in the role
	resolvedRole := repl.ReplaceAll(m.Role, "")
	resolvedRole = strings.TrimSpace(resolvedRole)

	if resolvedRole == "" {
		// No role defined, deny access
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("role not defined"))
	}
	
	// Get permissions for the current role
	permissions, exists := m.roles[resolvedRole]
	if !exists {
		m.logger.Warn("Role not found", zap.String("role", resolvedRole))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("role not found: %s", resolvedRole))
	}
	
	// Check if access is allowed
	if !canAccessWithPermissions(permissions, action, resource) {
		m.logger.Info("Access denied", 
			zap.String("role", resolvedRole),
			zap.String("action", action),
			zap.String("resource", resource),
		)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied"))
	}
	
	// Access allowed, continue to next handler
	m.logger.Info("Access granted", 
		zap.String("role", resolvedRole),
		zap.String("action", action),
		zap.String("resource", resource),
	)
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		param := d.Val()
		var arg string
		if !d.Args(&arg) {
			return d.ArgErr()
		}
		switch param {
			case "roles_file":
				m.RolesFilePath = arg
			case "role":
				m.Role = arg
			default:
				return d.Errf("unknown subdirective: %s", param)
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)