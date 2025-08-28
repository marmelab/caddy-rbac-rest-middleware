package plugin

import (
	"encoding/json"
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

const (
	// TODO - get that from JWT instead
	role = "accountant"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("simple_rest_rbac", parseCaddyfile)
}

// ActionType represents an action that can be either a single string or a slice of strings
type ActionType struct {
	Single   *string   `json:"-"`
	Multiple []string  `json:"-"`
}

// Permission represents a single permission rule
type Permission struct {
	Type     string     `json:"type,omitempty"`     // "allow" (default) or "deny"
	Action   ActionType `json:"action"`             // string or []string
	Resource string     `json:"resource"`           // resource pattern
}

// RoleDefinition represents a list of permissions for a role
type RoleDefinition []Permission

// RoleDefinitions represents the mapping of role names to their permissions
type RoleDefinitions map[string]RoleDefinition

// UnmarshalJSON implements json.Unmarshaler for RoleDefinitions
func (rd *RoleDefinitions) UnmarshalJSON(data []byte) error {
	var raw map[string][]map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	
	*rd = make(RoleDefinitions)
	for roleName, permissions := range raw {
		var roleDef RoleDefinition
		for _, perm := range permissions {
			permission := Permission{}
			
			// Handle type field
			if t, ok := perm["type"].(string); ok {
				permission.Type = t
			}
			
			// Handle resource field
			if r, ok := perm["resource"].(string); ok {
				permission.Resource = r
			}
			
			// Handle action field (string or []string)
			if action, ok := perm["action"]; ok {
				switch v := action.(type) {
				case string:
					permission.Action.Single = &v
				case []interface{}:
					var actions []string
					for _, item := range v {
						if str, ok := item.(string); ok {
							actions = append(actions, str)
						}
					}
					permission.Action.Multiple = actions
				}
			}
			
			roleDef = append(roleDef, permission)
		}
		(*rd)[roleName] = roleDef
	}
	
	return nil
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

// getActionFromMethod determines the action based on HTTP method and presence of record ID
func getActionFromMethod(method string, hasRecordID bool) string {
	switch method {
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

// canAccessWithPermissions checks if permissions allow the given action on the given resource
func canAccessWithPermissions(permissions []Permission, action, resource string) bool {
	if len(permissions) == 0 {
		return false
	}
	
	// If one deny permission matches, return false
	for _, permission := range permissions {
		if permission.Type == "deny" && matchTarget(permission, resource, action) {
			return false
		}
	}
	
	// If one allow permission matches, return true
	for _, permission := range permissions {
		if permission.Type != "deny" && matchTarget(permission, resource, action) {
			return true
		}
	}
	
	return false
}

// matchTarget checks if a permission matches a target (action, resource)
func matchTarget(permission Permission, resource, action string) bool {
	// Check resource match (with wildcard support)
	if !matchWildcard(permission.Resource, resource) {
		return false
	}
	
	// If action is empty or wildcard, always match
	if action == "" || action == "*" {
		return true
	}
	
	// Check action match
	if permission.Action.Multiple != nil {
		// Multiple actions case
		for _, a := range permission.Action.Multiple {
			if a == "*" || a == action {
				return true
			}
		}
		return false
	} else if permission.Action.Single != nil {
		// Single action case
		return *permission.Action.Single == "*" || *permission.Action.Single == action
	}
	
	return false
}

// matchWildcard checks if a pattern matches a resource with wildcard support
func matchWildcard(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == resource {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(resource, pattern[:len(pattern)-1])
	}
	return false
}

// Middleware implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type Middleware struct {
	RolesFilePath string          `json:"roles,omitempty"`
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
		return fmt.Errorf("no roles defined")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract resource from URL path
	resource := extractResource(r.URL.Path)
	if resource == "" {
		// No resource in path, allow request to continue
		return next.ServeHTTP(w, r)
	}
	
	// Extract record ID from URL path
	recordID := extractRecordID(r.URL.Path)
	hasRecordID := recordID != ""
	
	// Determine action from HTTP method
	action := getActionFromMethod(r.Method, hasRecordID)
	if action == "" {
		// Unknown method, deny access
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
	
	// Get permissions for the current role
	permissions, exists := m.roles[role]
	if !exists {
		m.logger.Warn("Role not found", zap.String("role", role))
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("role not found: %s", role))
	}
	
	// Check if access is allowed
	if !canAccessWithPermissions(permissions, action, resource) {
		m.logger.Info("Access denied", 
			zap.String("role", role),
			zap.String("action", action),
			zap.String("resource", resource),
			zap.String("record_id", recordID),
		)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied"))
	}
	
	// Access allowed, continue to next handler
	m.logger.Info("Access granted", 
		zap.String("role", role),
		zap.String("action", action),
		zap.String("resource", resource),
		zap.String("record_id", recordID),
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
			case "roles":
				m.RolesFilePath = arg
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