package plugin

import (
	"strings"
)

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
