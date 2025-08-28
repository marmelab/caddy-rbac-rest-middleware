package plugin

import (
	"encoding/json"
)

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
