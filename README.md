# caddy-rbac-rest-middleware

This repository contains the `simple_rest_rbac` [Caddy](https://caddyserver.com) module which implements a simple RBAC middleware for REST APIs.

It makes some [arbitrary assumptions](#limitations) about the REST API, so you can either use it directly if it fits your needs, or use it as a reference implementation to build your own middleware.

## Features

- **Simple Roles Configuration**: uses a [JSON file](#sample-rolesjson) to define roles and their permissions, per resource and action.
- **Easy JWT Integration**: [integrates easily](#example-usage-with-jwt-authentication) with JWT auth modules such as [caddy-jwt](https://github.com/ggicci/caddy-jwt) to obtain the user's role from JWT claims.
- **Wildcard Support**: supports wildcards in resource names for flexible permission definitions.
- **Deny Rules**: supports deny rules that take precedence over allow rules for enhanced security.

## How It Works

This module loads up a roles configuration from a [JSON file](#sample-rolesjson). Each role can have multiple permissions defined by an *action* and a *resource*.

When a request is made, the middleware checks the user's role (which can be [extracted from JWT claims](#example-usage-with-jwt-authentication)) and verifies if the requested action on the specified resource is allowed based on the defined permissions.

If the action is not permitted, the middleware responds with a `403 Forbidden` status code. Otherwise, the request is allowed to proceed.

## Usage

### Building Caddy with the Module

To build Caddy with this module, use [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/marmelab/caddy-rbac-rest-middleware/plugin
```

### Caddyfile Config

To use the `simple_rest_rbac` plugin, add the following directive to your Caddyfile:

```caddyfile
:8080 {
    route {
        simple_rest_rbac {
            roles_file <path-to-roles-file>
            role <role>
        }
        respond "Protected API endpoint."
    }
}
```

### Configuration Options

- `roles_file`: The path to the roles JSON file containing role definitions and their permissions.
- `role`: The role used to determine permissions. This can be a static value but will most likely be a placeholder (e.g., `{http.auth.user.role}`) to extract the role from JWT claims.

## Example Usage with JWT Authentication

The following example demonstrates how to use [caddy-jwt](https://github.com/ggicci/caddy-jwt) to protect an API endpoint with JWT authentication and obtain the role from the JWT claims.

```caddyfile
:8080 {
    route {
        # See https://github.com/ggicci/caddy-jwt
        jwtauth {
            sign_key {file./path/to/jwt-secret.txt}
            sign_alg HS256
            issuer_whitelist https://jwt.example.com
            audience_whitelist "api-endpoint-1"
            user_claims sub
            meta_claims role # this sets the {http.auth.user.role} placeholder
        }
        simple_rest_rbac {
          roles_file /etc/caddy/roles.json
          role {http.auth.user.role}
        }
        reverse_proxy api:3000
    }
}
```

In this example, the `jwtauth` directive is used to authenticate incoming requests using JWTs. The `meta_claims role` line specifies that the user's role should be extracted from the `role` claim in the JWT and made available as the `{http.auth.user.role}` placeholder. This placeholder is then used in the `simple_rest_rbac` directive to determine the user's permissions based on their role.

## Sample `roles.json`

Here is a sample `roles.json` file that can be used with the `simple_rest_rbac` plugin:

```json
{
  "guest": [
    { "action": ["list"], "resource": "posts" },
    { "action": "read", "resource": "posts.*" },
    { "type": "deny", "action": "read", "resource": "posts.views" },
    { "type": "deny", "action": "read", "resource": "posts.average_note" }
  ],
  "user": [
    { "action": ["list", "show"], "resource": "posts" },
    { "action": "read", "resource": "posts.*" },
    { "type": "deny", "action": "read", "resource": "posts.views" },
    { "type": "deny", "action": "read", "resource": "posts.average_note" },
    { "action": ["list", "show", "create"], "resource": "comments" },
    { "action": "read", "resource": "comments.*" },
    { "action": "write", "resource": "comments.*" }
  ],
  "writer": [
    { "action": ["list", "show", "create", "edit"], "resource": "posts" },
    { "action": "read", "resource": "posts.*" },
    { "action": "write", "resource": "posts.*" },
    { "type": "deny", "action": "read", "resource": "posts.views" },
    { "type": "deny", "action": "read", "resource": "posts.average_note" },
    { "type": "deny", "action": "write", "resource": "posts.views" },
    { "type": "deny", "action": "write", "resource": "posts.average_note" },
    { "action": ["list", "show"], "resource": "comments" },
    { "action": "read", "resource": "comments.*" }
  ],
  "moderator": [
    { "action": ["list", "show", "create", "edit"], "resource": "posts" },
    { "action": "read", "resource": "posts.*" },
    { "action": "write", "resource": "posts.*" },
    {
      "action": ["list", "show", "create", "edit", "delete"],
      "resource": "comments"
    },
    { "action": "read", "resource": "comments.*" },
    { "action": "write", "resource": "comments.*" }
  ],
  "admin": [{ "action": "*", "resource": "*" }]
}
```

This example demonstrates the following features:

- **Roles**: Defines five roles: `guest`, `user`, `writer`, `moderator`, and `admin`.
- **Permissions**: Each role has specific permissions for actions (`list`, `show`, `create`, `edit`, `delete`, `read`, `write`) on resources (`posts`, `comments`).
- **Deny Rules**: The `guest`, `user`, and `writer` roles have deny rules that prevent access to sensitive fields like `posts.views` and `posts.average_note`.
- **Wildcard Support**: The use of wildcards (e.g., `posts.*`) allows for flexible permission definitions.

## Limitations

This plugin makes some arbitrary assumptions about the REST API:

- Resources are identified by their names in the URL path (e.g., `/posts`, `/comments`), and are assumed to be the first segment of the path.
- Record identifiers (e.g., `/posts/1`) are assumed to be the second segment of the path.
- Actions are inferred from the HTTP method:
  - `GET` requests are mapped to `list` (for collection endpoints) or `show` (for single record endpoints).
  - `POST` requests are mapped to `create`.
  - `PUT` and `PATCH` requests are mapped to `edit`.
  - `DELETE` requests are mapped to `delete`.

If these assumptions do not fit your API, you may need to modify the code to suit your needs.

Check out the [simple-rest-rbac.go](./plugin/simple-rest-rbac.go) file, and notably the `extractResource`, `extractRecordID` and `getActionFromRequest` functions to get started.

## Included Demo

This repository includes configuration files allowing to run a demo with Caddy, JWT authentication, and the `simple_rest_rbac` middleware.

It requires [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/).

To run the demo:

```bash
# Build the project and Caddy with the plugin
make build
# Start the demo
make run
```

Then, open your browser and navigate to `http://localhost` to access the demo portal.

Demo features:

- A simple [portal](http://localhost/portal) to access various API endpoints.
- JWT authentication with [login](http://localhost/login) and [logout](http://localhost/logout) functionality.
- Role-based access control using the `simple_rest_rbac` middleware.

Check out the [users.json](./caddy/conf/users.json) and [roles.json](./caddy/conf/roles.json) files to see the available users and their roles.

## Development

You can use the [included Demo](#included-demo) to test your changes.

It requires [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/).

Development environment also requires [Node.js](https://nodejs.org/) for the fake API server.

Install the dependencies with:

```bash
make install
```

After modifying the code, rebuild the Docker image and restart the demo:

```bash
make build
make run
```

## Roadmap

- [x] Initial implementation
- [x] Getting the role from JWT claims
- [ ] Support multiple roles per user
- [ ] Field-level permissions (e.g., allow reading `posts.views` but not `posts.average_note`)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Caddy](https://caddyserver.com) for providing a powerful and extensible web server.
- [caddy-jwt](https://github.com/ggicci/caddy-jwt) for `jwtauth`, which provides the JWT Authentication.
- [caddy-jwt-issuer](https://github.com/steffenbusch/caddy-jwt-issuer) for `jwt_issuer`, which provides easy JWT issuing capabilities and great documentation.
- [JSON Server](https://github.com/typicode/json-server) for providing a simple fake REST API.
