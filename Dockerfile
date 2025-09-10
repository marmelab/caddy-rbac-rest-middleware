FROM caddy:builder AS builder

COPY ./plugin /etc/plugin

RUN xcaddy build \
    --with github.com/marmelab/caddy-simple-rest-rbac/plugin=/etc/plugin \
    --with github.com/steffenbusch/caddy-jwt-issuer \
    --with github.com/ggicci/caddy-jwt

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
