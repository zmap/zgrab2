FROM caddy:alpine

# Copy Caddyfile
COPY Caddyfile /etc/caddy/Caddyfile
COPY index.html /usr/share/caddy/index.html

## Copy static files
#COPY index.html /usr/share/caddy/index.html

# Generate self-signed cert at build time
RUN apk add openssl && \
    mkdir -p /etc/ssl/private && \
    openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/self.key -out /etc/ssl/private/self.crt \
        -days 365 -nodes -subj "/CN=localhost"
