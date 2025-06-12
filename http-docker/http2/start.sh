#!/bin/sh

# Generate self-signed certs
CERT_DIR=/etc/ssl/private
mkdir -p $CERT_DIR
openssl req -x509 -newkey rsa:2048 -nodes -keyout $CERT_DIR/self.key -out $CERT_DIR/self.crt -days 365 \
  -subj "/CN=localhost"

# Start nginx
nginx -g 'daemon off;'
