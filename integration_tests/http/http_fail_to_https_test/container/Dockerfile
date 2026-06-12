FROM nginx:alpine
RUN apk add --no-cache openssl
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt -days 3650 -nodes -subj "/CN=target"
COPY nginx.conf /etc/nginx/nginx.conf
