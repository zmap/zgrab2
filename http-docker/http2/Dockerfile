FROM nginx:alpine

# Install OpenSSL for cert generation
RUN apk add --no-cache openssl

# Copy static content and startup script
#COPY shared/index.html /usr/share/nginx/html/index.html
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Use custom nginx config
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 443

CMD ["/start.sh"]
