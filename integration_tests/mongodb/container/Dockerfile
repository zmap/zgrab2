FROM mongo:4.0.1

RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
      -keyout /tmp/mongodb.key \
      -out /tmp/mongodb.crt \
      -subj "/CN=target" && \
    cat /tmp/mongodb.key /tmp/mongodb.crt > /etc/ssl/mongodb.pem && \
    chown mongodb:mongodb /etc/ssl/mongodb.pem && \
    chmod 600 /etc/ssl/mongodb.pem && \
    rm /tmp/mongodb.key /tmp/mongodb.crt

CMD ["mongod", "--bind_ip_all", "--sslMode", "requireSSL", "--sslPEMKeyFile", "/etc/ssl/mongodb.pem", "--sslAllowConnectionsWithoutCertificates"]
