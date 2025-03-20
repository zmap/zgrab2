FROM zgrab2_smtp_service_base:latest

RUN apt-get install -y \
    openssl
RUN rm -rf /var/lib/apt/lists/*

# Add Certs
RUN mkdir -p /etc/ssl/certs; \
    mkdir -p /etc/ssl/private;
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/ssl/private/postfix.key \
    -out /etc/ssl/certs/postfix.crt \
    -subj "/C=US/ST=State/L=City/O=MyCompany/CN=mail.example.com"

# Enable TLS
RUN echo "smtpd_tls_cert_file = /etc/ssl/certs/postfix.crt" >> /etc/postfix/main.cf; \
  echo "smtpd_tls_key_file = /etc/ssl/private/postfix.key" >> /etc/postfix/main.cf; \
  echo "smtpd_tls_wrappermode = yes" >> /etc/postfix/main.cf

# Command to run postfix (in the foreground)
CMD ["postfix", "start-fg"]
