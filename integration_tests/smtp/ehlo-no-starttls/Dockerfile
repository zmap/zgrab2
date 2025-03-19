FROM instrumentisto/postfix

# Disable STARTTLS support
RUN echo "smtpd_tls_security_level = none" > /etc/postfix/main.cf
