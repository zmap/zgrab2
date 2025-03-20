FROM zgrab2_smtp_service_base:latest

# Disable STARTTLS support
RUN echo "smtpd_tls_security_level = none" >> /etc/postfix/main.cf

# Command to run postfix (in the foreground)
CMD ["postfix", "start-fg"]

