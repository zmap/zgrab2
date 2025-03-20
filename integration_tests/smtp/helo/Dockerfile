FROM zgrab2_smtp_service_base:latest

RUN rm -rf /var/lib/apt/lists/*

# Disable all ESMTP capabilities by not announcing ESMTP
RUN echo "smtpd_banner = $$myhostname $$mail_name" >> /etc/postfix/main.cf

# Command to run postfix (in the foreground)
CMD ["postfix", "start-fg"]
