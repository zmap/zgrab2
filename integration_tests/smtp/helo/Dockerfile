FROM instrumentisto/postfix

# Disable all ESMTP capabilities by not announcing ESMTP
RUN echo "smtpd_banner = $$myhostname $$mail_name" > /etc/postfix/main.cf

