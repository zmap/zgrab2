FROM zgrab2_service_base:latest

ENV DEBIAN_FRONTEND=noninteractive

# Pre-seed slapd configuration to avoid interactive prompts
RUN echo "slapd slapd/internal/generated_adminpw password password" | debconf-set-selections && \
    echo "slapd slapd/internal/adminpw password password" | debconf-set-selections && \
    echo "slapd slapd/password1 password password" | debconf-set-selections && \
    echo "slapd slapd/password2 password password" | debconf-set-selections && \
    echo "slapd slapd/domain string ldap.example.com" | debconf-set-selections && \
    echo "slapd shared/organization string Example" | debconf-set-selections

RUN apt-get install -y slapd ldap-utils openssl

# Generate a self-signed TLS certificate for LDAPS and STARTTLS
RUN mkdir -p /etc/ldap/tls && \
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
      -keyout /etc/ldap/tls/ldap.key \
      -out /etc/ldap/tls/ldap.crt \
      -subj "/C=US/ST=Test/L=Test/O=Test/CN=target" && \
    chown openldap:openldap /etc/ldap/tls/ldap.key /etc/ldap/tls/ldap.crt && \
    chmod 600 /etc/ldap/tls/ldap.key

# TLS configuration LDIF
RUN echo 'dn: cn=config\n\
changetype: modify\n\
add: olcTLSCertificateFile\n\
olcTLSCertificateFile: /etc/ldap/tls/ldap.crt\n\
-\n\
add: olcTLSCertificateKeyFile\n\
olcTLSCertificateKeyFile: /etc/ldap/tls/ldap.key\n\
' > /etc/ldap/tls-config.ldif

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

EXPOSE 389 636

ENTRYPOINT ["/entrypoint.sh"]
