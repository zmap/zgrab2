FROM danchitnis/xrdp:ubuntu-xfce

# Override xrdp.ini to use standard RDP security (no TLS, no NLA)
RUN sed -i 's/^security_layer=.*/security_layer=rdp/' /etc/xrdp/xrdp.ini && \
    sed -i 's/^crypt_level=.*/crypt_level=low/' /etc/xrdp/xrdp.ini
