FROM zgrab2_service_base:latest
RUN apt-get update && apt-get install -y openssl lighttpd

WORKDIR /etc/lighttpd
COPY lighttpd.conf .

WORKDIR /var/lighttpd/certs
# TODO: use container name for host?
RUN openssl req -new -x509 -subj "/CN=target" -nodes -keyout ssl.key -out ssl.cer
RUN cat ssl.key ssl.cer > ssl.pem

WORKDIR /var/lighttpd/htdocs/http
COPY index-http.html index.html

WORKDIR /var/lighttpd/htdocs/https
COPY index-https.html index.html

ENTRYPOINT ["lighttpd", "-f", "/etc/lighttpd/lighttpd.conf", "-D"]
