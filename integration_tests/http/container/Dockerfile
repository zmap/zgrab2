FROM zgrab2_service_base:latest
RUN apt-get install -y openssl lighttpd curl

WORKDIR /etc/lighttpd
COPY lighttpd.conf .

WORKDIR /var/lighttpd/certs
# TODO: use container name for host?
RUN openssl req -new -x509 -subj "/CN=target" -nodes -keyout ssl.key -out ssl.cer
RUN cat ssl.key ssl.cer > ssl.pem

WORKDIR /var/lighttpd/htdocs/http
COPY index-http.html index.html
COPY favicon.ico favicon.ico
RUN curl https://gist.githubusercontent.com/phillip-stephens/3f1a8d2874b4ff33e4fc46035810b7f9/raw/5bd8ed7fb1b923607c26807ea8ea0643825e6e16/index-very-large-http.html > large.html

COPY index-redirect.html index-redirect.html
COPY index-redirect-2.html index-redirect-2.html

WORKDIR /var/lighttpd/htdocs/https
COPY index-https.html index.html

ENTRYPOINT ["lighttpd", "-f", "/etc/lighttpd/lighttpd.conf", "-D"]
