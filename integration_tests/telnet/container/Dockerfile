FROM zgrab2_service_base:latest

RUN apt-get install -y inetutils-telnetd
COPY inetd.conf /etc/inetd.conf

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
