FROM zgrab2_service_base:latest

RUN apt-get update
RUN apt-get install -y xinetd socat netcat nano net-tools

WORKDIR /etc
COPY etc .

# TODO: run as an entrypoint process, not a service?
ENTRYPOINT [ "/usr/sbin/xinetd", "-dontfork" ]
