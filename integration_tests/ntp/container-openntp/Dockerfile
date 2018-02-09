FROM zgrab2_service_base:latest

RUN apt-get install -y openntpd
# Run directly from the entrypoint
RUN service openntpd stop

WORKDIR /etc/openntpd
COPY ntpd.conf .
RUN mkdir -p /var/run/openntpd

# Must be run with --privileged
# Don't fork, extra debugging info
ENTRYPOINT ["/usr/sbin/ntpd", "-d", "-v"]
