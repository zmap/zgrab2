# Must use amd64 image so this builds on Mac.
# Unfortunately, the ./configure script below doesn't have ARM support
FROM --platform=linux/amd64 ubuntu:24.04
RUN apt-get update

# This image grabs the 4.2.6p5 source release of NTP and builds it.

RUN apt-get install -y libssl-dev gcc g++ make binutils autoconf tar wget

WORKDIR /opt
RUN wget https://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-4.2.6p5.tar.gz
RUN tar -xzf ntp-4.2.6p5.tar.gz

WORKDIR /opt/ntp-4.2.6p5
RUN ./configure
RUN make

# Don't require authentication, don't fork, debug level 10
ENTRYPOINT [ "/opt/ntp-4.2.6p5/ntpd/ntpd", "-A", "-n", "-D", "10" ]
