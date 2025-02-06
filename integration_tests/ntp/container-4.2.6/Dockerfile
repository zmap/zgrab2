FROM ubuntu:24.04
RUN apt-get update

# Install build dependencies
#RUN apk add --no-cache \
#    build-base \
#    wget \
#    tar \
#    libevent-dev \
#    perl \
#    linux-headers

# This image grabs the 4.2.6p5 source release of NTP and builds it.

RUN apt-get install -y libssl-dev
RUN apt-get install -y gcc g++ make
RUN apt-get install -y binutils autoconf
RUN apt-get install -y tar
RUN apt-get install -y wget

WORKDIR /opt
RUN wget https://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-4.2.6p5.tar.gz
RUN tar -xzf ntp-4.2.6p5.tar.gz

WORKDIR /opt/ntp-4.2.6p5
RUN ./configure
RUN make

# Don't require authentication, don't fork, debug level 10
ENTRYPOINT [ "/opt/ntp-4.2.6p5/ntpd/ntpd", "-A", "-n", "-D", "10" ]
