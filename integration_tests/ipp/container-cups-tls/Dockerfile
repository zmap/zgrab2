FROM zgrab2_ipp_service_base:latest

WORKDIR /etc/cups
COPY cupsssl.conf cupsd.conf

RUN service cups stop
RUN update-rc.d -f cupsd remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]