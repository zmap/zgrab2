FROM zgrab2_service_base:latest

RUN apt-get update && apt-get install -y \
  cups \
  cups-pdf
WORKDIR /etc/cups
COPY cupsd.conf cupsd.conf

RUN service cups stop
RUN update-rc.d -f cupsd remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]