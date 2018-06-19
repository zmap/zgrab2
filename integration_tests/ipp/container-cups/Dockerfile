FROM zgrab2_service_base:latest

RUN apt-get update && apt-get install -y \
  cups \
  cups-pdf
WORKDIR /etc/cups
COPY cupsd.conf cupsd.conf
# TODO: Provide a pre-built cups-pdf.conf
#RUN service cups restart

# TODO: Actually stop service; see why this works without stopping it
RUN service cups stop
# TODO: Actually prevent cups from being started automatically
RUN update-rc.d -f cupsd remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]