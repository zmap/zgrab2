FROM zgrab2_service_base:latest

RUN apt-get update
RUN apt-get install -y cups
RUN apt-get install -y cups-pdf
RUN echo "ServerAlias *" >> /etc/cups/cupsd.conf
RUN echo "FileDevice yes" >> /etc/cups/cupsd.conf
#FIXME: Hard-coded IP address of my machine, which totally doesn't work for real testing
RUN sed -i 's/Order allow,deny/Order allow,deny\'$'\n  Allow all/g' /etc/cups/cupsd.conf
#RUN sed -i 's/Listen localhost:631/Listen 0.0.0.0:631/g' /etc/cups/cupsd.conf
RUN service cupsd restart

# Try to make it act more container-y -- remove it from init.d and just run the daemon as the entrypoint
#RUN service cupsd stop
#RUN update-rc.d -f cupsd remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

#ENTRYPOINT ["/entrypoint.sh"]