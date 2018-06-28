FROM zgrab2_service_base:latest

RUN apt-get install -y FIXME_YOUR_SERVICE_PKG

# Try to make it act more container-y -- remove it from init.d and just run the daemon as the entrypoint
RUN service FIXME_YOUR_SERVICED stop
RUN update-rc.d -f FIXME_YOUR_SERVICED remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
