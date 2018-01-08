FROM zgrab2_service_base:latest

RUN apt-get install -y vsftpd
# This comes pre-configured to use a pre-generated certificate at /etc/ssl/certs/ssl-cert-snakeoil.pem,
# but by default ssl_enable=NO. So, changing that to YES and (re)starting the service should be all we need to do.
RUN sed -i 's/ssl_enable=NO/ssl_enable=YES/g' /etc/vsftpd.conf
RUN sed -i 's/#xferlog_std_format=YES/xferlog_std_format=NO/g' /etc/vsftpd.conf
RUN echo 'log_ftp_protocol=YES' >> /etc/vsftpd.conf
RUN echo 'ssl_ciphers=HIGH' >> /etc/vsftpd.conf

# Try to make it act more container-y -- remove it from init.d and just run the daemon as the entrypoint
RUN service vsftpd stop
RUN update-rc.d -f vsftpd remove

WORKDIR /
COPY entrypoint.sh .
RUN chmod a+x ./entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
