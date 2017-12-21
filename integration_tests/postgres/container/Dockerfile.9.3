FROM postgres:9.3

ARG IMAGE_TYPE=ssl

WORKDIR /tmp/postgres_setup
COPY postgresql.conf.9.3.$IMAGE_TYPE.partial postgresql.conf.partial
COPY setup_$IMAGE_TYPE.sh /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh

RUN chown -R postgres:postgres .
RUN chown postgres:postgres /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh

RUN chmod 0755 .
RUN chmod 0644 postgresql.conf.partial
RUN chmod 0755 /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh
