FROM postgres:#{POSTGRES_VERSION}

# Our custom postgres image -- based on the standard images (https://hub.docker.com/_/postgres/)
# On top of the base, we enable logging and (if IMAGE_TYPE == ssl) server-side SSL (with a self-signed certificate)
ARG IMAGE_TYPE=ssl

WORKDIR /tmp/postgres_setup
# This gets catted to the end of $PGDATA/postgresql.conf
COPY postgresql.conf.$IMAGE_TYPE.partial postgresql.conf.partial
# The docker-entrypoint-initdb.d scripts get run after postgres is installed but before it is started.
COPY setup_$IMAGE_TYPE.sh /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh

RUN chown -R postgres:postgres .
RUN chown postgres:postgres /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh

RUN chmod 0755 .
RUN chmod 0644 postgresql.conf.partial
RUN chmod 0755 /docker-entrypoint-initdb.d/setup_$IMAGE_TYPE.sh
