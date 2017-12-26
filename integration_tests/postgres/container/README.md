## About ##

The integration_tests/postgres/container folder contains the config files for building the custom postgres docker images.
These are based on the standard postgres images (https://hub.docker.com/_/postgres/), but with two changes:

 1. Enable logging (in $PGDATA/pg_log/postgres.log)
 2. Enable SSL (at least, if type = ssl)

## Adding a new postgres version ##

For most new versions, you can just add the new version tag to the `versions` list in setup.sh / test.sh and the new version will be pulled in.
If on the other hand you need a custom Dockerfile / setup script (as we did for 9.3, which doesn't support all of the SSL config options available in later versions), 
you will need to add a custom `Dockerfile.[version]`.
The Dockerfile will receive a build-arg named IMAGE_TYPE, which can be `ssl` or `nossl`, which it can use to make the appropriate setup decisions.
See `Dockerfile.9.3` for an example. The only difference there is it uses the 9.3 versions of the conf files.

## Details ##

 1. `../setup.sh` calls `build.sh ssl [version]` and `build.sh nossl [version]` for each supported postgres version.
 2. `build.sh` creates a docker image tagged `zgrab_postgres:[version]-[type]`, where `[type]` is `ssl` or `nossl`
 3. The Dockerfile drops the `setup_[type].sh` and `postgresql.conf.[nossl].partial` into the image
 4. `../setup.sh` starts the containers, binding them to ports 3543x (ssl) and 4543x (nonssl).
 5. During startup, the `setup_[type].sh` script is run on the image, setting up logging (and, on SSL images, generating self-signed SSL certificates)
