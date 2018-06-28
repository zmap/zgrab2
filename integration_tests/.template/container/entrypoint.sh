#!/bin/sh

echo "ERROR: ***"
echo "ERROR: This container's entrypoint must be customized."
echo "ERROR: See integration_tests/#{MODULE_NAME}/container/*"
echo "FIXME: ***"
exit 1

# This should do the same work as the init.d start script, but the 
# process should run in the foreground.
# In some cases, it may be appropriate to exit (and hence stop the 
# container) if the daemon process ends, but in others that may be
# expected behavior.

set -x

while true; do
  if ! /usr/sbin/FIXME_YOUR_SERVICED --fixme-service-options; then
    echo "FIXME_YOUR_SERVICED exited unexpectedly. Restarting..."
    sleep 1
  fi
done
