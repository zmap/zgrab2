#!/usr/bin/env bash

# Utility script for scaffolding stub test files for a new protocol

# Run from root of project
TEST_DIR=$(dirname "$0")
cd "$TEST_DIR/.."

if [ "$#" -ne 1 ]
then
  echo "Usage: ./integration_tests/new.sh <new_protocol_name>"
  exit 1
fi

module_name="$1"
module_path="integration_tests/$module_name"

mkdir -p $module_path

cat << EOF > $module_path/setup.sh
#!/usr/bin/env bash

echo "Tests setup for $module_name"
EOF
chmod +x $module_path/setup.sh

cat << EOF > $module_path/test.sh
#!/usr/bin/env bash

echo "Tests runner for $module_name"
EOF
chmod +x $module_path/test.sh

cat << EOF > $module_path/cleanup.sh
#!/usr/bin/env bash

echo "Tests cleanup for $module_name"
EOF
chmod +x $module_path/cleanup.sh

echo "Test files scaffolded in $module_path"
