#!/usr/bin/env bash

set -e
# Utility script for scaffolding stub test files for a new protocol

# Run from root of project
TEST_DIR=$(dirname "$0")
cd "$TEST_DIR/.."

if [ "$#" -ne 1 ]; then
    echo "Usage: ./integration_tests/new.sh <new_protocol_name>"
    exit 1
fi


module_name="$1"
module_path="integration_tests/$module_name"

function doReplacements() {
    sed -i "s/#{MODULE_NAME}/$module_name/g" $1
}

mkdir -p $module_path
pushd "integration_tests/.template"
for file in $(ls *.sh); do
    dest="../$module_name/$file"
    cp "$file" "$dest"
    doReplacements "$dest"
    chmod +x "$dest"
done
popd

cp "integration_tests/.template/schema.py" "schemas/$module_name.py"
doReplacements "schemas/$module_name.py"

echo "import schemas.$module_name" >> schemas/__init__.py

cp "integration_tests/.template/module.go" "modules/$module_name.go"
doReplacements "modules/$module_name.go"

mkdir -p modules/$module_name
cp "integration_tests/.template/module/scanner.go" "modules/$module_name/scanner.go"
doReplacements "modules/$module_name/scanner.go"

echo "Test files scaffolded in $module_path"
