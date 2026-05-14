#!/usr/bin/env bash
# check-fuzz-coverage.sh — Ensure modules with binary parsing have fuzz tests.
#
# Scans modules/ and lib/ for Go packages that contain binary parsing patterns
# (binary.Read, binary.BigEndian, io.ReadFull, Unmarshal) and checks that each
# has at least one *_fuzz_test.go file.
#
# Exit 0 if all covered, exit 1 if any are missing.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Patterns that indicate binary parsing of untrusted input
PARSE_PATTERNS='binary\.Read|binary\.BigEndian|binary\.LittleEndian|io\.ReadFull|\.UnMarshal|\.Unmarshal'

# Packages to exclude (vendored/forked stdlib or thin wrappers)
EXCLUDE_PATTERN='lib/http|lib/http2|lib/ssh|lib/smb/gss|lib/smb/ntlmssp|lib/smb/smb$|internal/'

missing=()

# Find all Go packages under modules/ and lib/ that have parsing code
for pkg_dir in $(find modules lib -type f -name '*.go' ! -name '*_test.go' \
    -exec grep -lE "$PARSE_PATTERNS" {} \; | xargs -I{} dirname {} | sort -u \
    | grep -vE "$EXCLUDE_PATTERN"); do

    # Check if this package has any fuzz test files
    if ! ls "$pkg_dir"/*_fuzz_test.go >/dev/null 2>&1; then
        missing+=("$pkg_dir")
    fi
done

if [ ${#missing[@]} -eq 0 ]; then
    echo "✅ All packages with binary parsing have fuzz tests."
    exit 0
fi

echo "⚠️  The following packages contain binary parsing but have no fuzz tests:"
echo ""
for pkg in "${missing[@]}"; do
    # Show which parsing patterns were found
    patterns=$(grep -rEoh "$PARSE_PATTERNS" "$pkg"/*.go 2>/dev/null | sort -u | tr '\n' ', ' | sed 's/,$//')
    echo "  $pkg  ($patterns)"
done
echo ""
echo "Add a *_fuzz_test.go file to each package above."
echo "See existing fuzz tests (e.g., modules/redis/types_fuzz_test.go) for examples."
exit 1
