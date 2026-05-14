#!/usr/bin/env bash
# check-fuzz-coverage.sh — Ensure modules with binary parsing have fuzz tests.
#
# Two-level check:
# 1. Package-level: packages with parsing code must have *_fuzz_test.go files
# 2. Function-level: reports parse functions without corresponding Fuzz* coverage
#
# Exit 0 if all packages covered, exit 1 if any are missing.
# Function-level gaps are reported as warnings (non-blocking).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Patterns that indicate binary parsing of untrusted input
PARSE_PATTERNS='binary\.Read|binary\.BigEndian|binary\.LittleEndian|io\.ReadFull|\.UnMarshal|\.Unmarshal|\.Decode\b'

# Packages to exclude (vendored/forked stdlib or thin wrappers)
EXCLUDE_PATTERN='lib/http|lib/http2|lib/ssh|lib/smb/gss|lib/smb/ntlmssp|lib/smb/smb$|internal/'

missing=()
low_coverage=()

# Find all Go packages under modules/ and lib/ that have parsing code
for pkg_dir in $(find modules lib -type f -name '*.go' ! -name '*_test.go' \
    -exec grep -lE "$PARSE_PATTERNS" {} \; | xargs -I{} dirname {} | sort -u \
    | grep -vE "$EXCLUDE_PATTERN"); do

    # Check if this package has any fuzz test files
    if ! ls "$pkg_dir"/*_fuzz_test.go >/dev/null 2>&1; then
        missing+=("$pkg_dir")
        continue
    fi

    # Function-level coverage: count parse functions (excluding test files) vs fuzz functions
    parse_count=0
    while IFS= read -r n; do
        parse_count=$((parse_count + n))
    done < <(find "$pkg_dir" -maxdepth 1 -name '*.go' ! -name '*_test.go' \
        -exec grep -Ehc 'func.*([Uu]nmarshal|[Uu]n[Mm]arshal|[Dd]ecode[A-Za-z]|[Pp]arse[A-Za-z]|[Rr]ead[A-Za-z])' {} + 2>/dev/null || true)
    fuzz_count=0
    while IFS= read -r n; do
        fuzz_count=$((fuzz_count + n))
    done < <(grep -c '^func Fuzz' "$pkg_dir"/*_fuzz_test.go 2>/dev/null || true)

    if [ "$parse_count" -gt 0 ] && [ "$fuzz_count" -lt $(( (parse_count + 2) / 3 )) ]; then
        low_coverage+=("$pkg_dir: $fuzz_count fuzz targets for ~$parse_count parse functions")
    fi
done

exit_code=0

if [ ${#missing[@]} -gt 0 ]; then
    echo "❌ Packages with binary parsing but NO fuzz tests:"
    echo ""
    for pkg in "${missing[@]}"; do
        patterns=$(grep -rEoh "$PARSE_PATTERNS" "$pkg"/*.go 2>/dev/null | sort -u | tr '\n' ', ' | sed 's/,$//')
        echo "  $pkg  ($patterns)"
    done
    echo ""
    echo "Add a *_fuzz_test.go file to each package above."
    echo "See existing fuzz tests (e.g., modules/redis/types_fuzz_test.go) for examples."
    exit_code=1
fi

if [ ${#low_coverage[@]} -gt 0 ]; then
    echo ""
    echo "⚠️  Packages with low fuzz coverage (have tests but many uncovered parse functions):"
    echo ""
    for entry in "${low_coverage[@]}"; do
        echo "  $entry"
    done
    echo ""
    echo "Consider adding more Fuzz* functions for uncovered parse/decode/unmarshal methods."
fi

if [ $exit_code -eq 0 ] && [ ${#low_coverage[@]} -eq 0 ]; then
    echo "✅ All packages with binary parsing have fuzz tests."
fi

exit $exit_code
