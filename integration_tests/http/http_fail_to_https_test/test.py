#!/usr/bin/env python3
"""
Integration tests for the --fail-http-to-https flag (PR #735).

The target container (zgrab_http_fail_to_https) runs nginx configured for
HTTPS-only on port 443.  When a plain-text HTTP request arrives, nginx returns
HTTP 400 with "Client sent an HTTP request to an HTTPS server." in the body --
the same response Apache produces.  zgrab2 detects this string and, when
--fail-http-to-https is set, retries over TLS and succeeds.

Note: --retry-https is intentionally not tested here.  That flag retries on
any Grab() failure (connection-level errors), but Grab() treats the nginx 400
response as a successfully read HTTP reply and returns nil.  The body-check
that raises ErrHTTPSProtocolMismatch is only active when --fail-http-to-https
is set, so --retry-https has no effect against this server.
"""

import os
import json
import subprocess
import sys


def run_command(command, output_file=None):
    try:
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        ) as process:
            stdout, stderr = process.communicate()
            if output_file:
                with open(output_file, "w") as f:
                    f.write(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
            return stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}", file=sys.stderr)
        sys.exit(1)


zgrab_root = run_command("git rev-parse --show-toplevel")
zgrab_output = os.path.join(zgrab_root, "zgrab-output")
output_root = os.path.join(zgrab_output, "http")

os.makedirs(output_root, exist_ok=True)

container_name = "zgrab_http_fail_to_https"


def _scan(extra_flags, output_file=None):
    cmd = (
        f"CONTAINER_NAME={container_name} "
        f"{zgrab_root}/docker-runner/docker-run.sh "
        f"http --port 443 {extra_flags}"
    )
    return run_command(cmd, output_file=output_file)


def test_fail_http_to_https_flag():
    """--fail-http-to-https: plain HTTP to HTTPS port triggers retry, scan succeeds."""
    print("http/fail_to_https_test: --fail-http-to-https should retry over TLS")
    output_file = os.path.join(output_root, "http_fail_to_https.json")
    raw = _scan("--fail-http-to-https", output_file=output_file)

    result = json.loads(raw)
    scan = result.get("data", {}).get("http", {})

    status = scan.get("status")
    assert status == "success", f"Expected scan status 'success', got '{status}'"

    status_code = scan.get("result", {}).get("response", {}).get("status_code")
    assert status_code == 200, f"Expected HTTP 200 after TLS retry, got {status_code}"

    print("PASS: --fail-http-to-https retried over TLS and got 200 OK")


def test_no_flag_returns_400():
    """Without --fail-http-to-https, zgrab2 reads the 400 as a successful HTTP
    transaction and does not retry -- the mismatch response is the final result."""
    print("http/fail_to_https_test: plain HTTP without flag should return 400")
    # Do not write to the schema-validated output dir; capture inline only.
    raw = _scan("")

    result = json.loads(raw)
    scan = result.get("data", {}).get("http", {})

    status = scan.get("status")
    assert (
        status == "success"
    ), f"Expected scan status 'success' (HTTP transaction completed), got '{status}'"

    status_code = scan.get("result", {}).get("response", {}).get("status_code")
    assert (
        status_code == 400
    ), f"Expected HTTP 400 mismatch response without retry flag, got {status_code}"

    print("PASS: plain HTTP without flag returned scan status 'success' with HTTP 400")


def run_all_tests():
    tests = {
        name: func
        for name, func in globals().items()
        if name.startswith("test_") and callable(func)
    }
    for name, test_func in tests.items():
        print(f"=== Running {name} ===")
        test_func()
        print(f"=== Finished {name} ===\n")


if __name__ == "__main__":
    run_all_tests()
