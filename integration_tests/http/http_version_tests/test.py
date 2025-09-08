#!/usr/bin/env python3
import base64
import difflib
import os
import json
import requests
import subprocess
import sys
from hashlib import sha256


def run_command(command, output_file=None):
    """Run a shell command and optionally redirect output to a file."""
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

# Ensure output directory exists
os.makedirs(output_root, exist_ok=True)

def test_http_v1():
    """
    Test HTTP/1.1 request and response.
    Tests if the server correctly responds with HTTP/1.1 protocol and the body text is as expected
    """
    container_name = "zgrab_http1"
    target_name = "http1.target" # Used for docker network internal DNS resolution
    print("http_version_tests/test: Run HTTP/1.1")
    run_command(
        f"CONTAINER_NAME={container_name} TARGET_NAME={target_name} {zgrab_root}/docker-runner/docker-run.sh http",
        output_file=os.path.join(output_root, "http_v1.json"),
    )
    # Load the output JSON
    with open(os.path.join(output_root, "http_v1.json"), "r") as f:
        output = json.load(f)
    # Check if the scan was successful
    if not output or 'data' not in output or 'http' not in output['data']:
        print("No valid output found for HTTP/1.1 test", file=sys.stderr)
        sys.exit(1)
    http_data = output['data']['http']['result']
    if 'response' not in http_data or 'status_code' not in http_data['response']:
        print("No response data found for HTTP/1.1 test", file=sys.stderr)
        sys.exit(1)
    status_code = http_data['response']['status_code']
    if status_code != 200:
        print(f"Unexpected status code for HTTP/1.1 test: {status_code}", file=sys.stderr)
        sys.exit(1)
    actual_http_version = http_data["response"].get("protocol")
    if actual_http_version != "HTTP/1.1":
        print(f"Unexpected HTTP version for HTTP/1.1 test: {actual_http_version}", file=sys.stderr)
        sys.exit(1)
    expected_body_check_text = "Hello from HTTP versioned server!"
    actual_body_text = http_data['response'].get('body', '')
    if 'body' not in http_data['response'] or expected_body_check_text not in actual_body_text:
        print("Response body does not contain expected text for HTTP/1.1 test", file=sys.stderr)
        sys.exit(1)
    print("HTTP/1.1 test passed with status code 200")

def test_http_v2():
    """
    Test HTTP/2 request and response.
    Tests if the server correctly responds with HTTP/2 protocol and the body text is as expected
    """
    container_name = "zgrab_http2"
    target_name = "http2.target" # Used for docker network internal DNS resolution
    output_json = "http_v2.json"
    print("http_version_tests/test: Run HTTP/2")
    run_command(
        f"CONTAINER_NAME={container_name} TARGET_NAME={target_name} {zgrab_root}/docker-runner/docker-run.sh http --max-redirects=2",
        output_file=os.path.join(output_root, output_json),
    )
    # Load the output JSON
    with open(os.path.join(output_root, output_json), "r") as f:
        output = json.load(f)
    # Check if the scan was successful
    if not output or 'data' not in output or 'http' not in output['data']:
        print("No valid output found for HTTP/2 test", file=sys.stderr)
        sys.exit(1)
    http_data = output['data']['http']['result']
    if 'response' not in http_data or 'status_code' not in http_data['response']:
        print("No response data found for HTTP/2 test", file=sys.stderr)
        sys.exit(1)
    status_code = http_data['response']['status_code']
    if status_code != 200:
        print(f"Unexpected status code for HTTP/2 test: {status_code}", file=sys.stderr)
        sys.exit(1)
    actual_http_version = http_data["response"].get("protocol")
    if actual_http_version != "HTTP/2.0":
        print(f"Unexpected HTTP version for HTTP/2 test: {actual_http_version}", file=sys.stderr)
        sys.exit(1)
    expected_body_check_text = "Hello from HTTP versioned server!"
    actual_body_text = http_data['response'].get('body', '')
    if 'body' not in http_data['response'] or expected_body_check_text not in actual_body_text:
        print("Response body does not contain expected text for HTTP/2 test", file=sys.stderr)
        sys.exit(1)
    print("HTTP/2 test passed with status code 200")

def test_http_h2c():
    """
    Test HTTP/2 request and response over cleartext (h2c).
    Tests if the server correctly responds with HTTP/2 protocol and the body text is as expected
    """
    container_name = "zgrab_http_h2c"
    target_name = "http.h2c.target" # Used for docker network internal DNS resolution
    output_json = "http_h2c.json"
    print("http_version_tests/test: Run HTTP/2 over cleartext (h2c)")
    run_command(
        f"CONTAINER_NAME={container_name} TARGET_NAME={target_name} {zgrab_root}/docker-runner/docker-run.sh http --http2-prior-knowledge --port=443",
        output_file=os.path.join(output_root, output_json),
    )
    # Load the output JSON
    with open(os.path.join(output_root, output_json), "r") as f:
        output = json.load(f)
    # Check if the scan was successful
    if not output or 'data' not in output or 'http' not in output['data']:
        print("No valid output found for h2c test", file=sys.stderr)
        sys.exit(1)
    http_data = output['data']['http']['result']
    if 'response' not in http_data or 'status_code' not in http_data['response']:
        print("No response data found for HTTP/2 h2c test", file=sys.stderr)
        sys.exit(1)
    status_code = http_data['response']['status_code']
    if status_code != 200:
        print(f"Unexpected status code for HTTP/2 h2c test: {status_code}", file=sys.stderr)
        sys.exit(1)
    print(http_data)
    actual_http_http_version = http_data["response"]["request"].get("protocol")

    if actual_http_http_version != "HTTP/2.0":
        print(f"Unexpected HTTP version for HTTP/2 h2c test request: {actual_http_http_version}", file=sys.stderr)
        sys.exit(1)
    actual_http_version = http_data["response"].get("protocol")
    if actual_http_version != "HTTP/2.0":
        print(f"Unexpected HTTP version for HTTP/2 h2c test response: {actual_http_version}", file=sys.stderr)
        sys.exit(1)
    expected_body_check_text = "Successfully served over HTTP/2 NOT over TLS!"
    actual_body_text = http_data['response'].get('body', '')
    if 'body' not in http_data['response'] or expected_body_check_text not in actual_body_text:
        print("Response body does not contain expected text for HTTP/2 h2c test", file=sys.stderr)
        sys.exit(1)
    print("HTTP/2 h2c test passed with status code 200")

def run_all_tests():
    """Run all test functions defined in this module."""
    tests = {
        name: func
        for name, func in globals().items()
        if name.startswith("test_") and callable(func)
    }
    for name, test_func in tests.items():
        print(f"=== Running {name} ===")
        test_func()
        print(f"=== Finished {name} ===\n")


def print_docker_logs(container_name):
    print(f"http/test: BEGIN docker logs from {container_name} [{{(")
    run_command(f"docker logs --tail all {container_name}")
    print(f")}}] END docker logs from {container_name}")

    print(f"http/test: BEGIN https logs from {container_name} [{{(")
    run_command(f"docker exec {container_name} cat //var/log/lighttpd/error.log")
    print(f")}}] END docker logs from {container_name}")


def main():
    """Run specific test if provided as an argument, otherwise run all tests."""
    # TODO: Tests with local / remote redirection
    # TODO: Test various types of content (binary, JSON, ...)
    # TODO: Test with client cert required
    run_all_tests()
    print_docker_logs("zgrab_http1")


if __name__ == "__main__":
    main()
