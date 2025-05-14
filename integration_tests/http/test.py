#!/usr/bin/env python3

import difflib
import os
import json
import requests
import subprocess
import sys
import time


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

container_name = "zgrab_http"


def test_basic_http():
    print("http/test: Run http test in default port (should be 80)")
    run_command(
        f"CONTAINER_NAME={container_name} {zgrab_root}/docker-runner/docker-run.sh http",
        output_file=os.path.join(output_root, "http.json"),
    )


def test_basic_https():
    print("http/test: Run https test on port 443")
    run_command(
        f"CONTAINER_NAME={container_name} {zgrab_root}/docker-runner/docker-run.sh http --port 443 --use-https",
        output_file=os.path.join(output_root, "https.json"),
    )


# Ensures that the returned HTTP body matches the expected contents
def test_http_body_contents():
    with open("./container/index-http.html", "r", encoding="utf-8") as f:
        expected_content = f.read()
    # remove the trailing newlines that jq is adding and extract body from ZGrab scan
    cmd = f"CONTAINER_NAME={container_name} {zgrab_root}/docker-runner/docker-run.sh http | jq -r '.data.http.result.response.body' | perl -pe 'chomp if eof'"
    actual_content = run_command(cmd)
    if expected_content != actual_content:
        diff = difflib.unified_diff(
            expected_content.splitlines(), actual_content.splitlines(), lineterm=""
        )
        print(diff)
        raise ValueError(
            "http/body-test: The HTTP body contents do not match the expected contents.\n"
        )
    else:
        pass

def test_binary_contents():
    with open("./favicon.ico.base64", "r", encoding="utf-8") as f:
        expected_content = f.read()
    cmd = f"CONTAINER_NAME={container_name} {zgrab_root}/docker-runner/docker-run.sh http --endpoint=/favicon.ico --max-size=200000 --read-limit-per-host=200000 | jq -r '.data.http.result.response.body'"
    actual_content = run_command(cmd)
    if expected_content.strip() != actual_content.strip():
        diff = difflib.unified_diff(
            expected_content.splitlines(), actual_content.splitlines(), lineterm=""
        )
        print(diff)
        raise ValueError(
            "http/binary-test: The HTTP body contents do not match the expected contents.\n"
        )
    else:
        pass


# Ensures that the returned HTTP body matches the expected contents with a very large HTML file
def test_large_http_body_contents():
    large_http_gist_url = "https://gist.githubusercontent.com/phillip-stephens/3f1a8d2874b4ff33e4fc46035810b7f9/raw/5bd8ed7fb1b923607c26807ea8ea0643825e6e16/index-very-large-http.html"
    response = requests.get(large_http_gist_url)
    response.raise_for_status()  # Ensure the request was successful
    expected_content = response.text
    # remove the trailing newlines that jq is adding and extract body from ZGrab scan
    cmd = f"CONTAINER_NAME={container_name} {zgrab_root}/docker-runner/docker-run.sh http --endpoint=/large.html --max-size=10000 --read-limit-per-host=10000 | jq -r '.data.http.result.response.body' | perl -pe 'chomp if eof'"
    actual_content = run_command(cmd)
    if expected_content != actual_content:
        diff = difflib.unified_diff(
            expected_content.splitlines(), actual_content.splitlines(), lineterm=""
        )
        line_ctr = 0
        for line in diff:
            line_ctr += 1
            print(line)
            if line_ctr > 10:
                print("Truncated output")
                break
        raise ValueError(
            "http/large-body-test: The HTTP body contents do not match the expected contents.\n"
        )
    pass


# Uses the dockerized zgrab to ensure that scanning real domains returns a 200 OK
def test_scanning_real_domains():
    domains = [
        "cloudflare.com",
        "github.com",
        "en.wikipedia.org",
    ]
    for domain in domains:
        command = "docker run --rm -i zgrab2_runner http --max-redirects=3"
        grabbed_response = run_command(f"echo {domain} | {command}")
        status_line = (
            json.loads(grabbed_response)
            .get("data", {})
            .get("http", {})
            .get("result", {})
            .get("response", {})
            .get("status_line", "Unknown")
        )
        print(f"zgrab2_runner: {domain} status => {status_line}")
        # Check if the response contains a 200 OK status
        if status_line != "200 OK":
            raise ValueError(
                f"zgrab2_runner: {domain} returned an unexpected status line: {status_line}"
            )


def print_docker_logs():
    print(f"http/test: BEGIN docker logs from {container_name} [{{(")
    run_command(f"docker logs --tail all {container_name}")
    print(f")}}] END docker logs from {container_name}")

    print(f"http/test: BEGIN https logs from {container_name} [{{(")
    run_command(f"docker exec {container_name} cat //var/log/lighttpd/error.log")
    print(f")}}] END docker logs from {container_name}")


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


def main():
    """Run specific test if provided as an argument, otherwise run all tests."""
    # TODO: Tests with local / remote redirection
    # TODO: Test various types of content (binary, JSON, ...)
    # TODO: Test with client cert required
    run_all_tests()
    print_docker_logs()


if __name__ == "__main__":
    main()
