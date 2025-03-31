#!/usr/bin/env python3

import difflib
import os
import subprocess
import sys
import time

# Get directories
module_dir = os.path.dirname(os.path.abspath(__file__))
test_root = os.path.join(module_dir, "..")


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


# Ensures that the returned HTTP body matches the expected contents with a very large HTML file
def test_large_http_body_contents():
    with open("./container/index-very-large-http.html", "r", encoding="utf-8") as f:
        expected_content = f.read()
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
