#!/usr/bin/env python3

import difflib
import os
import json
from unittest.result import failfast

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
output_root = os.path.join(zgrab_output, "multiple")
multiple_test_root = os.path.join(zgrab_root, "integration_tests", "multiple")


def validate_http(output):
    json_data = json.loads(output)
    assert json_data["domain"] == "example.com"
    assert json_data["data"]["http"]["status"] == "success"


def validate_ntp(output):
    json_data = json.loads(output)
    assert json_data["domain"] == "time-a-g.nist.gov"
    assert json_data["data"]["ntp"]["status"] == "success"


def test_multiple():
    print("multiple/test: Run both NTP and HTTP scans")
    print(multiple_test_root)
    cmd = f"DIR={multiple_test_root} {multiple_test_root}/docker-run.sh multiple --input-file=/multiple/input.csv --config-file=/multiple/multiple.ini"
    out = run_command(
        cmd,
    )
    # print output
    lines = out.strip().split("\n")

    # Write each line to a separate JSON file
    for i, line in enumerate(lines):
        if "http" in line:
            validate_http(line)
        elif "ntp" in line:
            validate_ntp(line)
        else:
            print(f"Unknown protocol in line: {line}")
            sys.exit(1)


if __name__ == "__main__":
    test_multiple()
