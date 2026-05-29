#!/usr/bin/env python3
import difflib
import os
import json
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
output_root = os.path.join(zgrab_output, "memcached")


def test_memcached(version):
    print("Memcached test")
    run_command(
        f"CONTAINER_NAME=zgrab_memcached-{version} {zgrab_root}/docker-runner/docker-run.sh memcached",
        output_file=os.path.join(output_root, f"memcached-{version}.json"),
    )


def check_version(version):
    fp = open(os.path.join(output_root, f"memcached-{version}.json"))
    result_json = json.load(fp)
    print(fp.name)
    result_version = result_json["data"]["memcached"]["result"]["version"]
    result_version = result_version.strip()
    if str(result_version) != str(version):
        print(
            f"Versions do not match!\nContainer version:{version}\nMeasured version:{result_version}"
        )


if __name__ == "__main__":
    os.makedirs(os.path.join(zgrab_output, "memcached"), exist_ok=True)
    versions = ["1.6.0", "1.6.38"]
    for version in versions:
        test_memcached(version)
        check_version(version)
