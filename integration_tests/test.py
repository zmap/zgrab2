import os
import subprocess
import sys
from pathlib import Path
import json
import shutil


def run_command(command, cwd=None, check=True):
    result = subprocess.run(
        command, shell=True, cwd=cwd, text=True, capture_output=True
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0 and check:
        print(f"Command failed: {command}")
        sys.exit(result.returncode)
    return result.stdout.strip()


def validate_json_schema(protocol, filepath):
    print(f"Validating {filepath}...")
    result = subprocess.run(
        f"python3 -m zschema validate zgrab2 {filepath} --path . --module zgrab2_schemas.zgrab2",
        shell=True,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Schema validation failed for {protocol}/{filepath}:\n{result.stderr}")
        sys.exit(1)

    with open(filepath) as f:
        data = json.load(f)

    status = data.get("data", {}).get(protocol, {}).get("status")
    if status != "success":
        print(f"Scan failure: Expected success, got '{status}' in {filepath}")
        sys.exit(1)


def main():
    zgrab_root = run_command("git rev-parse --show-toplevel")
    os.chdir(zgrab_root)

    zgrab_output = Path("zgrab-output")
    zgrab_output.mkdir(exist_ok=True)

    if not shutil.which("jp"):
        print("Please install jp")
        sys.exit(1)

    test_modules = (
        os.getenv("TEST_MODULES", "").split() if os.getenv("TEST_MODULES") else None
    )
    no_schema = os.getenv("NOSCHEMA")

    integration_tests = Path("integration_tests")
    for mod in integration_tests.iterdir():
        if (
            mod.is_dir()
            and mod.name != ".template"
            and (not test_modules or mod.name in test_modules)
        ):
            result = None
            for test in mod.glob("test*"):
                if test.suffix == ".sh":
                    print(f"Running {test}...")
                    result = subprocess.run(f"./{test.name}", cwd=mod, shell=True)
                elif test.suffix == ".py":
                    print(f"Running {test}...")
                    result = subprocess.run(
                        f"python3 ./{test.name}", cwd=mod, shell=True
                    )

                if result.returncode != 0:
                    print(
                        f"Test {test.name} failed with exit code {result.returncode}",
                        file=sys.stderr,
                    )
                    sys.exit(1)  # Exit immediately with failure

                if no_schema:
                    continue

                protocol_output_dir = zgrab_output / mod.name
                if protocol_output_dir.exists():
                    for outfile in protocol_output_dir.iterdir():
                        validate_json_schema(mod.name, outfile)

    print("All tests and schema validations passed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
