#!/usr/bin/env python3
"""Generate bcrypt password hashes for configs/config.yaml.

This project verifies passwords with Go's golang.org/x/crypto/bcrypt.
The script first tries Python's optional ``bcrypt`` package, then falls back
to a temporary Go helper so it works without adding a Python dependency.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_COST = 10
MIN_COST = 4
MAX_COST = 31


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate bcrypt password_hash values and audit HMAC secrets."
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Password to hash. If omitted, the script prompts securely.",
    )
    parser.add_argument(
        "-c",
        "--cost",
        type=int,
        default=DEFAULT_COST,
        help=f"bcrypt cost. Default: {DEFAULT_COST}.",
    )
    parser.add_argument(
        "--hmac-secret",
        action="store_true",
        help="Generate a random password_attempt_hmac_secret instead of a password hash.",
    )
    parser.add_argument(
        "--secret-bytes",
        type=int,
        default=32,
        help="Number of random bytes for --hmac-secret. Default: 32.",
    )
    return parser.parse_args()


def prompt_password() -> str:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("passwords do not match")
    return password


def validate_cost(cost: int) -> None:
    if cost < MIN_COST or cost > MAX_COST:
        raise SystemExit(f"bcrypt cost must be between {MIN_COST} and {MAX_COST}")


def generate_with_python_bcrypt(password: str, cost: int) -> str | None:
    try:
        import bcrypt  # type: ignore
    except ModuleNotFoundError:
        return None
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=cost))
    return hashed.decode("utf-8")


def find_repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        if (parent / "go.mod").exists():
            return parent
    return Path.cwd()


def generate_with_go_bcrypt(password: str, cost: int) -> str:
    if shutil.which("go") is None:
        raise SystemExit(
            "Python package 'bcrypt' is not installed and 'go' was not found in PATH."
        )

    source = r'''
package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: helper <cost> <password>")
	}
	cost, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), cost)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
}
'''
    repo_root = find_repo_root()
    fd, helper_path_raw = tempfile.mkstemp(
        prefix="password_generate_tmp_", suffix=".go", dir=repo_root
    )
    helper_path = Path(helper_path_raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as helper:
            helper.write(source)
        env = os.environ.copy()
        env.setdefault("GOWORK", "off")
        result = subprocess.run(
            ["go", "run", str(helper_path), str(cost), password],
            cwd=repo_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        try:
            helper_path.unlink()
        except FileNotFoundError:
            pass
    if result.returncode != 0:
        raise SystemExit(
            "failed to generate bcrypt hash with Go helper:\n"
            f"{result.stderr.strip()}\n\n"
            f"repo root detected as: {repo_root}"
        )
    return result.stdout.strip()


def generate_password_hash(password: str, cost: int) -> str:
    validate_cost(cost)
    hashed = generate_with_python_bcrypt(password, cost)
    if hashed is not None:
        return hashed
    return generate_with_go_bcrypt(password, cost)


def generate_hmac_secret(byte_count: int) -> str:
    if byte_count <= 0:
        raise SystemExit("--secret-bytes must be greater than 0")
    return base64.b64encode(secrets.token_bytes(byte_count)).decode("ascii")


def main() -> int:
    args = parse_args()
    if args.hmac_secret:
        print(generate_hmac_secret(args.secret_bytes))
        return 0

    password = args.password if args.password is not None else prompt_password()
    if password == "":
        raise SystemExit("password cannot be empty")

    print(generate_password_hash(password, args.cost))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
