"""A fixture with none of the detectable risks. Any finding here is a false positive."""

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

ENV_NAME = "DATABASE_PASSWORD"
PLACEHOLDER = "your_token_here"
SAFE_SALT_SIZE = 16


def run_command(archive, target):
    return subprocess.run(["tar", "czf", "-", archive], capture_output=True, check=True)


def load_state(blob):
    return json.loads(blob.decode("utf-8"))


def parse_config(text):
    import yaml

    return yaml.safe_load(text)


def compute_digest(payload):
    return hashlib.sha256(payload).hexdigest()


def derive(password):
    return hashlib.pbkdf2_hmac("sha256", password, b"salt", 600_000)


def temporary_path():
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        return Path(handle.name)


def read_user_file(root, name):
    candidate = (Path(root) / name).resolve()
    if not candidate.is_relative_to(Path(root).resolve()):
        raise ValueError("path escapes the permitted root")
    return candidate.read_text()


def evaluate(expression):
    import ast

    return ast.literal_eval(expression)


def matching(text):
    return re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", text)


def make_token():
    return secrets.token_urlsafe(32)


def constant_time_equal(left, right):
    return hmac.compare_digest(left, right)


def main():
    print(os.getcwd(), ENV_NAME, PLACEHOLDER, SAFE_SALT_SIZE)


if __name__ == "__main__":
    main()
