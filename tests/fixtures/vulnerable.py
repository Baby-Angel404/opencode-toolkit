"""A fixture file containing one instance of each detectable Python risk.

Used by the security-audit tests. Every construct here is deliberately unsafe and
exists only as scanner input -- it is never imported or executed.
"""

import os
import pickle
import subprocess
import tempfile

import requests
import yaml

DATABASE_URL = "postgres://svcuser:sup3rs3cr3t@db.internal:5432/app"
SESSION_SECRET = "0123456789abcdef0123456789abcdef"


def run_command(user_input):
    return subprocess.run("tar czf - " + user_input, shell=True, capture_output=True)


def fetch(url):
    return requests.get(url, verify=False)


def load_state(blob):
    return pickle.loads(blob)


def parse_config(text):
    return yaml.load(text)


def compute_digest(payload):
    import hashlib

    return hashlib.md5(payload).hexdigest()


def derive(password):
    import hashlib

    return hashlib.pbkdf2_hmac("sha256", password, b"salt", 1000)


def temporary_path():
    return tempfile.mktemp()


def read_user_file(root, name):
    return open(os.path.join(root, name)).read()


def evaluate(expression):
    return eval(expression)


def matching(text):
    import re

    return re.match(r"(\w+\s?)*$", text)


def make_token():
    import random

    return str(random.randint(100000, 999999))
