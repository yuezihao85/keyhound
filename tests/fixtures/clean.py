"""A clean source file: no findings expected."""

import os

API_KEY = os.environ.get("API_KEY")
PASSWORD = "changeme"
TOKEN = "${CI_TOKEN}"
PLACEHOLDER = "your_api_key_here"
FAKE = "example"
LOW_ENTROPY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PUBLIC_KEY = "public_key_material_for_docs"


def load(name):
    return os.getenv(name)
