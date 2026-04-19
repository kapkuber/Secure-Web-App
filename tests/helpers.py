"""Shared test utilities for encrypted JSON I/O using the app's storage key."""
from app import storage


def write_json(path, data):
    storage.save_encrypted_json(str(path), data)


def read_json(path, default=None):
    d = default if default is not None else {}
    return storage.load_encrypted_json(str(path), default=d)
