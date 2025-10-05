import os
import os
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet

from .database import DATA_DIR

FERNET_KEY_PATH = os.path.join(DATA_DIR, "fernet.key")


def _ensure_key() -> bytes:
    if os.path.exists(FERNET_KEY_PATH):
        with open(FERNET_KEY_PATH, "rb") as fh:
            return fh.read()
    key = Fernet.generate_key()
    with open(FERNET_KEY_PATH, "wb") as fh:
        fh.write(key)
    return key


@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    key = _ensure_key()
    return Fernet(key)


def encrypt(value: Optional[str]) -> Optional[bytes]:
    if value is None:
        return None
    f = _get_fernet()
    return f.encrypt(value.encode("utf-8"))


def decrypt(token: Optional[bytes]) -> Optional[str]:
    if token is None:
        return None
    f = _get_fernet()
    return f.decrypt(token).decode("utf-8")
