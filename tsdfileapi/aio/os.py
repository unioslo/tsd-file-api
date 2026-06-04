import os

from aiofiles.base import wrap
from aiofiles.os import *  # noqa: F403

from . import ospath as path  # noqa: F401

# Complement missing procedures
for name in ("chmod", "lstat", "utime", "walk"):
    if not name in globals():
        globals()[name] = wrap(getattr(os, name))
