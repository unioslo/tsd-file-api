from os import path

from aiofiles.base import wrap
from aiofiles.ospath import *  # noqa: F403

# Complement missing procedures
for name in ("lexists",):
    if not name in globals():
        globals()[name] = wrap(getattr(path, name))
