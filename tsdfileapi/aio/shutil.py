from shutil import COPY_BUFSIZE

from aioshutil import *  # noqa: F403


async def copyfileobj(fsrc, fdst, length=0):
    """
    A co-routine equivalent of `shutil.copyfilobj` for file-like object that feature co-routines for methods like `read` and `write`.

    The variant imported from `aioshutil` naively wraps `shutil.copyfileobj` which not only keeps the worker thread occupied for the duration of the _entire_ copy process -- as opposed to yielding between each copied chunk -- but also assumes same file-object interface as the builtin it wraps -- co-routines are not supported. This is unfortunate since much of the point with an already re-worked API (you need to use `await` for `aioshutil.copyfileobj` anyway) is to leverage the event loop.
    """
    if not length:
        length = COPY_BUFSIZE
    # Localize variable access to minimize overhead.
    fsrc_read = fsrc.read
    fdst_write = fdst.write
    while buf := await fsrc_read(length):
        await fdst_write(buf)
