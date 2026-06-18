import itertools as _itertools
import os as _os
import sys as _sys
from asyncio import to_thread as _to_thread
from collections import deque as _deque
from collections.abc import Iterator as _Iterator

from aiofiles.base import wrap as _wrap
from aiofiles.os import *  # noqa: F403

from . import ospath as path  # noqa: F401

# Complement missing procedures
for _name in ("chmod", "lstat", "utime"):
    if not _name in globals():
        globals()[_name] = _wrap(getattr(_os, _name))


class _AsyncDirEntry:
    __slots__ = ("_entry",)

    def __init__(self, entry: _os.DirEntry):
        self._entry = entry

    def __getattr__(self, name):
        return getattr(self._entry, name)

    def _delegate(name):
        return lambda self, *args, **kwargs: _to_thread(
            getattr(self._entry, name), *args, **kwargs
        )

    for _name in ("inode", "is_dir", "is_file", "is_symlink", "is_junction", "stat"):
        locals()[_name] = _delegate(_name)

    def _delegate(name):
        return lambda self, *args, **kwargs: getattr(self._entry, name)(*args, **kwargs)

    for _name in ("__fspath__", "__hash__", "__eq__", "__repr__", "__str__"):
        locals()[_name] = _delegate(_name)

    del _delegate, _name


class _AsyncScandirIterator:
    def __init__(self, it: _Iterator, batch_size: int):
        self._it = it
        self._batch_size = batch_size
        self._buffer = _deque()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.aclose()

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._buffer:
            await _to_thread(self._load)
            if not self._buffer:
                raise StopAsyncIteration
        return _AsyncDirEntry(self._buffer.popleft())

    def _load(self):
        self._buffer.extend(_itertools.islice(self._it, self._batch_size))

    async def aclose(self):
        await _to_thread(self._it.close)


async def scandir(
    *args, batch_size=int(_os.getenv("SCANDIR_BATCH_SIZE", "25")), **kwargs
):
    """
    An equivalent of `_os.scandir` that returns an _asynchronous_ iterator that vends entries that feature co-routines for I/O, in _batches_ (to save on cumulative inter-thread communication costs).

    The batch size determines how many files are discovered and buffered on each pass of the scanning (iteration).
    """
    return _AsyncScandirIterator(
        await _to_thread(_os.scandir, *args, **kwargs), batch_size
    )


async def walk(top, topdown=True, onerror=None, followlinks=False):
    """
    An implementation of `walk` copied from Python 3.14 (tweaked for code size) and amended to use co-routines internally (for a more responsive event loop than `_wrap_os.walk, ...)` could allow).
    """
    _sys.audit("os.walk", top, topdown, onerror, followlinks)
    stack = [_os.fspath(top)]
    while stack:
        top = stack.pop()
        if isinstance(top, tuple):
            yield top
            continue
        dirs = []
        nondirs = []
        walk_dirs = []
        try:
            async with await scandir(top) as entries:
                async for entry in entries:
                    try:
                        is_dir = await entry.is_dir()
                    except OSError:
                        is_dir = False
                    (dirs if is_dir else nondirs).append(entry.name)
                    if not topdown and is_dir:
                        if not followlinks:
                            try:
                                is_symlink = entry.is_symlink()
                            except OSError as error:
                                onerror(error)
                                is_symlink = False
                        if followlinks or not is_symlink:
                            walk_dirs.append(entry.path)
        except OSError as error:
            if onerror is not None:
                onerror(error)
        else:
            if topdown:
                yield top, dirs, nondirs
                paths = (_os.path.join(top, dirname) for dirname in reversed(dirs))
                if followlinks:
                    paths = [x for x in paths if not await path.islink(x)]
            else:
                stack.append((top, dirs, nondirs))
                paths = reversed(walk_dirs)
            stack.extend(paths)
