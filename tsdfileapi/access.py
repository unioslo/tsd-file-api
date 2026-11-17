"""
Helpers for ensuring that the API process can perform filesystem operations.

Access is attempted natively first. If the process lacks the required
privileges for ``chmod``/``chown`` and ``sudo`` fallback is enabled, the
operation is retried through ``sudo``.

Deployments can avoid the ``sudo`` fallback entirely by granting the process
the necessary Linux capabilities (``CAP_FOWNER`` for ``chmod`` and
``CAP_CHOWN`` for ``chown``), either through systemd's
``AmbientCapabilities=`` or the container runtime's capability options.
"""

import os
import stat
from collections.abc import Awaitable
from collections.abc import Callable
from contextlib import asynccontextmanager

from tsdfileapi import aio
from tsdfileapi.utils import asystem


def _permission_bits(mode: int) -> int:
    return stat.S_IMODE(mode)


def _with_read_access(mode: int) -> int:
    mode |= stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    if stat.S_ISDIR(mode) or mode & 0o111:
        mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    return mode


def _with_write_access(mode: int) -> int:
    mode |= stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    if stat.S_ISDIR(mode):
        mode |= (
            stat.S_IRUSR
            | stat.S_IRGRP
            | stat.S_IROTH
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
    return mode


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


async def chmod(
    path: str,
    mode: int,
    *,
    sudo: bool = False,
    recursive: bool = False,
) -> None:
    """
    Set the permission bits of ``path``, falling back to ``sudo chmod`` if the
    process is not permitted to do so natively.
    """
    mode = _permission_bits(mode)
    try:
        if recursive and await aio.os.path.isdir(path):
            await aio.os.chmod(path, mode)
            async for root, dirs, files in aio.os.walk(path):
                for entry in dirs + files:
                    entry_path = os.path.join(root, entry)
                    if await aio.os.path.islink(entry_path):
                        continue
                    await aio.os.chmod(entry_path, mode)
        else:
            await aio.os.chmod(path, mode)
    except PermissionError:
        if not sudo:
            raise
        args = ["sudo", "chmod"]
        if recursive:
            args.append("-R")
        args.extend([oct(mode)[2:], path])
        await asystem(args)


async def chown(
    path: str,
    uid: int,
    gid: int,
    *,
    sudo: bool = False,
    recursive: bool = False,
) -> None:
    """
    Set the owner and group of ``path``, falling back to ``sudo chown`` if the
    process is not permitted to do so natively.
    """
    try:
        if recursive and await aio.os.path.isdir(path):
            await aio.os.chown(path, uid, gid)
            async for root, dirs, files in aio.os.walk(path):
                for entry in dirs + files:
                    entry_path = os.path.join(root, entry)
                    if await aio.os.path.islink(entry_path):
                        continue
                    await aio.os.chown(entry_path, uid, gid)
        else:
            await aio.os.chown(path, uid, gid)
    except PermissionError:
        if not sudo:
            raise
        args = ["sudo", "chown"]
        if recursive:
            args.append("-R")
        args.extend([f"{uid}:{gid}", path])
        await asystem(args)


async def ensure_access(
    path: str,
    mode: int = os.R_OK,
    *,
    sudo: bool = False,
    recursive: bool = False,
) -> None:
    """
    Ensure that the API process can access ``path`` with the requested mode.

    The permission bits needed to satisfy ``mode`` are added to the existing
    mode before ``chmod`` is attempted.
    """
    if await aio.os.access(path, mode):
        return
    st = await aio.os.stat(path)
    new_mode = st.st_mode
    if mode & os.R_OK:
        new_mode = _with_read_access(new_mode)
    if mode & os.W_OK:
        new_mode = _with_write_access(new_mode)
    if mode & os.X_OK:
        new_mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if _permission_bits(new_mode) != _permission_bits(st.st_mode):
        await chmod(path, new_mode, sudo=sudo, recursive=recursive)


async def ensure_parent_access(
    path: str,
    mode: int = os.X_OK,
    *,
    root: str,
    sudo: bool = False,
) -> None:
    """
    Ensure that the parent directories of ``path`` are accessible.

    Traversal stops at ``root``, to avoid changing permissions outside of the
    backend's storage tree.
    """
    parent = os.path.dirname(os.path.abspath(path))
    root = os.path.abspath(root)
    if not _within(parent, root):
        return
    while True:
        await ensure_access(parent, mode, sudo=sudo)
        if parent == root:
            break
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            break
        if not _within(next_parent, root):
            break
        parent = next_parent


@asynccontextmanager
async def temporary_write_access(path: str, *, sudo: bool = False):
    """
    Temporarily grant group/other write and traversal rights on ``path`` and
    restore the original permission bits afterwards.

    Intended for directories whose entries need to be renamed or deleted.
    """
    st = await aio.os.stat(path)
    granted = False
    if not await aio.os.access(path, os.W_OK | os.X_OK):
        await chmod(path, _with_write_access(st.st_mode), sudo=sudo)
        granted = True
    try:
        yield
    finally:
        if granted:
            await chmod(path, st.st_mode, sudo=sudo)


async def retry_on_permission_error(
    operation: Callable[[], Awaitable],
    path: str,
    *,
    mode: int = os.R_OK,
    parent: bool = False,
    root: str | None = None,
    sudo: bool = False,
    recursive: bool = False,
):
    """
    Run ``operation`` once, and if it raises ``PermissionError``, ensure the
    required access on ``path`` and try again.
    """
    try:
        return await operation()
    except PermissionError:
        if parent:
            if root is None:
                raise ValueError("root is required when parent=True")
            await ensure_parent_access(path, mode, root=root, sudo=sudo)
        else:
            await ensure_access(path, mode, sudo=sudo, recursive=recursive)
        return await operation()
