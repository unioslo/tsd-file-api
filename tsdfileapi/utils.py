import datetime
import errno
import hashlib
import logging
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
from typing import Optional
from typing import Union

import tornado.options

from tsdfileapi.exc import ClientIllegalFilenameError
from tsdfileapi.exc import ClientIllegalFiletypeError
from tsdfileapi.exc import ClientSnsPathError
from tsdfileapi.exc import ServerSnsError
from tsdfileapi.exc import ServerStorageNotMountedError

VALID_FORMID = re.compile(r"^[0-9]+$")
PGP_KEY_FINGERPRINT = re.compile(r"^[0-9A-Z]{16}$")
VALID_UUID = re.compile(r"([a-f\d0-9-]{32,36})")

logger = logging.getLogger(__name__)


def days_since_mod(path: str) -> int:
    """
    Calculate the amount of days that have elapsed
    since the given path was modified.

    """
    current_moment = datetime.datetime.now()
    mtime_moment = datetime.datetime.fromtimestamp(os.stat(path).st_mtime)
    days_since = (current_moment - mtime_moment).days
    return days_since


def _rwxrwx___() -> int:
    u = stat.S_IREAD | stat.S_IWRITE | stat.S_IXUSR
    g = stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
    return u | g


def _rwxrws___() -> int:
    return _rwxrwx___() | stat.S_ISGID


def _find_ess_dir(
    pnum: str,
    root: str = "/ess",
) -> Optional[str]:
    sub_dir = None
    for projects_dir in os.listdir(root):
        if pnum in os.listdir(f"{root}/{projects_dir}"):
            sub_dir = projects_dir
            break
    return None if not sub_dir else f"{root}/{sub_dir}/{pnum}/data/durable"


def find_tenant_storage_path(
    tenant: str,
    endpoint_backend: str,
    opts: tornado.options.OptionParser,
    root: str = "/ess",
) -> str:
    """
    Either one of these: /ess/projects0{1|2|3|...|n}/{pnum}/data/durable
    Results are cached in a dict stored on options.
    Returns the base path which the endpoint_backend should use.

    """
    cache = opts.tenant_storage_cache.copy()
    if not cache.get(tenant):
        cache[tenant] = {
            "storage_backend": "ess",
            "storage_paths": {
                "ess": _find_ess_dir(tenant, root=root),
            },
        }
        opts.tenant_storage_cache = cache.copy()
    return opts.tenant_storage_cache["storage_paths"]["ess"]


def choose_storage(
    *,
    tenant: str,
    endpoint_backend: str,
    opts: tornado.options.OptionParser,
    directory: str,
) -> str:
    if not directory.startswith("/tsd"):
        return directory
    split_on = "data/durable"
    storage_path = find_tenant_storage_path(
        tenant,
        endpoint_backend,
        opts,
    ).split(split_on)
    in_dir = directory.split(split_on)
    out_dir = "".join([storage_path[0], split_on, in_dir[-1]])
    return out_dir


def call_request_hook(path: str, params: list, as_sudo: bool = True) -> None:
    if as_sudo:
        cmd = ["sudo"]
    else:
        cmd = []
    cmd.append(shlex.quote(path))
    cmd.extend(params)
    subprocess.call(cmd)


def tenant_from_url(url: str) -> list:
    if "v1" in url:
        idx = 2
    else:
        idx = 1
    return url.split("/")[idx]


def check_filename(filename: str, disallowed_start_chars: list = []) -> str:
    start_char = filename[0]
    if disallowed_start_chars:
        if start_char in disallowed_start_chars:
            raise ClientIllegalFilenameError(
                f"Filename: {filename} has illegal start character: {start_char}"
            )
    return filename


def sns_dir(
    base_pattern: str,
    tenant: str,
    uri: str,
    tenant_string_pattern: str,
    test: bool = False,
    options: tornado.options.OptionParser = None,
) -> str:
    """
    Construct and create a path for sns uploads.

    """
    try:
        uri_parts = uri.split("/")
        formid = uri_parts[-1]
        keyid = uri_parts[-2]
        if not VALID_FORMID.match(formid):
            raise ClientSnsPathError(f"invalid form ID: {formid}")
        if not PGP_KEY_FINGERPRINT.match(keyid):
            raise ClientSnsPathError(f"invalid PGP fingerprint: {keyid}")
        try:
            ess_path = (
                options.tenant_storage_cache.get(tenant, {})
                .get("storage_paths", {})
                .get("ess", "")
            )
            ess_sns_dir = (
                base_pattern.replace(tenant_string_pattern, tenant)
                .replace("KEYID", keyid)
                .replace("FORMID", formid)
                .replace(f"/tsd/{tenant}/data/durable", ess_path)
            )
            if not os.path.lexists(ess_sns_dir):
                os.makedirs(ess_sns_dir)
                subprocess.call(["sudo", "chmod", "2770", ess_sns_dir])
                logger.info(f"Created: {ess_sns_dir}")
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise ServerStorageNotMountedError(
                    f"NFS mount missing for {ess_path}"
                ) from e
            else:
                raise e
        return ess_sns_dir
    except Exception as e:
        logger.error(e)
        raise ServerSnsError from e


def md5sum(filename: str, blocksize: int = 65536) -> str:
    _hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            _hash.update(block)
    return _hash.hexdigest()


def move_data_to_folder(path: str, dest: str) -> Union[str, bool]:
    """
    Move file/dir at path into and folder at dest.

    """
    try:
        if not dest:
            return path
        filename = os.path.basename(path)
        new_path = os.path.normpath(dest + "/" + filename)
        if os.path.isdir(path):
            if os.path.lexists(new_path):
                # idempotency
                shutil.rmtree(new_path)
            shutil.move(path, new_path)
        else:
            os.rename(path, new_path)
        return new_path
    except Exception as e:
        logger.error(e)
        logger.error("could not move file: %s", path)
        return False


def set_mtime(path: str, mtime: int) -> None:
    mtime = mtime
    atime = mtime
    os.utime(path, (mtime, atime))


def any_path_islink(
    path: Union[str, pathlib.Path],
    opts: tornado.options.OptionParser,
) -> bool:
    """Check if any part of a given path is a symlink.
    Args:
        path (str): path to check
    Raises:
        ClientIllegalFiletypeError: if a symlink is found in the path
    Returns:
        bool: function returns false if no part of path is a symlink
    """
    allowed_symlinks = [pathlib.Path(path) for path in opts.allowed_symlinks]
    if isinstance(path, str):
        path = pathlib.Path(path)
    while path != path.parent:
        if path.is_symlink() and path not in allowed_symlinks:
            raise ClientIllegalFiletypeError(
                f"Path '{path}' is a symlink to '{os.readlink(path)}'."
            )
        path = path.parent
    return False
