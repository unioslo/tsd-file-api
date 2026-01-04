import datetime
import errno
import functools
import hashlib
import itertools
import logging
import os
import pathlib
import re
import reprlib
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Callable
from typing import Mapping
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
        storage_path_ess = _find_ess_dir(tenant, root=root)
        if not storage_path_ess:
            return None

        cache[tenant] = {
            "storage_backend": "ess",
            "storage_paths": {
                "ess": storage_path_ess,
            },
        }
        opts.tenant_storage_cache = cache.copy()
    out = opts.tenant_storage_cache[tenant]["storage_paths"]["ess"]
    return out


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
        directory = (
            base_pattern.replace(tenant_string_pattern, tenant)
            .replace("KEYID", keyid)
            .replace("FORMID", formid)
        )
        sns_dir = choose_storage(
            tenant=tenant,
            endpoint_backend="sns",
            opts=options,
            directory=directory,
        )
        try:
            if not os.path.lexists(sns_dir):
                os.makedirs(sns_dir)
                subprocess.call(["sudo", "chmod", "2770", sns_dir])
                logger.info(f"Created: {sns_dir}")
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise ServerStorageNotMountedError(
                    f"NFS mount missing for {sns_dir}"
                ) from e
            else:
                raise e
        return sns_dir
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


def cidr_to_set(ip: str) -> set:
    """Converts a CIDR to a set of IP addresses."""
    return {str(x) for x in ip_network(ip)}


def trusted_proxies_to_trusted_downstream(
    trusted_proxies: list = None,
) -> Optional[list]:
    """Convert our trusted_proxies (CIDR supported) format to a list of IP addresses.

    Tornado expects a list of IP addresses, so we must expand CIDR network
    ranges to lists of IP addresses that it can support.
    """
    if not trusted_proxies:
        return None
    trusted_downstream = set()
    for proxy in trusted_proxies:
        trusted_downstream = trusted_downstream | cidr_to_set(proxy)
    return list(trusted_downstream)


class LoggedObjectRepr(reprlib.Repr):
    def repr_call(self, callable, args, kwargs):
        return (
            self.repr(callable)
            + "("
            + ", ".join(self.repr(arg) for arg in args)
            + (
                (
                    ", "
                    + ", ".join(
                        (name + "=" + self.repr(value))
                        for name, value in kwargs.items()
                    )
                )
                if kwargs
                else ""
            )
            + ")"
        )

    @staticmethod
    def repr_bytes(obj, *_):
        return f"<{len(obj)} byte(s)>"


logged_object_repr = LoggedObjectRepr()
logged_object_repr.maxother = sys.maxsize


def with_logged_calls(logger: logging.Logger, level: Union[int | str]) -> Callable:
    """
    A decorator that makes calling an object (normally a function) produce a log message.
    """
    if not isinstance(level, int):
        level = logging.getLevelNamesMapping()[level] # Not available on Python 3.10, so level names cannot be used before 3.11

    def decorator(callable):
        @functools.wraps(callable)
        def wrapper(*args, **kwargs):
            logger.log(
                level, logged_object_repr.repr_call(callable, args, kwargs)
            )  # TODO: This message uses utils.py as origin while it'd be preferable the call site of `decorator` was used instead
            return callable(*args, **kwargs)

        return wrapper

    return decorator


@dataclass
class ParametrisedField:
    """
    Parsed elements of values of HTTP request headers like `Prefer` (et al. -- the same syntax is reused across HTTP)

    See `parse_http_request_handling_preference` which does the parsing and returns an object of this class.
    """

    name: str
    value: str
    params: dict[str, str]


def parse_http_prefer_header_values(*header_values: str) -> Mapping[str, ParametrisedField]:
    """
    Parse one or several HTTP headers like the `Prefer` request header.

    Input may be text like "foo=1; bar=baz, hello-world" which if parsed "breadth first" contains 2 elements `foo=1; bar=baz` and `hello-world`, each of these superficially resembling the syntax shared with the `Content-Type` header, with the former parsed further into `foo=1`, with `foo` being the principal key or name of the element and `1` being the value, and `bar=baz` and any other `;`-separated pair(s) called parameters, each being a key-value pair much like `foo=1`; `hello-world` not featuring a `=` followed by a value is equivalent to `hello-world=` where the value is the empty string, and no parameters (empty list).

    Returns the set of parsed fields, as a dictionary, keyed by the field name (matching the value of the `name` attribute).
    """
    return {
        pref.name: pref
        for pref in (
            parse_http_request_handling_preference(pref_text)
            for pref_text in itertools.chain.from_iterable(
                re.split(r"\s*,\s*", header_value) for header_value in header_values
            )
        )
    }


def parse_http_request_handling_preference(text: str) -> ParametrisedField:
    """
    Parse a single component (field) of a HTTP header like the `Prefer` request header.

    E.g. `parse_http_request_handling_preference("foo=1; bar=baz")` produces a single so-called field, an element with a key, a value and one or multiple parameters.
    """
    first, *rest = (re.split(r"\s*=\s*", part) for part in re.split(r"\s*;\s*", text))
    return ParametrisedField(
        name=first[0], value=first[1] if len(first) > 1 else "", params=dict(rest)
    )
