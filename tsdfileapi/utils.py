# -*- coding: utf-8 -*-

import os
import re
import logging
import hashlib
import subprocess
import shlex
import re
import shutil

from typing import Union, Optional

import tornado.options

_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')


def _find_ess_dir(pnum: str, root: str = "/ess",) -> Optional[str]:
    sub_dir = None
    for projects_dir in os.listdir(root):
        if pnum in os.listdir(f"{root}/{projects_dir}"):
            sub_dir = projects_dir
            break
    return None if not sub_dir else f"{root}/{sub_dir}/{pnum}/data/durable"


class StorageTemporarilyUnavailableError(Exception):
    """
    Raised for backends which cannot be used during migration.

    """
    pass


def find_tenant_storage_path(
    tenant: str,
    endpoint_backend: str,
    opts: tornado.options.OptionParser,
    root: str = "/ess",
    default_storage_backend: str = "hnas",
) -> str:
    """
    Either one of these:

        - /tsd/{pnum}/data/durable
        - /ess/projects0{1|2|3}/{pnum}/data/durable

    Results are cached in a dict stored on options:

    {
        pnum: {
            storage_backend: Optional[str] (hnas|migrating|ess),
            storage_paths: {
                hnas: str,
                ess: Optional[str],
            },
        },
        ...
    }

    Returns the path which the endpoint_backend should use.

    """
    cache = opts.tenant_storage_cache.copy()
    if not cache.get(tenant):
        cache[tenant] = {
            "storage_backend": opts.migration_statuses.get(tenant, default_storage_backend),
            "storage_paths": {
                "hnas": f"/tsd/{tenant}/data/durable",
                "ess": None,
            }
        }
    else:
        cache[tenant]["storage_backend"] = opts.migration_statuses.get(tenant, default_storage_backend)
    if (
        opts.migration_statuses.get(tenant, default_storage_backend) == "ess"
        and not cache.get(tenant).get("storage_paths").get("ess")
    ):
        cache[tenant]["storage_backend"] = "ess"
        cache[tenant]["storage_paths"]["ess"] = _find_ess_dir(tenant, root=root)
    opts.tenant_storage_cache = cache
    preferred = "ess" if endpoint_backend in opts.prefer_ess else "hnas"
    current_storage_backend = cache.get(tenant).get("storage_backend")
    if current_storage_backend == "migrating":
        if preferred == "ess":
            raise StorageTemporarilyUnavailableError
        else:
            return cache.get(tenant).get("storage_paths").get(preferred)
    elif current_storage_backend == "ess":
        return cache.get(tenant).get("storage_paths").get(preferred)
    else:
        return cache.get(tenant).get("storage_paths").get("hnas")


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
        tenant, endpoint_backend, opts,
    ).split(split_on)
    in_dir = directory.split(split_on)
    out_dir = "".join([storage_path[0], split_on, in_dir[-1]])
    return out_dir


def call_request_hook(path: str, params: list, as_sudo: bool = True) -> None:
    if as_sudo:
        cmd = ['sudo']
    else:
        cmd = []
    cmd.append(shlex.quote(path))
    cmd.extend(params)
    subprocess.call(cmd)


class IllegalFilenameException(Exception):
    message = 'Filename not allowed'


def tenant_from_url(url: str) -> list:
    if 'v1' in url:
        idx = 2
    else:
        idx = 1
    return url.split('/')[idx]


def check_filename(filename: str, disallowed_start_chars: list = []) -> str:
    try:
        start_char = filename[0]
        if disallowed_start_chars:
            if start_char in disallowed_start_chars:
                logging.error('Filename has illegal start character: {0}'.format(start_char))
                raise Exception
    except Exception:
        raise IllegalFilenameException
    return filename


def sns_dir(
    base_pattern: str,
    tenant: str,
    uri: str,
    tenant_string_pattern: str,
    test: bool = False,
    opts: tornado.options.OptionParser = None,
) -> str:
    """
    Construct a path for sns uploads. Create it if missing.
    If ESS is available, create the path there too.

    """
    try:
        uri_parts = uri.split('/')
        formid = uri_parts[-1]
        keyid = uri_parts[-2]
        assert _VALID_FORMID.match(formid), f'invalid form ID: {formid}'
        assert _IS_REALISTIC_PGP_KEY_FINGERPRINT.match(keyid), f'invalid PGP fingerprint: {keyid}'
        folder = base_pattern.replace(tenant_string_pattern, tenant).replace('KEYID', keyid).replace('FORMID', formid)
        _path = os.path.normpath(folder)
        if test:
            return _path
        if not os.path.lexists(_path):
            try:
                os.makedirs(_path)
                subprocess.call(['chmod', '2770', _path])
                logging.info('Created %s', _path)
            except Exception as e:
                logging.error(e)
                logging.error(f"Could not create {_path}")
                raise e
        if (
            opts and _path.startswith("/tsd")
            and tenant in opts.sns_migrations or "all" in opts.sns_migrations
        ):
            try:
                ess_path = opts.tenant_storage_cache.get(tenant, {}).get("storage_paths", {}).get("ess")
                target = _path.replace(f"/tsd/{tenant}/data/durable", ess_path) if ess_path else None
                if ess_path and target and not os.path.lexists(target):
                    os.makedirs(target)
                    subprocess.call(['chmod', '2770', target])
                    logging.info(f"Created {target}")
            except Exception as e:
                logging.error(e)
                logging.error(f"Could not create {target}")
                # no reason to abort just yet
        return _path
    except (Exception, AssertionError, IndexError) as e:
        logging.error(e)
        raise e


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
        base_dir = path.replace(f'/{filename}', '')
        new_path = os.path.normpath(dest + '/' + filename)
        if os.path.isdir(path):
            if os.path.lexists(new_path):
                # idempotency
                shutil.rmtree(new_path)
            shutil.move(path, new_path)
        else:
            os.rename(path, new_path)
        return new_path
    except Exception as e:
        logging.error(e)
        logging.error('could not move file: %s', path)
        return False

def set_mtime(path: str, mtime: int) -> None:
    mtime = mtime
    atime = mtime
    os.utime(path, (mtime, atime))
