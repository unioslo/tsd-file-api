# -*- coding: utf-8 -*-

import os
import re
import logging
import hashlib
import subprocess
import shlex
import re
import shutil

from typing import Union

_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')


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
) -> str:
    """
    Construct a path for sns uploads.

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
            logging.info('Creating %s', _path)
            os.makedirs(_path)
            subprocess.call(['chmod', '2770', _path])
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
