# -*- coding: utf-8 -*-

import os
import re
import logging
import hashlib
import subprocess
import shlex


_VALID_PNUM = re.compile(r'^[0-9a-z]+$')
_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
IS_VALID_GROUPNAME = re.compile(r'p+[0-9]+-[a-z-]')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')


def call_request_hook(path, params):
    cmd = ['sudo']
    cmd.append(shlex.quote(path))
    cmd.extend(params)
    subprocess.call(cmd)


class IllegalFilenameException(Exception):
    message = 'Filename not allowed'


def pnum_from_url(url):
    if 'v1' in url:
        idx = 2
    else:
        idx = 1
    return url.split('/')[idx]


def check_filename(filename):
    disallowed_start_chars = ['~', '.']
    try: # py2/3 compat
        if isinstance(filename, unicode):
            filename = filename.encode('utf-8')
    except (Exception, NameError) as e:
        pass
    try:
        if os.path.basename(filename) != filename:
            logging.error('Filename not a basename')
            raise Exception
        start_char = filename[0]
        if start_char in disallowed_start_chars:
            logging.error('Filename has illegal start character: {0}'.format(start_char))
            raise Exception
    except Exception:
        raise IllegalFilenameException
    for sep in os.path.sep, os.path.altsep:
        if sep and sep in filename:
            logging.error('filename not a basename')
            raise IllegalFilenameException
    return filename


def create_cluster_dir_if_not_exists(path, pnum):
    base = path.replace('pXX', pnum).replace('/file-import', '')
    target = path.replace('pXX', pnum)
    if os.path.lexists(base):
        if not os.path.lexists(target):
            os.makedirs(target)
        return target
    else:
        raise Exception('{0} does not have a cluster disk space'.format(pnum))


def project_sns_dir(base_pattern, pnum, uri, test=False):
    """
    Construct a path for sns uploads.

    Paramaters
    ----------
    config: dict
    pnum: str
    uri: request uri
    test: bool

    Returns
    -------
    path

    """
    try:
        uri_parts = uri.split('/')
        formid = uri_parts[-1]
        keyid = uri_parts[-2]
        assert _VALID_FORMID.match(formid)
        assert _IS_REALISTIC_PGP_KEY_FINGERPRINT.match(keyid)
        folder = base_pattern.replace('pXX', pnum).replace('KEYID', keyid).replace('FORMID', formid)
        _path = os.path.normpath(folder)
        if test:
            return _path
        if not os.path.lexists(_path):
            logging.info('Creating %s', _path)
            os.makedirs(_path)
        return _path
    except Exception as e:
        logging.error(e)
        logging.error('Could not resolve specified directory with key ID: %s', keyid)
        raise e


def md5sum(filename, blocksize=65536):
    _hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            _hash.update(block)
    return _hash.hexdigest()


def atoi(text):
    return int(text) if text.isdigit() else text


def natural_keys(text):
    """
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    """
    return [ atoi(c) for c in re.split(r'(\d+)', text) ]
