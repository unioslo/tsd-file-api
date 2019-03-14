# -*- coding: utf-8 -*-

# Spurred to use this by: http://lucumr.pocoo.org/2010/12/24/common-mistakes-as-web-developer/
# code taken from: werkzeug.utils and werkzeug._compat

"""
    This module implements various utilities for WSGI applications.  Most of
    them are used by the request and response wrappers but especially for
    middleware development it makes sense to use them without the wrappers.

    :copyright: (c) 2014 by the Werkzeug Team, see AUTHORS for more details.
    :license: BSD, see LICENSE for more details.
"""

import os
import re
import logging
import hashlib


_VALID_PNUM = re.compile(r'^[0-9a-z]+$')
_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
IS_VALID_GROUPNAME = re.compile(r'p+[0-9]+-[a-z-]')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')

# from werkzeug/_compat.py#L16
text_type = unicode
# from werkzeug/utils.py#L30
_filename_ascii_strip_re = re.compile(r'[^A-Za-z0-9_.-]')

def secure_filename(filename):
    r"""Pass it a filename and it will return a secure version of it.  This
    filename can then safely be stored on a regular file system and passed
    to :func:`os.path.join`.  The filename returned is an ASCII only string
    for maximum portability.

    On windows systems the function also makes sure that the file is not
    named after one of the special device files.

    >>> secure_filename("My cool movie.mov")
    'My_cool_movie.mov'
    >>> secure_filename("../../../etc/passwd")
    'etc_passwd'
    >>> secure_filename(u'i contain cool \xfcml\xe4uts.txt')
    'i_contain_cool_umlauts.txt'

    The function might return an empty filename.  It's your responsibility
    to ensure that the filename is unique and that you generate random
    filename if the function returned an empty one.

    .. versionadded:: 0.5

    :param filename: the filename to secure
    """
    if isinstance(filename, text_type):
        from unicodedata import normalize
        filename = normalize('NFKD', filename).encode('ascii', 'ignore')
        #if not PY2:
        #    filename = filename.decode('ascii')
    for sep in os.path.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, ' ')
    filename = str(_filename_ascii_strip_re.sub('', '_'.join(filename.split()))).strip('._')
    return filename


def check_filename(filename):
    """A version which does not change the name, but throws an exception instead."""
    if isinstance(filename, text_type):
        from unicodedata import normalize
        filename = normalize('NFKD', filename).encode('ascii', 'ignore')
        #if not PY2:
        #    filename = filename.decode('ascii')
    for sep in os.path.sep, os.path.altsep:
        if _filename_ascii_strip_re.search(filename):
            logging.error('illegal filename provided: %s', filename)
            raise Exception('file name not allowed')
        if sep and sep in filename:
            logging.error('illegal filename provided: %s', filename)
            raise Exception('file name not allowed')
    return filename



def project_import_dir(uploads_folder, pnum, keyid=None, formid=None):
    """
    Create a project specific path based on config and a project number.

    Paramaters
    ----------
    uploads_folder: list
    pnum: str
    keyid: not used
    formid: not used

    Returns
    -------
    path

    """
    try:
        assert _VALID_PNUM.match(pnum)
        folder = uploads_folder[pnum]
    except KeyError as e:
        folder = uploads_folder['default'].replace('pXX', pnum)
    return os.path.normpath(folder)

def project_sns_dir(sns_uploads_folder, pnum, keyid=None, formid=None, test=False,
                    use_hidden_tsd_folder=False):
    """
    Construct a path for sns uploads.

    Paramaters
    ----------
    uploads_folder: list
    pnum: str
    keyid: PGP public key id - must match what we already have
    formid: nettskjema form id - restricted to numerical chars

    Notes
    -----
    The following must be true for the path to be constructed
    (and, therefore, data to be written to a file):

        1) pnum must be alphanumeric
        2) the project must have a /tsd/pXX/data/durable/nettskjema folder already
        3) formid must be numeric
        4) the provided PGP key id must be realistic

    If the keyid/formid path does not exist, it will be created.

    Returns
    -------
    path

    """
    if not use_hidden_tsd_folder:
        base_pattern = '/tsd/pXX/data/durable/nettskjema-submissions/keyid/formid'
    else:
        base_pattern = '/tsd/pXX/data/durable/nettskjema-submissions/.tsd/keyid/formid'
    try:
        assert _VALID_PNUM.match(pnum)
        durable = sns_uploads_folder.replace('pXX', pnum)
        if not os.path.lexists(durable):
            logging.error('durable folder does not exist for %s', pnum)
            raise Exception
        assert _VALID_FORMID.match(formid)
        assert _IS_REALISTIC_PGP_KEY_FINGERPRINT.match(keyid)
        folder = base_pattern.replace('pXX', pnum).replace('keyid', keyid).replace('formid', formid)
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
