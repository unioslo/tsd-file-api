# -*- coding: utf-8 -*-

import os
import re
import logging
import hashlib


_VALID_PNUM = re.compile(r'^[0-9a-z]+$')
_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
IS_VALID_GROUPNAME = re.compile(r'p+[0-9]+-[a-z-]')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')
ILLEGAL_CHARS = re.compile(r'[^A-Za-z0-9_().æøåÆØÅ\-]')


class IllegalFilenameException(Exception):
    message = 'Filename not allowed'


def pnum_from_url(url):
    if 'v1' in url:
        idx = 2
    else:
        idx = 1
    return url.split('/')[idx]


def check_filename(filename):
    try: # py2/3 compat
        if isinstance(filename, unicode):
            filename = filename.encode('utf-8')
    except (Exception, NameError) as e:
        pass
    try:
        assert os.path.basename(filename) == filename
    except Exception:
        logging.error('filename not a basename')
        raise IllegalFilenameException
    for sep in os.path.sep, os.path.altsep:
        if sep and sep in filename:
            logging.error('filename not a basename')
            raise IllegalFilenameException
    if ILLEGAL_CHARS.search(filename):
            logging.error('filename has illegal characters')
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

def project_import_dir(config, pnum=None, keyid=None,
                       formid=None, backend=False):
    """
    Create a project specific path based on config and a project number.

    If backend=False, then the project directory is located on
    /durable, otherwise it is on /cluster. For the latter case,
    we first ensure that /cluster/projects/{pnum} exists, and if so
    check whether /cluster/projects/{pnum}/file-import exists. If not,
    it is created, and the path returned. Otherwise an exception is
    raise, since the project first needs to get this storage.

    Paramaters
    ----------
    config: dict
    pnum: str
    keyid: deprecated
    formid: deprecated
    cluster: bool, default=False

    Returns
    -------
    path

    """
    try:
        assert _VALID_PNUM.match(pnum)
        if backend != 'cluster' and pnum == 'p01':
            return config['uploads_folder_cluster_software']
        elif backend == 'cluster':
            path = config['uploads_folder_cluster']
            base = path.replace('pXX', pnum).replace('/file-import', '')
            target = path.replace('pXX', pnum)
            if os.path.lexists(base):
                if not os.path.lexists(target):
                    os.makedirs(target) # unsure if we have the permissions
                return target
            else:
                raise Exception('{0} does not have a cluster disk space'.format(pnum))
        folder = config['uploads_folder'][pnum]
    except KeyError as e:
        folder = config['uploads_folder']['default'].replace('pXX', pnum)
    return os.path.normpath(folder)


def project_sns_dir(config, pnum, keyid=None, formid=None, test=False,
                    use_hidden_tsd_folder=False):
    """
    Construct a path for sns uploads.

    Paramaters
    ----------
    config: dict
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
    sns_uploads_folder = config['sns_uploads_folder']
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


def atoi(text):
    return int(text) if text.isdigit() else text


def natural_keys(text):
    """
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    """
    return [ atoi(c) for c in re.split(r'(\d+)', text) ]
