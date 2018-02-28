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


def project_import_dir(uploads_folder, pnum):
    """
    Create a project specific path based on config and a project number.

    Paramaters
    ----------
    uploads_folder: list
    pnum: str

    Returns
    -------
    path

    """
    try:
        folder = uploads_folder[pnum]
    except KeyError as e:
        folder = uploads_folder['default'].replace('pXX', pnum)
    return os.path.normpath(folder)
