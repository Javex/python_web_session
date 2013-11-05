# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import time
from email.utils import formatdate
from functools import wraps
import os
import stat
import json
import base64
import logging


log = logging.getLogger(__name__)


def create_secret_file(path, encrypt_key_size=32, signature_key_size=32,
                       overwrite=False):
    """
    Creates a file to keep the necessary secrets for cookie authentication and
    signature. It is recommended to not use this function directly and instead
    use :func:`get_or_create_secret_keys`.

    Args:
        ``encrypt_key_size``, ``signature_key_size``: The length of the
        corresponding keys in bytes, i.e. the default of ``32`` bytes
        translates into ``256`` bit keys (which is the recommended, secure
        size).

        ``overwrite``: If the file already exists, this function will raise
        a :exc:`ValueError``. If you set this from its default of ``False`` to
        ``True`` the function will ignore any existing file and just create a
        new one.
    """
    # Default to not overwriting old secrets
    if not overwrite and os.path.isfile(path):
        raise ValueError("Secret file already exists, not overwriting!")

    # Generate new secrets and make them storage friendly
    enc_key = os.urandom(encrypt_key_size)
    sig_key = os.urandom(signature_key_size)
    keys = {'encryption_key': enc_key, 'signature_key': sig_key}
    # ISO-8859-1 will preserve all bytes and not fail like UTF-8
    data = json.dumps(keys, encoding='iso-8859-1')

    # Make sure the file exists emptily to set access rights first
    with open(path, "w"):
        os.utime(path, None)

    # Set the access rights before actually writing the keys to it
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    assert permissions_okay(path, [stat.S_IRUSR, stat.S_IWUSR])

    # Finally write the keys generated above
    with open(path, "a") as secfile:
        secfile.write(data)


def get_secret_keys(path, ignore_permissions=False):
    """
    Return the secret keys for encryption and authentication as a dictonary
    with the keys being ``encryption_key`` and ``signature_key``. Can only be
    used after it has been created. Use :func:`get_or_create_secret_keys` for
    transparent usage. The keys will be returned as **byte** strings as
    required by the used cryptographic functions.

    Note, that this function also performs a check on the permissions of path
    so that they are only readable and writable by the owner of the
    application.

    :param unicode path: The path to the secret file.

    :param bool ignore_permissions: If it should be ignored (i.e. not checked)
                                    if the permissions on the secret file are
                                    insecure. Default: ``False``, meaning it
                                    will be checked.
    """
    if (not ignore_permissions and
            not permissions_okay(path, [stat.S_IRUSR, stat.S_IWUSR])):
        raise ValueError("Permissions on file are insecure. Keys could be "
                         "compromised. Please check the documentation before "
                         "before proceeding!")
    with open(path) as secfile:
        data = json.loads(secfile.read(), encoding='iso-8859-1')
    data["signature_key"] = data["signature_key"].encode('iso-8859-1')
    data["encryption_key"] = data["encryption_key"].encode('iso-8859-1')
    return data


def get_or_create_secret_keys(path):
    """
    Return the secret keys, creating them if they are not already available.
    """
    if not os.path.isfile(path):
        log.info("No secret keys exist yet, creating a new file")
        create_secret_file(path)
    return get_secret_keys(path)


def permissions_okay(path, permlist):
    """
    Check whether the file under ``path`` has exactly only the permissions
    specified under ``permlist``. Returns ``True`` or ``False`` depending on
    the result.
    """
    if not os.path.exists(path) and os.path.isfile(path):
        raise IOError("File does not exist (or is a directory).")
    path_permissions = os.stat(path).st_mode & 0o777
    expected_permissions = 0
    for perm in permlist:
        expected_permissions |= perm
    if expected_permissions == path_permissions:
        return True
    else:
        return False


def compare_constant_time(val1, val2):  # pragma: no cover
    """
    Compare two values with constant times, thus defeating timing attacks.
    """
    if len(val1) != len(val2):
        return False

    invalid_count = 0
    for a, b, in zip(val1, val2):
        invalid_count += a != b
    if invalid_count:
        return False
    else:
        return True


def max_age_to_expires(max_age, fromtime=None):
    """
    Converts a ``max-age`` value to an ``expires`` value. Largely taken from
    :func:`django.utils.http.cookie_date`. Pass as the ``fromtime`` parameter
    a timestamp to choose a different starting point than ``time.time()``.
    """
    if fromtime is None:
        fromtime = time.time()
    expires_time = fromtime + max_age
    rfcdate = formatdate(expires_time, usegmt=True)
    return '{0}-{1}-{2}'.format(rfcdate[:7], rfcdate[8:11], rfcdate[12:])


def filter_internal(func):
    """
    Wrap an iterator or list function to filter parameters that start with '_'.
    """
    @wraps(func)
    def _filter(*args, **kwargs):
        ret = func(*args, **kwargs)
        if isinstance(ret, list):
            ret_list = []
            for item in ret:
                if isinstance(item, tuple) and len(item) == 2:
                    k, __ = item
                    if not k.startswith("_"):
                        ret_list.append(item)
                else:
                    if not item.startswith("_"):
                        ret_list.append(item)
            return ret_list
        else:
            return _generator_filter(ret)
    return _filter


def _generator_filter(gen):
    for item in gen:
        if isinstance(item, tuple) and len(item) == 2:
            k, v = item
            if not k.startswith("_"):
                yield (k, v)
        else:
            if not item.startswith("_"):
                yield item


class manage_modified(object):

    def __init__(self, set_modified=lambda *args, **kwargs: True):
        self.set_modified = set_modified

    def __call__(self, func):
        @wraps(func)
        def _handle(target_self, *args, **kwargs):
            old_val = target_self.modified
            target_self.modified = self.set_modified(target_self, *args,
                                                     **kwargs)
            try:
                return func(target_self, *args, **kwargs)
            except:
                target_self.modified = old_val
                raise
        return _handle
