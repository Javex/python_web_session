# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import time
from email.utils import formatdate
from functools import wraps


def create_secret_file(path, encrypt_key_size=32, signature_key_size=32):
    """
    Creates a file to keep the necessary secrets for cookie authentication and
    signature.
    """
    pass


def get_secret_keys(path):
    """
    Return the secret keys for encryption and authentication as a tuple where
    those keys that are unavailable are ``None``.
    """
    return (None, None)


def get_or_create_secret_keys(path, *args, **kwargs):
    """
    Return the secret keys, creating them if they are not already available.
    """
    return (None, None)


def compare_constant_time(val1, val2):
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
    rfcdate = formatdate(expires_time)
    return '{0}-{1}-{2} GMT'.format(rfcdate[:7], rfcdate[8:11], rfcdate[12:25])


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
