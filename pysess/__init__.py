# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import os
import logging
from pysess.util import get_or_create_secret_keys


__version__ = '0.0.1dev'


log = logging.getLogger(__name__)


class sessionmaker(object):

    backend = None
    session_class = None

    def __init__(self, **settings):
        """
        Create a session factory that, upon execution, returns a new session
        object.
        """
        self.configure(**settings)

    def __call__(self, cookie=None, **settings):
        if settings:
            all_settings = self.settings.copy()
            all_settings.update(settings)
        else:
            all_settings = self.settings
        if self.session_class is None:
            from pysess.session import get_session_class
            backend = all_settings.get('backend')
            if backend is None:
                raise ValueError("No backend was configured")
            self.session_class = get_session_class(backend)
        log.debug("Creating new cookie with value %s" % cookie)
        return self.session_class(cookie, **all_settings)

    def configure(self, **settings):
        """if ('encryption_key' not in settings and
            'signature_key' not in settings):
            secret_file = settings.get(
                'secret_file',
                os.path.join(os.path.dirname(__file__), 'secret')
            )
            encryption_key, signature_key = get_or_create_secret_keys(secret_file)
            settings['encryption_key'] = encryption_key
            settings['signature_key'] = signature_key"""
        self.settings = settings


def sessionmaker_from_config(config, key):
    """
    Return a :func:`sessionmaker` from a configuration dictonary ``config``
    where it looks for values beginnign with ``key``.
    """
    pass
