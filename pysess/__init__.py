# -*- coding: utf-8 -*-
import os
import logging
from pysess.util import get_or_create_secret_keys


__version__ = '0.0.1dev'


log = logging.getLogger(__name__)


class sessionmaker(object):

    backend = None

    def __init__(self, **settings):
        """
        Create a session factory that, upon execution, returns a new session
        object.
        """
        self.configure(**settings)

    def __call__(self, cookie=None, **settings):
        if not self.session_class:
            raise ValueError("No backend was configured")
        if settings:
            all_settings = self.settings.copy()
            all_settings.update(settings)
        else:
            all_settings = self.settings
        log.debug("Creating new cookie with value %s" % cookie)
        return self.session_class(cookie, **all_settings)

    def configure(self, **settings):
        from pysess.session import get_session_class
        backend = settings.get('backend')
        self.session_class = get_session_class(backend)
        if ('encryption_key' not in settings and
            'signature_key' not in settings):
            secret_file = settings.get(
                'secret_file',
                os.path.join(os.path.dirname(__file__), 'secret')
            )
            encryption_key, signature_key = get_or_create_secret_keys(secret_file)
            settings['encryption_key'] = encryption_key
            settings['signature_key'] = signature_key
        self.settings = settings


def sessionmaker_from_config(config, key):
    """
    Return a :func:`sessionmaker` from a configuration dictonary ``config``
    where it looks for values beginnign with ``key``.
    """
    pass
