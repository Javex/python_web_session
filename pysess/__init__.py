# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess.exc import SessionConfigurationError, CryptoError
from pysess.util import get_or_create_secret_keys
import logging
import os
from pysess.crypto import encryption_available


__version__ = '0.0.1dev'


log = logging.getLogger(__name__)


class sessionmaker(object):

    def __init__(self):
        self.backend = None
        self.session_class = None

    def __call__(self, cookie=None, **settings):
        if not hasattr(self, "settings"):
            raise SessionConfigurationError("Session not configured yet.")
        all_settings = self.settings.copy()
        # Add custom added params
        if settings:
            all_settings.update(settings)

        # Make sure there is a session class registered to make sessions
        if self.session_class is None:
            from pysess.session import get_session_class
            backend = all_settings.get('backend')
            if backend is None:
                raise SessionConfigurationError("No backend was configured")
            self.session_class = get_session_class(backend)

        # Delete the sessionmaker only settings
        for sessionmaker_only in ["enable_encryption", "secret_file",
                                  "backend"]:
            if sessionmaker_only in all_settings:
                del all_settings[sessionmaker_only]

        # Create a new instance of a session
        return self.session_class(cookie, **all_settings)

    def configure(self, **settings):
        if hasattr(self, "settings"):
            raise SessionConfigurationError("Session already configured.")
        self._init_keys(settings)
        assert "signature_key" in settings
        self.settings = settings

        # Check if we can encrypt:
        if "encryption_key" in self.settings and not encryption_available():
            raise CryptoError("Encryption not available, install pycrypto.")

    def _init_keys(self, settings):
        """
        If there are no keys specified, load the appropriate keys into the
        configuration.
        """
        if settings.get('signature_key') is None:
            secret_file = settings.get(
                'secret_file',
                os.path.join(os.getcwd(), 'secret')
            )
            encryption_key, signature_key = \
                get_or_create_secret_keys(secret_file)
            if settings.get('enable_encryption'):
                settings['encryption_key'] = encryption_key
            settings['signature_key'] = signature_key


def sessionmaker_from_config(config, key):
    """
    Return a :func:`sessionmaker` from a configuration dictonary ``config``
    where it looks for values beginnign with ``key``.
    """
    pass
