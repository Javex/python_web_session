# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess.exc import SessionConfigurationError, CryptoError
from pysess.util import get_or_create_secret_keys
import logging
import os
from pysess.crypto import encryption_available
import warnings
from pysess.session import get_session_class


__version__ = '0.0.1dev'


log = logging.getLogger(__name__)


class sessionmaker(object):
    """
    Create a session factory which contains a configuration to be applied to
    each newly created session.
    """

    def __init__(self):
        self.backend = None
        self.session_class = None

    def __call__(self, cookie=None, **settings):
        """
        Create a new session by calling a :cls:`sessionmaker` instance.
        """
        if not hasattr(self, "settings"):
            raise SessionConfigurationError("Session not configured yet.")
        self._check_call_settings_sanity(settings)

        all_settings = self.settings.copy()
        # Add custom added params
        if settings:
            all_settings.update(settings)

        # If requesting a different backend, give it
        if 'backend' in settings:
            session_class = get_session_class(settings['backend'])
        else:
            if not hasattr(self, 'session_class'):
                raise SessionConfigurationError("No backend was configured")
            session_class = self.session_class

        # Delete the sessionmaker only settings
        for sessionmaker_only in ["enable_encryption", "secret_file",
                                  "backend"]:
            if sessionmaker_only in all_settings:
                del all_settings[sessionmaker_only]

        # Create a new instance of a session
        return session_class(cookie, **all_settings)

    def configure(self, **settings):
        """
        Configure sessions with default arguments. The settings passed in here
        will be used for all newly created sessions, unless superseded by the
        settings explicity passed to :meth:`sessionmaker.__call__`.

        The following configuration settings are available exclusively to the
        sessionmaker:

        :param backend: The name of the backend to be used. This setting is
                        mandatory, but can also be passed individually on
                        session creation.

        :param secret_file: If this is specified, a file is used to store keys
                            for both encryption and signing of the cookie.
                            This option conflicts with the ``signature_key``
                            and ``encryption_key`` options, so you can only use
                            one of them. Defaults to a file called `secret` in
                            the current working directory.

        :param enable_encryption: Only useful in conjunction with
                                  ``secret_file``, as it specifies to not only
                                  load a signature key but also an encryption
                                  key. This requires `PyCrypto`_. Defaults to
                                  no encryption.

        .. _PyCrypto: https://www.dlitz.net/software/pycrypto/
        """
        if hasattr(self, 'settings'):
            raise SessionConfigurationError("Session already configured.")
        self._check_settings_sanity(settings)
        self._init_keys(settings)
        assert 'signature_key' in settings
        self.settings = settings
        try:
            backend = self.settings['backend']
            self.session_class = get_session_class(backend)
        except ValueError:
            raise SessionConfigurationError("Backend %s not found." % backend)
        except KeyError:
            raise SessionConfigurationError("No backend given, please "
                                            "specifiy a 'backend' setting.")

        # Check if we can encrypt:
        # This is just a failsafe check to throw up at configuration already
        if 'encryption_key' in self.settings and not encryption_available():
            raise CryptoError("Encryption not available, install pycrypto.")

    def _check_call_settings_sanity(self, settings):
        """
        Check the sanity of settings for immediate configuration, i.e. inside
        the :meth:`sessionmaker.__call__` function. This differs from the
        usual sanity check as
        some settings like ``secret_file`` are not allowed any more (they must
        be specified in the configuration phase).
        """
        if 'secret_file' in settings:
            raise SessionConfigurationError(
                "A secret file is not allowed for this configuration, you "
                "must specify it in the configuration phase.")
        if 'enable_encryption' in settings:
            raise SessionConfigurationError(
                "The enable_encryption option only makes sense in the "
                "configuration phase.")

    @classmethod
    def _check_settings_sanity(cls, settings):
        # Check for good configuration, raise Exception if problem occurs.
        if 'signature_key' not in settings and 'encryption_key' in settings:
            raise SessionConfigurationError(
                "You have an encryption key but no signature key. This is not "
                "possible, either specify both or remove the encryption key.")
        if 'secret_file' in settings and 'signature_key' in settings:
            raise SessionConfigurationError("Either specify a secret file OR "
                                            "a signature key, not both.")
        if ('signature_key' in settings and
                settings.get('enable_encryption') and
                'encryption_key' not in settings):
            raise SessionConfigurationError(
                "If you enable encryption but already provide a signature key "
                "and no encryption key, the secret file will not load. Thus, "
                "either remove the signature key and handle it through a "
                "secret file, or specify an encryption key explicitly.")

        # Configuration is sane, but warn for these weird configuration
        # combinations (they will work, but one might not get expected results)
        if 'encryption_key' in settings and 'enable_encryption' in settings:
            warnings.warn(
                "Configuring both an encryption key and the enable_encryption "
                "option does not make sense, because the latter is only used "
                "with a secret file (which is not used if you specify the "
                "keys yourself).")

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
            keys = get_or_create_secret_keys(secret_file)
            if settings.get('enable_encryption'):
                settings['encryption_key'] = keys['encryption_key']
            settings['signature_key'] = keys['signature_key']


def sessionmaker_from_config(config, key):
    """
    Return a :func:`sessionmaker` from a configuration dictonary ``config``
    where it looks for values beginnign with ``key``.
    """
    raise NotImplementedError
