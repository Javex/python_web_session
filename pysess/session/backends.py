# -*- coding: utf-8 -*-
from pysess.conf import HASHALG
from pysess.crypto import encryption_available
from pysess.session.cookies import SignedCookie, EncryptedCookie
from pysess.util import max_age_to_expires
import Cookie
import binascii
import functools
import json
import os
import time
import logging
from Cookie import Morsel


"""
Module that contains all available session types, currently the dogpile.cache
and cookie type.
"""


log = logging.getLogger(__name__)


class BaseSession(object):
    """
    Create a new session or load an existing for the backend. The general
    options available to all backends are described here, options specific to
    the backend can be found in its documentation.

    Cookie parameters:

    :param cookie: A string specifying the cookie (or a set of cookies) which
                   also contain the session cookie.
    :param session_id_length: Length of the session ID in bytes, Default: 32,
                              which equals 256 bits. Note, however, that the
                              acutal string will be twice as long, as it is
                              encoded as a hexadecimal.
    :param name: Name for the cookie. Default: 'session'
    :param path: Path for the cookie. Default: '/'
    :param domain: Domain for the cookie, required.
    :param max_age: A number of seconds until the cookie expires, Default: Never
    :param secure: Whether to restrict the cookie to HTTPS, Default: False
    :param httponly: Whether to set the httponly flag, Default: False


    General configuration:

    :param refresh_on_access: Whether to refresh the session lifetime when it
                              is accessed or instead leave it at a static
                              expiration from the moment it was created.
                              Default: True, meaning it will refresh the
                              session each time it is accessed.
    :param serializer: Which method to use to serialize data, Default: json.
                       Pass in a module or object that has methods ``loads``
                       and ``dumps``, for example pickle, to change this. For
                       a more thorough explanation see ...
    .. todo::
        Create an explanation for why json is a good idea and how and when to
        replace it and reference it here.

    Security options:

    :param encryption_key: A key used for encryption, optional but recommended,
                           especially with a backend that stores data **in**
                           the cookie.
    :param signature_key: A key used to create a signature
    :param hashalg: An optional hasing algorithm to use for the creation of an
                    HMAC (signature). Defaults to :class:`hashlib.sha256` and
                    can usally be left at its default.

    .. note::
        The three options above are all relevant for security. The least
        painful way is to use :class:`sessionmaker` which does all the work for
        you. However, it is strongly advised to read (...)

    .. todo::
        Create something that talks about the security of keys, hashes and
        whatnot and reference it here.
    """

    modified = False
    accessed = False
    is_new = False
    has_encryption = False
    _saved = False
    _data_cache = None

    def __init__(self, cookie=None, **settings):
        log.debug("Recieved cookie '%s'" % cookie)
        self._id_length = settings.get('session_id_length', 32)
        self.enc_key = settings.get('encryption_key', None)
        self.sig_key = settings['signature_key']
        self.hashalg = settings.get('hashalg', HASHALG)
        self.refresh_on_access = settings.get('refresh_on_access', True)
        self.serializer = settings.get('serializer', json)

        # Cookie settings
        self.name = settings.get('name', 'session')
        self.path = settings.get('path', '/')
        self.domain = settings['domain']
        self.max_age = settings.get('max_age', None)
        self.secure = settings.get('secure', False)
        self.httponly = settings.get('httponly', False)

        if self.enc_key:
            enc_avail = encryption_available()
            if not enc_avail:
                raise ValueError("Encryption key was given but encryption is "
                                 "not available.")
            self.has_encryption = enc_avail


        # Choose the correct class for creating a cookie and prepare it
        if self.enc_key and self.has_encryption:
            CookieClass = functools.partial(EncryptedCookie,
                                            self.serializer,
                                            self.sig_key,
                                            self.hashalg,
                                            self.enc_key)
        else:
            CookieClass = functools.partial(SignedCookie,
                                            self.serializer,
                                            self.sig_key,
                                            self.hashalg)

        # Load the cookie data and on error create a new cookie
        try:
            self._cookie = CookieClass(input=cookie)
            cookie_val = self._cookie.get(self.name)
            log.debug('Loaded old cookie with session ID %s from input %s'
                      % (cookie_val.value if cookie_val is not None else None, cookie))
        except Cookie.CookieError as e:
            log.debug('Creating new cookie because of the following '
                      'exception: %s' % e)
            self._cookie = CookieClass(input=None)

        if (self._cookie.get(self.name) is None
                or self._cookie[self.name].value is None):
            self.is_new = True

    # Internal functions, usually not overwritten

    @property
    def _data(self):
        self.accessed = True
        if self._data_cache is None:
            if self.session_id is None or self.is_new:
                log.debug("Creating a new cache due to session id being %s and "
                          "new status being %s" % (self.session_id, self.is_new))
                self._new_data_cache()
            else:
                self.load()
        return self._data_cache

    def _new_data_cache(self):
        self.session_id = self._create_id()
        data = {}
        now = time.time()
        data['_access'] = now
        data['_creation'] = now
        self.is_new = True
        self._data_cache = data

    def _get_or_create_id(self):
        """
        Either return the ID or create a new one (saves the potential new ID so
        a new session can be created with it).
        """
        if self.session_id is None:
            self.session_id = self._create_id()
        return self.session_id

    def _create_id(self):
        """
        Create a new session ID (but don't save it, only return it)
        """
        while True:
            id_ = binascii.hexlify(os.urandom(self._id_length))
            if not self.exists(id_):
                break
        log.debug("Created a new session id %s" % id_)
        return id_

    def _update_cookie(self):
        """
        Update all the cookie metadata.
        """
        cookie = self._cookie[self.name]
        cookie["path"] = self.path
        cookie["domain"] = self.domain
        if self.max_age:
            cookie["max-age"] = self.max_age
            # Only set expires if we have data to read "_access" from
            if self.accessed or self.is_new:
                fromtime = self._data["_access"]
                cookie["expires"] = max_age_to_expires(self.max_age, fromtime)
        if self.secure:
            cookie["secure"] = self.secure
        if self.httponly:
            cookie["httponly"] = self.httponly

    @property
    def session_id(self):
        try:
            val = self._cookie[self.name].value
            log.debug("Current session id is '%s'" % val)
            return val
        except KeyError:
            # There is none yet, create a new one then try again
            self.session_id = self._create_id()
            return self.session_id

    @session_id.setter
    def session_id(self, value):
        log.debug("Setting new session id to %s" % value)
        self._cookie[self.name] = value

    # Dict interface

    def __contains__(self, key):
        return key in self._data

    def __delitem__(self, key):
        self.modified = True
        del self._data[key]

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self.modified = True
        self._data[key] = value

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def pop(self, key, *args):
        self.modified = self.modified or key in self
        return self._data.pop(key, *args)

    def setdefault(self, key, value):
        if key not in self:
            self.modified = True
        return self._data.setdefault(key, value)

    def update(self, *args, **kwargs):
        self.modified = True
        return self._data.update(*args, **kwargs)

    def clear(self):
        self.modified = True
        self.accessed = True
        self._new_data_cache()

    def get(self, key, default=None):
        return self._data.get(key, default)

    def has_key(self, key):
        return self._data.has_key(key)

    def items(self):
        return self._data.items()

    def iteritems(self):
        return self._data.iteritems()

    def iterkeys(self):
        return self._data.iterkeys()

    def itervalues(self):
        return self._data.itervalues()

    def keys(self):
        return self._data.keys()

    def popitem(self):
        return self._data.popitem()

    def values(self):
        return self._data.values()

    def viewitems(self):
        return self._data.viewitems()

    def viewkeys(self):
        return self._data.viewkeys()

    def viewvalues(self):
        return self._data.viewvalues()

    # Utility functions that are usually not overwritten

    def refresh(self):
        """
        Create a new session identifier but keep the old data.
        """
        data = self._data
        key = self.session_id
        self.invalidate(key)
        self.update(data)

    def invalidate(self, session_id=None):
        """
        Delete current session and create a new session without retaining the
        data.
        """
        if session_id is None:
            session_id = self.session_id
        self._delete_data(session_id)
        self.clear()

    @property
    def cookie(self):
        """
        Return a cookie object (instance of a subclass of
        :class:`Cookie.BaseCookie` to be converted to a string and inserted
        directly into an HTTP response header, for example:

        .. code-block: pycon

            >>> print session.cookie

        .. todo::
            Make a sensible output of the above codeblock

        Of course, the actual implementation highly depends on the framework
        used.
        """
        if not self._saved:
            raise ValueError("Session has to be saved before retrieving "
                             "cookie.")
        self._update_cookie()
        return self._cookie


    def load(self):
        """
        Load the session data and also make sure the data is not expired.
        """
        # First load data
        data = self._load_data()
        log.debug("Loaded data %s" % data)

        expired = False
        if data and self.max_age:
            max_age = self.max_age

            if self.refresh_on_access:
                reference_time = data["_access"]
            else:
                reference_time = data["_creation"]

            now = time.time()
            delta = now - reference_time
            log.debug("Loaded data with a delta of %s and a max_age of %s"
                      % (delta, max_age))
            if delta > max_age:
                # Session has expired
                expired = True

        # Is there a reason to start over?
        if expired or data is None:
            self.invalidate()
        else:
            self._data_cache = data
        # Careful, at this point _data_cache MUST be set or we enter a loop!
        assert self._data_cache is not None
        return self._data

    def save(self):
        """
        Save the session data and return a cookie to be saved on the clients
        side. You **must** save this cookie or else you cannot find the
        session once the client returns.

        This cookie can later also be accessed under the ``cookie`` parameter
        of this session, however may not be accessed beforehand!
        """
        if self.accessed:
            self._data["_access"] = time.time()
            self._save_data()
        self._saved = True
        return self.cookie

    # Interface functions to be implemented by subclasses

    def _save_data(self):
        """
        Save the session to the backend. As with :meth:`_load_data` this is
        the core save operation with wrapping actions around it.
        """
        raise NotImplementedError

    def _delete_data(self, session_id):
        """
        Remove the specified session from the backend.
        """
        raise NotImplementedError

    def _load_data(self):
        """
        Load session data from the backend. The reason for this being an
        internal function is so that additional wrapping tasks can be
        performed such as expiry checking. Thus, here only the raw loading
        of data from the backend is performed without any checking of times.
        """
        raise NotImplementedError

    def exists(self, session_id):
        """
        Check whether a given ``session_id`` exists or not.
        """
        raise NotImplementedError

    @classmethod
    def cleanup(cls):
        """
        Remove all expired sessions from the backend. Periodic calls of this
        should be made to ensure no old sessions linger in the backend.

        Depending on the nature of the backend, this might not be necessary,
        then just make this method a no-op. However, if it is not possible
        don't override this method at all.
        """
        raise NotImplementedError


class DogpileSession(BaseSession):
    """
    A session based on :mod:`dogpile.cache`. The only additional configuration
    parameter is :param region: which should be a configured instance of
    :meth:`dogpile.cache.make_region`. For all other parameters look at the
    documentation for :class:`BaseSession`.

    .. note::
        This type of session currently does not support the
        :meth:`BaseSession.cleanup` function as dogpile.cache itself lacks
        support for such a mechanism. Thus, depending on your backend, this
        could lead to very much old data accumulating.
    """

    def __init__(self, *args, **settings):
        self._imports()
        log.debug("Passing through parameters '%s' and '%s'"
                  % (args, settings))
        self.region = settings['region']
        BaseSession.__init__(self, *args, **settings)

    def _imports(self):
        from dogpile import cache
        self.dpcache = cache

    @property
    def _data_key(self):
        k = "session_%s" % self.session_id
        log.debug("Created key %s from session id %s" % (k, self.session_id))
        return k

    def _save_data(self):
        self.region.set(self._data_key, self._data)

    def _delete_data(self, session_id):
        self.region.delete(self._data_key)

    def _load_data(self):
        log.debug("Loading data with key %s" % self._data_key)
        data = self.region.get(self._data_key)
        log.debug("Recieved data %s" % data)
        return data or None

    def exists(self, session_id):
        # We can only retrieve not check so this is a little expensive
        NO_VALUE = self.dpcache.api.NO_VALUE
        return self.region.get(session_id) is not NO_VALUE


class CookieSession(BaseSession):
    pass
