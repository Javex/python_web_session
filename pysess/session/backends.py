# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess.conf import HASHALG
from pysess.crypto import encryption_available
from pysess.exc import CryptoError
from pysess.session.cookies import SignedCookie, EncryptedCookie
from pysess.util import max_age_to_expires, filter_internal
import Cookie
import binascii
import functools
import json
import logging
import os
import time


"""
Module that contains all available session types, currently the dogpile.cache
and cookie type.
"""


log = logging.getLogger(__name__)


class BaseSession(object):
    """
    Create a new session or load an existing from the backend. The general
    options available to all backends are described here, options specific to
    the backend can be found in its documentation.

    Cookie parameters:

    :param str cookie: A string specifying the cookie (or a set of cookies)
                       which also contain the session cookie.

    :param session_id_length: Length of the session ID in bytes, Default: 32,
                              which equals 256 bits. Note, however, that the
                              acutal string will be twice as long, as it is
                              encoded as a hexadecimal.
    :type session_id_length: int

    :param name: Name for the cookie. Default: ``b'session'``, has to be a
                **byte** string.
    :type name: str

    :param path: Path for the cookie. Default: ``'/'``
    :type path: str

    :param domain: Domain for the cookie, required.
    :type domain: str

    :param max_age: A number of seconds until the cookie expires,
                    Default: Session cookie (expires after browser closes). In
                    this case, the backend will not delete or expire the cookie
                    in any way but the browser will delete it once it is
                    closed.
    :type max_age: str

    :param secure: Whether to restrict the cookie to HTTPS, Default: ``False``
    :type secure: bool

    :param httponly: Whether to set the httponly flag, Default: ``False``
    :type httponly: bool


    General configuration:

    :param refresh_on_access: Whether to refresh the session lifetime when it
                              is accessed or instead leave it at a static
                              expiration from the moment it was created.
                              Default: ``True``, meaning it will refresh the
                              session each time it is accessed.
    :type refresh_on_access: bool

    :param serializer: Which method to use to serialize data, Default: json.
                       Pass in a module or object that has methods ``loads``
                       and ``dumps``, for example pickle, to change this. For
                       a more thorough explanation see ...

    .. todo::
        Create an explanation for why json is a good idea and how and when to
        replace it and reference it here. Also make a note on Unicode there to
        explain that the values returned always have to be unicode, not str.

    Security options:

    :param encryption_key: A key used for encryption, optional but recommended,
                           especially with a backend that stores data **in**
                           the cookie. Has to be a **byte** string.

    :param signature_key: A key used to create a signature. Has to be a
                          **byte** string.

    :param hashalg: An optional hashing algorithm to use for the creation of an
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

    def __init__(self, cookie=None, **settings):
        if (cookie is not None and not isinstance(cookie, str)):
            raise ValueError("Cookie must be str or unicode, cast it "
                             "explicitly")
        self.modified = False
        self.accessed = False
        self.is_new = False
        self.has_encryption = False
        self._saved = False
        self._data_cache = None
        log.debug("Recieved cookie '%s'" % cookie)
        self._id_length = settings.get('session_id_length', 32)
        self.enc_key = settings.get('encryption_key', None)
        self.sig_key = settings['signature_key']
        self.hashalg = settings.get('hashalg', HASHALG)
        self.refresh_on_access = settings.get('refresh_on_access', True)
        self.serializer = settings.get('serializer', json)

        # Cookie settings
        self.name = settings.get('name', b'session')
        self.path = settings.get('path', '/')
        self.domain = settings['domain']
        self.max_age = settings.get('max_age', None)
        self.secure = settings.get('secure', False)
        self.httponly = settings.get('httponly', False)

        # Make sure if we have an encryption key that we are also able to
        # encrypt.
        if self.enc_key:
            enc_avail = encryption_available()
            if not enc_avail:
                raise CryptoError("Encryption key was given but encryption is "
                                  "not available.")
            self.has_encryption = enc_avail

        # Choose the correct class for creating a cookie and prepare it
        if self.has_encryption:
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

        if cookie:
            # Load the cookie data and on error create a new cookie
            try:
                self._cookie = CookieClass(input=cookie)
                sess_id = self._get_session_id_from_cookie()
                log.debug('Loaded old cookie with session ID %s from input %s'
                          % (sess_id,
                             cookie))
            except Cookie.CookieError as e:
                log.debug('Creating new cookie because of the following '
                          'exception: %s' % e)
                self._cookie = CookieClass(input=None)
        else:
            log.debug("Starting new session because of empty cookie.")
            self._cookie = CookieClass(input=None)

        if self._get_session_id_from_cookie() is None:
            self.is_new = True

    # Internal functions, usually not overwritten

    @property
    def _data(self):
        self.accessed = True
        if self._data_cache is None:
            if self.session_id is None or self.is_new:
                log.debug("Creating a new cache due to session id being %s "
                          "and new status being %s"
                          % (self.session_id, self.is_new))
                self._new_data_cache(self.session_id)
            else:
                self.load()
        return self._data_cache

    def _new_data_cache(self, existing_id=None):
        log.debug("Creating new data cache")
        self.session_id = existing_id or self._create_id()
        data = self._get_new_data()
        self.is_new = True
        self._data_cache = data

    def _get_new_data(self):
        data = {}
        now = time.time()
        data['_access'] = now
        data['_creation'] = now
        return data

    def _create_id(self):
        """
        Create a new session ID (but don't save it, only return it)
        """
        while True:
            id_ = binascii.hexlify(os.urandom(self._id_length)).decode("ascii")
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
        val = self._get_session_id_from_cookie()
        if val is not None:
            log.debug("Current session id is '%s'" % val)
            return val
        else:
            # There is none yet, create a new one then try again
            log.debug("Creating a new session because none exists yet")
            self._new_data_cache()
            return self.session_id

    @session_id.setter
    def session_id(self, value):
        log.debug("Setting new session id to %s" % value)
        self._set_session_id_to_cookie(value)

    def _get_session_id_from_cookie(self):
        session = self._cookie.get(self.name)
        return session.value if session else None

    def _set_session_id_to_cookie(self, value):
        self._cookie[self.name] = value

    @property
    def created(self):
        return self["_creation"]

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

    @filter_internal
    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data) - 2  # Remove count of own items

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

    @filter_internal
    def items(self):
        return self._data.items()

    @filter_internal
    def iteritems(self):
        return self._data.iteritems()

    @filter_internal
    def iterkeys(self):
        return self._data.iterkeys()

    def itervalues(self):
        for k, v in self._data.iteritems():
            if not k.startswith('_'):
                yield v

    @filter_internal
    def keys(self):
        return self._data.keys()

    def popitem(self):
        already_modified = self.modified
        self.modified = True
        k, v = self._data.popitem()
        if k.startswith("_"):
            self._data[k] = v
            if not already_modified:
                self.modified = False
            {}.popitem()  # This raises the excpetion but it's kinda hacky...
        else:
            return (k, v)

    def values(self):
        return [v for k, v in self._data.items() if not k.startswith("_")]

    # TODO: Should we implement the view{items,keys,values} function and if
    # yes, how? On the same page could be how to port the app to Python 3.
    # See: http://stackoverflow.com/questions/17749866/subclassing-datatypes-that-have-views-in-python2-7-and-python3

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
        Delete either the given session or the current one with out retaining
        the data.

        :param unicode session_id: If specified does not invalidate the current
                                   session but instead the one with the
                                   specified ID.

        """
        if session_id is None:
            session_id = self.session_id
        self._delete_data(session_id)
        self.clear()

    @property
    def cookie(self):
        """
        Return a cookie object (instance of a subclass of
        :class:`Cookie.BaseCookie`) like this:

        .. code-block:: pycon

            >>> print session.cookie
            <SignedCookie: session=u'ca6fd7...'>
            >>> print str(cookie)
            'Set-Cookie: session=Yjc0Y...YyIg==; Domain=example.com; Path=/'

        The returned class can be used to access individual values and
        possibly change or verify some data. Afterwards cast it to a string
        and it will represent a line that can be added to the HTTP response
        header.

        .. note::

            Most likely you will want to use this in conjunction with
            :meth:`BaseSession.save` will already returns the exact same
            cookie.
        """
        if not self._saved:
            raise ValueError("Session has to be saved before retrieving "
                             "cookie.")
        if self.name not in self._cookie:
            self.session_id
        self._update_cookie()
        return self._cookie

    def load(self):
        """
        Load the session data and also make sure the data is not expired.

        :rtype: dict
        """
        # First load data
        data = self._load_data()
        log.debug("Loaded data %s" % data)

        # Check if the data is expired
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

        :rtype: ``SignedCookie`` or ``EncryptedCookie``
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
        Check whether a given session ID exists or not.

        :param unicode session_id: The session ID to check.
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
    A session based on `dogpile.cache`_.  It has one additional configuration
    parameter:

    :param region: A configured instance of
                   :func:`dogpile.cache.region.make_region`

    For all other parameters look at the documentation for
    :class:`BaseSession`.

    .. _dogpile.cache: https://dogpilecache.readthedocs.org/en/latest/

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

    def _data_key(self, session_id=None):
        if session_id is None:
            session_id = self.session_id
        k = "session_%s" % session_id
        return k

    def _save_data(self):
        self.region.set(self._data_key(), self._data)

    def _delete_data(self, session_id):
        self.region.delete(self._data_key(session_id))

    def _load_data(self):
        log.debug("Loading data with key %s" % self._data_key())
        data = self.region.get(self._data_key())
        log.debug("Recieved data %s" % data)
        return data or None

    def exists(self, session_id):
        # We can only retrieve not check so this is a little expensive
        NO_VALUE = self.dpcache.api.NO_VALUE
        return self.region.get(session_id) is not NO_VALUE


class CookieSession(BaseSession):
    def _save_data(self):
        self._cookie[self.name] = (self.session_id, self._data.copy())

    def _delete_data(self, session_id):
        if session_id and self.session_id != session_id:
            raise ValueError("Cannot delete foreign sessions.")
        self._cookie[self.name] = (self.session_id, self._get_new_data())

    def _load_data(self):
        return self._cookie[self.name].value[1]

    def exists(self, session_id):
        """
        This is not possible for cookies. Thus if you depend on it somehow,
        this might be the wrong backend.
        """
        pass

    @classmethod
    def cleanup(cls):
        # Not necessary for cookies
        pass

    def _get_session_id_from_cookie(self):
        session = self._cookie.get(self.name)
        return session.value[0] if session else None

    def _set_session_id_to_cookie(self, value):
        if self.name in self._cookie and self._cookie[self.name].value:
            olddata = self._cookie[self.name].value[1]
        else:
            olddata = self._get_new_data()
        self._cookie[self.name] = (value, olddata)
