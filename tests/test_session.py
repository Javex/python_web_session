# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess.session.backends import BaseSession
import pytest
from pysess.conf import HASHALG
import json
from pysess.session.cookies import SignedCookie
from tests import sessionmaker, cache, existing_session
import logging
import time
import pickle
import base64
import hashlib
from tests.test_crypto import test_enc_key


log = logging.getLogger(__name__)


"""
Tests to create:

- encryption
- different hashalg
- secret file instead of static keys
- Just work with the session without any noticing
- Invalid signatures & encryption lead to fails & logging

"""


def test_session_default_params():
    with pytest.raises(KeyError):
        sess = BaseSession()
    with pytest.raises(KeyError):
        sess = BaseSession(signature_key='')
    sess = BaseSession(signature_key='', domain='example.com')

    assert sess._id_length == 32
    assert sess.enc_key is None
    assert not sess.has_encryption
    assert sess.hashalg is HASHALG
    assert sess.refresh_on_access
    assert sess.serializer is json
    assert isinstance(sess.name, str)
    assert sess.name == b'session'
    assert sess.path == '/'
    assert sess.max_age is None
    assert not sess.secure
    assert not sess.httponly
    assert isinstance(sess._cookie, SignedCookie)
    assert sess.is_new


def test_session_custom_params(sessionmaker):
    conf = {'session_id_length': 20, 'name': b'testsession', 'path': '/foo',
            'secure': True, 'httponly': True, 'serializer': pickle,
            'max_age': 30}
    sessionmaker.settings.update(conf)
    session = sessionmaker()

    assert len(session.session_id) == 40
    assert session.name == 'testsession'
    assert session.path == '/foo'
    assert session.secure
    assert session.httponly
    assert session.max_age == 30

    cookie = session.save()
    assert cookie['testsession']['path'] == '/foo'
    assert cookie['testsession']['max-age'] == 30
    assert cookie['testsession']['secure']
    assert cookie['testsession']['httponly']

    # Make sure that we can decode it using pickle (and json cannot)
    coded = cookie['testsession'].coded_value
    decoded = base64.b64decode(coded)
    pickle.loads(decoded[64:])
    with pytest.raises(ValueError):
        json.loads(decoded[64:])


def test_session_custom_crypto(sessionmaker):
    conf = {'encryption_key': test_enc_key, 'hashalg': hashlib.md5}
    sessionmaker.settings.update(conf)
    session = sessionmaker()
    session["kéy"] = "valué"
    cookie = str(session.save())

    session2 = sessionmaker(cookie)
    assert session2["kéy"] == "valué"


def test_session_new(sessionmaker):
    session = sessionmaker()
    log.debug("Current cache: %s" % cache)
    assert session.is_new
    assert not session.modified
    assert not session.accessed
    assert session._data_cache is None
    assert session.created
    log.debug("Current cache: %s" % cache)

    session["testkey"] = "testval"
    assert session._data_cache
    assert session["testkey"] == "testval"
    log.debug("Current cache: %s" % cache)

    assert session.session_id
    cookie = session.save()
    log.debug("Current cache: %s" % cache)

    log.debug("Creating new session from cookie %s" % cookie)
    log.debug("Current cache: %s" % cache)
    new_session = sessionmaker(str(cookie))
    log.debug("Current cache: %s" % cache)
    log.debug("Testing value")
    assert new_session["testkey"] == "testval"


def test_session_existing(sessionmaker, existing_session):
    session = existing_session
    assert not session.is_new
    assert not session.accessed
    assert not session.modified


def test_session_dict_interface(sessionmaker):
    old_session = sessionmaker()
    old_session["kéy"] = "valué"
    cookie = old_session.save()

    session = sessionmaker(str(cookie))
    assert session["kéy"] == "valué"
    assert "kéy" in session
    assert not session.modified
    del session["kéy"]
    assert session.modified
    session.modified = False
    assert "kéy" not in session
    assert not session.modified
    session["kéy2"] = "valué2"
    assert session.modified
    session.modified = False
    assert len(session) == 1
    for key in session:
        assert key == "kéy2"
    assert not session.modified
    assert session.pop("kéy2") == "valué2"
    assert session.modified
    session.modified = False
    assert "kéy2" not in session
    assert "kéy3" not in session
    assert not session.modified
    assert session.setdefault("kéy3", "valué3")
    assert session.modified
    session.modified = False
    assert session["kéy3"] == "valué3"
    assert not session.modified
    session.update({'kéy4': 'valué4'})
    assert session.modified
    session.modified = False
    assert session["kéy4"] == "valué4"
    session.clear()
    assert len(session) == 0
    session["kéy5"] = "valué5"
    session.modified = False
    assert session.get("kéy5") == "valué5"
    assert session.get("kéy4") is None
    assert session.get("kéy4", 0) == 0
    assert session.has_key("kéy5")
    assert session.items() == [("kéy5", "valué5")]
    assert not isinstance(session.iteritems(), list)
    for k, v in session.iteritems():
        assert k == "kéy5"
        assert v == "valué5"
    assert not isinstance(session.iterkeys(), list)
    for k in session.iterkeys():
        assert k == "kéy5"
    assert not isinstance(session.itervalues(), list)
    for v in session.itervalues():
        assert v == "valué5"
    assert session.keys() == ["kéy5"]
    assert session.values() == ["valué5"]
    assert not session.modified
    assert session.popitem() == ("kéy5", "valué5")
    assert session.modified
    with pytest.raises(KeyError):
        session.popitem()
    assert session.modified
    session.modified = False
    with pytest.raises(KeyError):
        session.popitem()
    assert not session.modified


def test_session_clear(sessionmaker):
    session = sessionmaker()
    session["kéy"] = "valué"
    cookie = session.save()

    session2 = sessionmaker(cookie)
    assert not session2.accessed
    assert session["kéy"] == "valué"
    assert not session2.modified
    session2.accessed = False
    assert not session2.accessed
    old_creation = session2["_creation"]
    old_access = session2["_access"]
    session2.clear()
    assert session2["_creation"] > old_creation
    assert session2["_access"] > old_access
    assert len(session2) == 0


def test_session_create_id(sessionmaker):
    session = sessionmaker()
    assert isinstance(session.session_id, unicode)


def test_session(sessionmaker):
    session = sessionmaker()
    assert session.created
    session["kéy"] = "valué"
    old_creation = session.created
    cookie = session.save()

    session2 = sessionmaker(str(cookie))
    assert not session2.is_new
    log.debug("Data: %s" % session2._data)
    assert session2["kéy"] == "valué"
    assert session2.created == old_creation


def test_refresh(sessionmaker):
    session = sessionmaker()
    session["kéy"] = "valué"
    old_creation = session.created
    old_access = session['_access']
    old_data = session._data
    old_id = session.session_id
    session.refresh()
    assert session.created == old_creation
    assert session['_access'] == old_access
    assert session._data == old_data
    assert session.session_id != old_id
    assert not session.exists(old_id)


def test_cookie_exception_before_save(sessionmaker):
    session = sessionmaker()
    with pytest.raises(ValueError):
        session.cookie


def test_base_class_unimplemented():
    sess = BaseSession(signature_key='', domain='example.com')
    for fname in ['_save_data', '_load_data', '_delete_data', 'exists',
                  'cleanup']:
        func = getattr(sess, fname)
        with pytest.raises(NotImplementedError):
            if fname in ['exists', '_delete_data']:
                func(None)
            else:
                func()
