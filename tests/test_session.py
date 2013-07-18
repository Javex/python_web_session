# -*- coding: utf-8 -*-
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
    assert sess.name == 'session'
    assert sess.path == '/'
    assert sess.max_age is None
    assert not sess.secure
    assert not sess.httponly
    assert isinstance(sess._cookie, SignedCookie)
    assert sess.is_new


def test_session_custom_params(sessionmaker):
    conf = {'session_id_length': 20, 'name':'testsession', 'path':'/foo',
            'secure':True, 'httponly':True, 'serializer':pickle, 'max_age':30}
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
    conf = {'encryption_key': '1' * 32, 'hashalg': hashlib.md5}
    sessionmaker.settings.update(conf)
    session = sessionmaker()
    session["key"] = "value"
    cookie = str(session.save())

    session2 = sessionmaker(cookie)
    assert session2["key"] == "value"


def test_session_new(sessionmaker):
    session = sessionmaker()
    log.debug("Current cache: %s" % cache)
    assert session.is_new
    assert not session.modified
    assert not session.accessed
    assert session._data_cache is None
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


"""
def test_session_expired(sessionmaker):
    sessionmaker.settings["max-age"] = 1
    session = sessionmaker()
    session["key"] = "value"
    cookie = str(session.save())
    assert session.is_new
    assert not sessionmaker(cookie).is_new
    time.sleep(2)
    session = sessionmaker(cookie)
    session.load()
    assert session.is_new"""

