# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from logging import WARN, INFO, DEBUG
from pysess import crypto
from pysess.conf import HASHALG
from pysess.crypto import authenticate_data, decrypt_authenticated
from pysess.exc import CryptoError
from pysess.session.backends import BaseSession, log as backend_log
from pysess.session.cookies import SignedCookie, log as cookie_log
from tests import LogCollector
from tests.test_crypto import test_enc_key, test_sig_key
import base64
import hashlib
import json
import logging
import pickle
import pytest
import time


log = logging.getLogger(__name__)


"""
Tests to create:

- Implement and test some kind of concurrency mechanism: We need to have a
  strategy for when a session is accessed from multiple locations (locking?)
  see https://github.com/Javex/python_web_session/wiki/Race-Conditions for
  details.
- Integration tests (webtest)
- Maybe even selenium?

"""


@pytest.fixture(params=[('0' * 64 +
                         '"a5eb44559a9ecf64ca7c5cf04df006b'
                         'd1ade073aa20c14243112f459f71d5e4b"')])
def invalid_sig_cookie(request):
    cookie = (b"'Set-Cookie: session=%s; Domain=example.com; Path=/'"
              % base64.b64encode(request.param))
    return cookie


@pytest.fixture(params=[('0' * 64 +
                         '"a5eb44559a9ecf64ca7c5cf04df006b'
                         'd1ade073aa20c14243112f459f71d5e4b"')])
def invalid_sig_on_enc_cookie(request, sessionmaker):
    sessionmaker.settings['encryption_key'] = test_enc_key
    cookie = (b"'Set-Cookie: session=%s; Domain=example.com; Path=/'"
              % base64.b64encode(request.param))
    return cookie


@pytest.fixture(params=[(b'a87cb447758273654ff42bed03a3c3e4d512d287684ed383eea'
                         b'793c63100bf963j\x14\x14\xdf!\xd2!\x8e_\xcaR\x8e|'
                         b'\xc2\x10\x11\xdduA\xe7\xb8\xcb"\x00R]\xe0V"A\x98o'
                         b'\xb4n\xfa\xcd\xc8U!\x92\x95\xb4\xc2\xf4k\x153\xf1'
                         b'\x98f\xa3\xc6SB\xbe/\xf0~[\xd0\xe4\xaes%!')])
def invalid_enc_cookie(request, sessionmaker):
    sessionmaker.settings['encryption_key'] = test_enc_key
    cookie = (b"'Set-Cookie: session=%s; Domain=example.com; Path=/'"
              % base64.b64encode(request.param))
    return cookie


@pytest.fixture(params=[(b'5507cf4f0622580ae880af95263cd8c51abed2c49125625b9e2'
                         b'4cae178faf3963j\x14\x14\xdf\xfb\xd2\xe9\x8e_\xcaR'
                         b'\x8e|\xc2\x10\x11\xdduA\xe7\xb8\xcb"\x00R]\xe0V"A'
                         b'\x98o\xb4n\xfa\xcd\xc8U!\x92\x95\xb4\xc2\xf4k\x153'
                         b'\xf1\x98f\xa3\xc6SB\xbe/\xf0~[\xd0\xe4\xaes%!',
                             True)])
def invalid_cookie_general(request, sessionmaker):
    cookiedata, is_encrypted = request.param
    if is_encrypted:
        sessionmaker.settings['encryption_key'] = test_enc_key
    cookie = (b"'Set-Cookie: session=%s; Domain=example.com; Path=/'"
              % base64.b64encode(cookiedata))
    return cookie


def test_session_default_params():
    with pytest.raises(KeyError):
        BaseSession()
    with pytest.raises(KeyError):
        BaseSession(signature_key='')
    sess = BaseSession(signature_key='', domain='example.com')

    assert sess._id_length == 32
    assert sess.enc_key is None
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


def test_session_enc_raise(sessionmaker):
    session = sessionmaker()
    cookie = str(session.save())
    sessionmaker.settings["encryption_key"] = test_enc_key
    crypto.conf["encryption_available"] = False
    with pytest.raises(CryptoError):
        sessionmaker()
    with pytest.raises(CryptoError):
        sessionmaker(cookie)
    crypto.conf["encryption_available"] = True


def test_session_no_enc_no_raise(sessionmaker):
    session = sessionmaker()
    cookie = str(session.save())
    crypto.conf["encryption_available"] = False
    # Don't raise, as we don't want encryption
    sessionmaker()
    sessionmaker(cookie)
    crypto.conf["encryption_available"] = True


def test_session_enc(sessionmaker):
    sessionmaker.settings["encryption_key"] = test_enc_key
    session = sessionmaker()
    session_id = ("a94d3fc0fd42e0f4d860b714b7ca4b2f"
                  "675c5164bfaa50dc1c6ce949b52699dd")
    cookie = session.save()
    session.session_id = session_id
    data = base64.b64decode(str(cookie).split(";")[0][20:])
    tag, ciphertext = data[:64], data[64:]
    plain = decrypt_authenticated(ciphertext, tag, test_enc_key, test_sig_key,
                                  hashlib.sha256)
    plain = json.loads(plain)
    if sessionmaker.settings["backend"] == "cookie":
        plain = plain[0]
    assert plain == session_id


def test_session_id_set(sessionmaker):
    log.debug("Start set id test")
    session = sessionmaker()
    sessid = "0" * 64
    session.save()
    session.session_id = sessid
    assert session.session_id == sessid
    log.debug("End set id test")


def test_session_default_values(sessionmaker):
    session = sessionmaker()
    assert session._load_data() is None


def test_session_new(sessionmaker):
    session = sessionmaker()
    assert session.is_new
    assert not session.modified
    assert session._data is None
    assert session.created

    session["testkey"] = "testval"
    assert session._data
    assert session["testkey"] == "testval"

    assert session.session_id
    cookie = session.save()

    new_session = sessionmaker(str(cookie))
    assert new_session["testkey"] == "testval"


def test_session_new_load_data(sessionmaker):
    session = sessionmaker()
    ret = session._load_data()
    assert ret is None


def test_session_empty(sessionmaker):
    session = sessionmaker()
    cookie = session.save()
    created_before = time.time()
    session_id = session._get_session_id_from_cookie()

    # Load it back
    session_old = sessionmaker(str(cookie))
    assert session_old.session_id == session_id
    session_old.load()
    assert "_access" in session_old.internal_data
    assert "_creation" in session_old.internal_data
    assert session_old["_creation"] < created_before


def test_session_existing(sessionmaker, existing_session):
    session = existing_session
    assert not session.is_new
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
    del session["kéy5"]
    session["_internal"] = "internal_value"
    assert "_internal" not in session
    assert "_internal" in session.internal_data
    session["key6"] = "value6"
    assert session.popitem() == ("key6", "value6")
    assert session.modified
    with pytest.raises(KeyError):
        session.popitem()
    assert session.modified
    session.modified = False
    with pytest.raises(KeyError):
        session.popitem()
    assert not session.modified

    session = sessionmaker()
    session["kéy1"] = "valué1"
    session["kéy2"] = "valüe2"
    assert dict(session) == {"kéy1": "valué1", "kéy2": "valüe2"}


def test_session_clear(sessionmaker):
    session = sessionmaker()
    session["kéy"] = "valué"
    cookie = session.save()

    session2 = sessionmaker(str(cookie))
    assert not session2.is_new
    assert session2["kéy"] == "valué"
    assert not session2.modified
    old_creation = session2["_creation"]
    old_access = session2["_access"]
    session2.clear()
    assert session2["_creation"] > old_creation
    assert session2["_access"] > old_access
    assert len(session2) == 0


def test_session_not_new_after_save(sessionmaker):
    # Session had issue where it was marked as new after it was saved, but
    # at that point it is NOT new any more
    session = sessionmaker()
    cookie = session.save()
    assert not session.is_new


def test_session_cookie_no_str(sessionmaker):
    session = sessionmaker()
    cookie = session.save()
    session_id = session.session_id

    with pytest.raises(ValueError):
        sessionmaker(cookie)

    with pytest.raises(ValueError):
        sessionmaker(unicode(cookie))

    assert sessionmaker(str(cookie)).session_id == session_id


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
    assert session2["kéy"] == "valué"
    assert session2.created == old_creation


def test_delete_data(sessionmaker):
    session = sessionmaker()
    session._delete_data(session.session_id)
    assert session._load_data() is None


def test_session_delete_other(sessionmaker):
    # Cookie not capable of deleting other data
    if sessionmaker.settings["backend"] == "cookie":
        pytest.skip("Cookies cannot delete foreign data")
    sess1 = sessionmaker()
    sess1["key"] = "value1"
    sess1_id = sess1.session_id
    cookie1 = sess1.save()

    sess2 = sessionmaker()
    sess2["key"] = "value2"
    sess2._delete_data(sess1.session_id)
    cookie2 = sess2.save()

    sess2_old = sessionmaker(str(cookie2))
    assert sess2_old["key"] == "value2"
    assert sess2_old.session_id == sess2.session_id

    sess1_old = sessionmaker(str(cookie1))
    assert sess1_id == sess1_old.session_id
    assert "key" not in sess1_old
    assert sess1_id != sess1_old.session_id


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


def test_different_hashalg(sessionmaker):
    settings = sessionmaker.settings
    delattr(sessionmaker, "settings")
    settings["hashalg"] = hashlib.md5
    sessionmaker.configure(**settings)
    session = sessionmaker()
    cookie = session.save()
    session_id = session._get_session_id_from_cookie()
    val = base64.b64decode(str(cookie).split(";")[0][20:])
    sig, data = val[:32], val[32:]
    sig_key = session.sig_key
    assert authenticate_data(data, sig_key, hashlib.md5) == sig

    old_session = sessionmaker(str(cookie))
    assert old_session.session_id == session_id


def test_invalid_signature(invalid_sig_cookie, sessionmaker):
    with LogCollector(backend_log) as l:
        sessionmaker(invalid_sig_cookie)
        records = [r for r in l.records if r.levelno == WARN]
        assert len(records) == 1
        assert "Cryptographic Error 'Invalid Signature'" in records[0].message


def test_invalid_sig_on_enc(sessionmaker, invalid_sig_on_enc_cookie):
    with LogCollector(backend_log) as l:
        sessionmaker(invalid_sig_on_enc_cookie)
        records = [r for r in l.records if r.levelno == WARN]
        assert len(records) == 1
        assert ("Cryptographic Error 'Signature does not match, "
                "invalid ciphertext'") in records[0].message


def test_invalid_ciphertext(sessionmaker, invalid_enc_cookie):
    with LogCollector(backend_log) as l:
        sessionmaker(invalid_enc_cookie)
        records = [r for r in l.records if r.levelno == WARN]
        assert len(records) == 1
        assert ("Cryptographic Error 'Could not retrieve plaintext back "
                "properly (wrong key or ciphertext?)'") in records[0].message


def test_cookie_load_error_general(sessionmaker, invalid_cookie_general):
    with LogCollector(backend_log) as l:
        sessionmaker(invalid_cookie_general)
        records = [r for r in l.records if r.levelno == INFO]
        not_debug = [r for r in l.records if r.levelno != DEBUG]
        assert len(records) == 1
        assert len(not_debug) == 1
        assert "Error loading cookie" in records[0].message


def test_get_session_id_from_cookie(sessionmaker):
    session = sessionmaker()
    sessid = "0" * 64
    session.session_id = sessid
    assert session._get_session_id_from_cookie() == sessid


def test_get_session_id_from_cookie_existing(sessionmaker):
    session = sessionmaker()
    sessid = session.session_id
    cookie = session.save()

    session = sessionmaker(str(cookie))


def test_set_session_id_to_cookie(sessionmaker):
    session = sessionmaker()
    sessid = "0" * 64
    session._set_session_id_to_cookie(sessid)
    assert session.session_id == sessid


def test_set_session_id_to_cookie_existing(sessionmaker):
    session = sessionmaker()
    cookie = session.save()

    session = sessionmaker(str(cookie))
    sessid = "0" * 64
    session._set_session_id_to_cookie(sessid)
    assert session.session_id == sessid


def test_set_session_id_to_cookie_data(sessionmaker):
    session = sessionmaker()
    sessid = "0" * 64
    session._set_session_id_to_cookie(sessid)
    assert session.session_id == sessid
    assert session._load_data() is None


def test_set_session_id_before_save(sessionmaker):
    session = sessionmaker()
    sessid = "0" * 64
    session.session_id = sessid
    session.save()
    assert session.session_id == sessid
