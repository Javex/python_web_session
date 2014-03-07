# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess import sessionmaker, crypto
from pysess.exc import SessionConfigurationError, CryptoError
from pysess.session.backends import DogpileSession
from tests.test_crypto import test_sig_key, test_enc_key
import pytest
import warnings
from pysess.util import get_secret_keys


@pytest.fixture(params=list(range(3)))
def wrong_settings(request):
    """Settings which are considered a wrong combination. Returns a pair of
    (faulty_settings, msg_part) where faulty_settings is the dictionary with
    wrong settings and msg_part is a part of the expected exception message to
    make sure the correct exception was raised."""
    wrong_settings = [({'encryption_key': True},
                       "encryption key but no signature key"),
                      ({'secret_file': True, 'signature_key': True},
                       "a secret file OR a signature key"),
                      ({'signature_key': True, 'enable_encryption': True},
                       "enable encryption but already provide a signature "
                       "key")
                      ]
    return wrong_settings[request.param]


@pytest.fixture(params=list(range(2)))
def wrong_call_settings(request):
    """Same as wrong_settings only for the __call__ sanity check."""
    wrong_settings = [({'secret_file': True},
                       "secret file is not allowed"),
                      ({'enable_encryption': True},
                       "enable_encryption option only")]
    return wrong_settings[request.param]


def test_sessionmaker_no_backend(filename):
    Session = sessionmaker()
    info = pytest.raises(SessionConfigurationError, Session.configure,
                         secret_file=filename)
    assert "No backend given" in info.value.message


def test_session_unknown_backend(filename):
    Session = sessionmaker()
    info = pytest.raises(SessionConfigurationError, Session.configure,
                         backend='doesnotexist', secret_file=filename)
    assert info.value.message == "Backend doesnotexist not found."


def test_sessionmaker_new_conf(cache_dict):
    try:
        from dogpile.cache.region import make_region
    except ImportError:
        pytest.skip("dogpile.cache not available")
    region = make_region().configure('dogpile.cache.memory',
                                     arguments={'cache_dict': cache_dict})
    settings = {'backend': 'dogpile',
                'domain': 'example.com',
                'signature_key': test_sig_key,
                'region': region
                }
    Session = sessionmaker()
    assert not hasattr(Session, "settings")
    Session.configure(**settings)
    assert isinstance(Session(), DogpileSession)

    del Session.settings["region"]
    assert "region" not in Session.settings
    assert isinstance(Session(region=region), DogpileSession)
    Session.settings["region"] = region

    assert Session.settings["signature_key"] == test_sig_key
    session = Session(signature_key=test_enc_key)
    assert session.sig_key == test_enc_key


def test_sessionmaker_not_configured():
    Session = sessionmaker()
    with pytest.raises(SessionConfigurationError):
        Session()


def test_sessionmaker_already_configured(sessionmaker):
    with pytest.raises(SessionConfigurationError):
        sessionmaker.configure()


def test_sessionmaker_secret_file(sessionmaker, filename):
    del sessionmaker.settings["signature_key"]
    settings = sessionmaker.settings
    delattr(sessionmaker, "settings")
    settings["secret_file"] = filename
    sessionmaker.configure(**settings)
    assert "signature_key" in sessionmaker.settings
    keys = get_secret_keys(filename)
    assert sessionmaker.settings["signature_key"] == keys["signature_key"]


def test_sessionmaker_secret_file_encryption(sessionmaker, filename):
    del sessionmaker.settings["signature_key"]
    settings = sessionmaker.settings
    delattr(sessionmaker, "settings")
    settings["enable_encryption"] = True
    settings["secret_file"] = filename
    sessionmaker.configure(**settings)
    assert "signature_key" in sessionmaker.settings
    assert "encryption_key" in sessionmaker.settings


def test_sessionmaker_different_backend_on_call(sessionmaker):
    del sessionmaker.settings["backend"]
    pass


def test_sessionmaker_pycrypto_exception_raise(sessionmaker, filename):
    settings = sessionmaker.settings
    delattr(sessionmaker, "settings")
    crypto.conf["encryption_available"] = False
    with pytest.raises(CryptoError):
        sessionmaker.configure(secret_file=filename, enable_encryption=True,
                               backend=settings["backend"])


def test_sessionmaker_pycrypto_exception_no_enc(sessionmaker, filename):
    settings = sessionmaker.settings
    delattr(sessionmaker, "settings")
    crypto.conf["encryption_available"] = False
    # does not raise because no encryption is requested
    sessionmaker.configure(secret_file=filename, backend=settings["backend"])


def test_sessionmaker_sanity_configure(sessionmaker):
    # Make sure sanity is called on configure
    delattr(sessionmaker, "settings")
    with pytest.raises(SessionConfigurationError):
        sessionmaker.configure(**{'encryption_key': None})


def test_sessionmaker_sanity_call(sessionmaker):
    with pytest.raises(SessionConfigurationError):
        sessionmaker(**{'secret_file': True})


def test_sessionmaker_sanity_checks(wrong_settings):
    settings, msg_part = wrong_settings
    info = pytest.raises(SessionConfigurationError,
                         sessionmaker._check_settings_sanity, settings)
    msg = info.value.message
    assert msg_part in msg


def test_sessionmaker_sanity_checks_warnings():
    with warnings.catch_warnings(record=True) as w:
        sessionmaker._check_settings_sanity({'encryption_key': True,
                                             'enable_encryption': True,
                                             'signature_key': True})
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert ("both an encryption key and the "
                "enable_encryption") in str(w[0].message)


def test_sessionmaker_call_sanity(wrong_call_settings):
    settings, msg_part = wrong_call_settings
    info = pytest.raises(SessionConfigurationError,
                         sessionmaker()._check_call_settings_sanity, settings)
    msg = info.value.message
    assert msg_part in msg


def test_sessionmaker_init_keys(filename):
    Session = sessionmaker()
    Session.settings = {'secret_file': filename}
    Session._init_keys(Session.settings)
    assert 'encryption_key' not in Session.settings
    assert isinstance(Session.settings['signature_key'], str)
    assert len(Session.settings['signature_key']) == 32

    Session = sessionmaker()
    Session.settings = {'enable_encryption': True, 'secret_file': filename}
    Session._init_keys(Session.settings)
    assert isinstance(Session.settings['signature_key'], str)
    assert isinstance(Session.settings['encryption_key'], str)

    assert len(Session.settings['encryption_key']) == 32
    assert len(Session.settings['signature_key']) == 32
