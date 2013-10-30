# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from dogpile.cache.region import make_region
from pysess import sessionmaker, crypto
from pysess.exc import SessionConfigurationError, CryptoError
from pysess.session.backends import DogpileSession
from tests.test_crypto import test_sig_key, test_enc_key
import pytest


def test_sessionmaker_no_backend(filename):
    Session = sessionmaker()
    Session.configure(secret_file=filename)
    with pytest.raises(SessionConfigurationError):
        Session()


def test_session_unknown_backend(filename):
    Session = sessionmaker()
    Session.configure(backend='doesnotexist',
                      secret_file=filename)
    with pytest.raises(ValueError):
        Session()


def test_sessionmaker_new_conf(cache_dict):
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


def test_sessionmaker_pycrypto_exception_raise(sessionmaker, filename):
    delattr(sessionmaker, "settings")
    crypto.conf["encryption_available"] = False
    with pytest.raises(CryptoError):
        sessionmaker.configure(secret_file=filename, enable_encryption=True)


def test_sessionmaker_pycrypto_exception_no_enc(sessionmaker, filename):
    delattr(sessionmaker, "settings")
    crypto.conf["encryption_available"] = False
    # does not raise because no encryption is requested
    sessionmaker.configure(secret_file=filename)
