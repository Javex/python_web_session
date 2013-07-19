# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess import sessionmaker
import pytest
from tests.test_crypto import test_sig_key, test_enc_key
from tests import cache
from dogpile.cache.region import make_region
from pysess.session.backends import DogpileSession

def test_sessionmaker_no_backend():
    Session = sessionmaker()
    with pytest.raises(ValueError):
        Session()


def test_session_unknown_backend():
    Session = sessionmaker(backend='doesnotexist')
    with pytest.raises(ValueError):
        Session()


def test_sessionmaker_new_conf():
    region = make_region().configure('dogpile.cache.memory',
                            arguments={'cache_dict': cache})
    settings = {'backend': 'dogpile',
              'domain': 'example.com',
              'signature_key': test_sig_key,
              'region': region,
              }
    Session = sessionmaker()
    assert not Session.settings
    assert isinstance(Session(**settings), DogpileSession)

    del settings["region"]
    Session.configure(**settings)
    assert "region" not in Session.settings
    assert isinstance(Session(region=region), DogpileSession)
    settings["region"] = region

    Session.configure(**settings)
    assert Session.settings["signature_key"] == test_sig_key
    session = Session(signature_key=test_enc_key)
    assert session.sig_key == test_enc_key
