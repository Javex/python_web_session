# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import pytest
import pysess
from pysess.session.backends import DogpileSession
from dogpile.cache import make_region
from tests.test_crypto import test_sig_key

cache = {}  # dict for region cache

@pytest.fixture
def sessionmaker():
    region = make_region().configure('dogpile.cache.memory',
                            arguments={'cache_dict': cache})
    settings = {'backend': 'dogpile',
              'domain': 'example.com',
              'signature_key': test_sig_key,
              'region': region,
              }

    Session = pysess.sessionmaker(**settings)
    return Session


@pytest.fixture
def existing_session(sessionmaker):
    sess = sessionmaker()
    sess["test"] = "testval"
    cookie = sess.save()
    return sessionmaker(str(cookie))
