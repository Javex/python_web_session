# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import os
import logging.config


ROOT_PATH = os.path.dirname(__file__)
conf = os.path.join(ROOT_PATH, 'pytest.ini')
here = os.path.dirname(conf)
defaults = {'__file__': conf, 'here': here}
logging.config.fileConfig(conf, defaults)
from tests.test_crypto import test_sig_key
import pysess
import pytest


@pytest.fixture(params=["dogpile", ])
def sessionmaker(request, cache_dict):
    backend = request.param
    settings = {'backend': backend,
                'domain': 'example.com',
                'signature_key': test_sig_key,
               }
    if backend == 'dogpile':
        try:
            from dogpile.cache import make_region
        except ImportError:
            pytest.skip("dogpile.cache not available")
        region = make_region().configure('dogpile.cache.memory',
                                         arguments={'cache_dict': cache_dict})
        settings["region"] = region
    elif backend == 'cookie':
        raise NotImplementedError

    Session = pysess.sessionmaker()
    Session.configure(**settings)
    return Session


@pytest.fixture
def cache_dict():
    return {}


@pytest.fixture
def existing_session(sessionmaker):
    sess = sessionmaker()
    sess["test"] = "testval"
    cookie = sess.save()
    return sessionmaker(str(cookie))


@pytest.fixture
def filename(request, tmpdir):
    filename = tmpdir.join('file')
    assert not os.path.exists(filename.strpath)

    def remove():
        filename.remove()
        assert not os.path.exists(filename.strpath)
    request.addfinalizer(remove)
    return filename.strpath
