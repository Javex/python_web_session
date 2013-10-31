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


log = logging.getLogger(__name__)


@pytest.fixture(params=['dogpile', 'cookie'])
def sessionmaker(request, cache_dict):
    """Return a new session factory, one for each tested backend. It will be
    already configured, so if re-configuration is desired, one should reset
    the configuration."""
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
        # No extra settings needed
        pass

    Session = pysess.sessionmaker()
    Session.configure(**settings)
    return Session


@pytest.fixture
def cache_dict():
    """Just a dict to be used as cache."""
    return {}


@pytest.fixture
def existing_session(sessionmaker):
    """Create a session, save a value to it and load it again."""
    sess = sessionmaker()
    sess["test"] = "testval"
    cookie = sess.save()
    return sessionmaker(str(cookie))


@pytest.fixture
def filename(request, tmpdir):
    """Create a temporary file in a uniqe testing directory and delete it
    after the test."""
    filename = tmpdir.join('file')
    assert not os.path.exists(filename.strpath)

    def remove():
        filename.remove()
        assert not os.path.exists(filename.strpath)
    request.addfinalizer(remove)
    return filename.strpath
