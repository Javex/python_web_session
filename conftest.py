# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import os
import logging.config
from pyramid.paster import setup_logging
setup_logging

ROOT_PATH = os.path.dirname(__file__)

def pytest_sessionstart():
    from pytest import config  # @UnresolvedImport
    if not hasattr(config, 'slaveinput'):
        ROOT_PATH = os.path.dirname(__file__)
        conf = os.path.join(ROOT_PATH, 'pytest.ini')
        logging.config.fileConfig(
            conf,
            dict(__file__=conf, here=os.path.dirname(conf))
            )
