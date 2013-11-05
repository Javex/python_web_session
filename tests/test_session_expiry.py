# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import base64
import logging


log = logging.getLogger(__name__)


def test_refresh_on_access(sessionmaker):
    sessionmaker.settings["max_age"] = 10
    session = sessionmaker()
    session["_access"] -= 100
    # Work around main method to avoid saving of access time
    session._save_data((session.data, session.internal_data))
    session._saved = True
    cookie = session.cookie

    new_session = sessionmaker(str(cookie))
    old_data = new_session._load_data()
    assert old_data  # Make sure there was data before
    new_session.load()
    assert new_session.is_new
    assert old_data != new_session.data


def test_static_expiry(sessionmaker):
    sessionmaker.settings["refresh_on_access"] = False
    sessionmaker.settings["max_age"] = 10
    session = sessionmaker()
    session["test"] = "val"
    session["_creation"] -= 100
    cookie = str(session.save())

    session2 = sessionmaker(cookie)
    assert not session2.is_new
    session2.load()
    assert session2.is_new


def test_no_expiry(sessionmaker):
    session = sessionmaker()
    session["_creation"] = 0
    session["_access"] = 0
    session._save_data((session.data, session.internal_data))
    session._saved = True
    cookie = session.cookie
    cookie = str(cookie)

    session2 = sessionmaker(cookie)
    session2.load()
    assert not session2.is_new
    assert 0 == session2["_creation"]
    assert 0 == session2["_access"]
