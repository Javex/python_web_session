# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import base64
import logging


log = logging.getLogger(__name__)


def test_refresh_on_access(sessionmaker):
    sessionmaker.settings["max_age"] = 10
    session = sessionmaker()
    session._data["_access"] -= 100
    # Work around main method to avoid saving of access time
    session._save_data()
    session._saved = True
    cookie = session.cookie

    new_session = sessionmaker(str(cookie))
    old_data = new_session._load_data()
    assert old_data  # Make sure there was data before
    new_session.load()
    assert new_session.is_new
    assert old_data != new_session._data


def test_no_access_no_refresh(sessionmaker):
    sessionmaker.settings["max_age"] = 10

    # First create a regular session with access
    session = sessionmaker()
    session["test"] = "val"
    cookie = str(session.save())
    old_access = session["_access"]

    # Now make a session with no access
    session2 = sessionmaker(cookie)
    cookie = str(session2.save())
    assert old_access == session2["_access"]


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
    log.debug("Testing backend %s" % sessionmaker.settings["backend"])
    session = sessionmaker()
    log.debug("1")
    session["_creation"] = 0
    log.debug("2: %s" % session._data)
    session["_access"] = 0
    log.debug("3: %s" % session._data)
    session._save_data()
    log.debug("4: %s" % session._data)
    session._saved = True
    log.debug("5: %s" % session._data)
    cookie = session.cookie
    log.debug("Cookie: %r" % cookie)
    cookie = str(cookie)
    log.debug("Data: %r" % base64.b64decode(cookie))

    session2 = sessionmaker(cookie)
    session2.load()
    assert not session2.is_new
    assert 0 == session2["_creation"]
    assert 0 == session2["_access"]
