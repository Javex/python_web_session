# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess.session.backends import DogpileSession, CookieSession


def get_session_class(name):
    """
    For a given name, retrieve the corresponding session class.
    """
    available_sessions = {'dogpile': DogpileSession,
                          'cookie': CookieSession,
                          }
    try:
        return available_sessions[name.lower()]
    except KeyError:
        raise ValueError("Session %s not found" % name)
