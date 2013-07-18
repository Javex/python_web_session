# -*- coding: utf-8 -*-
from pysess.session.backends import DogpileSession, CookieSession


def get_session_class(name):
    """
    For a given name, retrieve the corresponding session class.
    """
    available_sessions = {'dogpile': DogpileSession,
                          'cookie': CookieSession,
                          }
    return available_sessions[name.lower()]
