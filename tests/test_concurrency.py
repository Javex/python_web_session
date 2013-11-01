# encoding: utf-8
from __future__ import unicode_literals, print_function, absolute_import
from threading import Thread, Lock
import logging
import pytest
import time


log = logging.getLogger(__name__)


@pytest.fixture
def cookie(sessionmaker):
    session = sessionmaker()
    cookie = str(session.save())
    return cookie


@pytest.fixture
def run_thread_test(sessionmaker, threadmon):
    # wont work on cookies
    if sessionmaker.settings["backend"] == 'cookie':
        pytest.skip("Cookie has no threading")

    def _run(write, read):

        write = Thread(target=threadmon.wrap(write))
        read = Thread(target=threadmon.wrap(read))
        write.start()
        time.sleep(0.01)
        read.start()
        write.join()
        read.join()
    return _run


def test_two_thread_read_lock(run_thread_test, cookie, sessionmaker):
    def write_data():
        session = sessionmaker(cookie)
        session["kéy"] = "valué"
        time.sleep(0.1)
        session.save()

    def read_data():
        try:
            session = sessionmaker(cookie)
            assert session["kéy"] == "valué"
        finally:
            session.abort()

    run_thread_test(write_data, read_data)
    log.debug("Load main thread")
    session = sessionmaker(cookie)
    log.debug("session created")
    assert session["kéy"] == "valué"
    log.debug("after assertion")
