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

    def _run(*threads):

        thread_list = []
        for thread in threads:
            thread_list.append(Thread(target=threadmon.wrap(thread)))
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()
    return _run


def test_no_read_lock(run_thread_test, cookie, sessionmaker):
    data_read = Lock()

    def write_data():
        try:
            session = sessionmaker(cookie)
            session["kéy"] = "valué"
            while data_read.acquire(False):
                data_read.release()^
            data_read.acquire()
        finally:
            session.save()
            data_read.release()

    def read_data():
        try:
            data_read.acquire()
            session = sessionmaker(cookie)
            assert "kéy" not in session
        finally:
            session.abort()
            data_read.release()

    run_thread_test(write_data, read_data)
    log.debug("Load main thread")
    session = sessionmaker(cookie)
    log.debug("session created")
    assert session["kéy"] == "valué"
    log.debug("after assertion")


def test_write_lock(run_thread_test, cookie, sessionmaker):
    write1_done = Lock()

    def write1():
        try:
            write1_done.acquire()
            session = sessionmaker(cookie)
            session["kéy"] = "valué"
        finally:
            session.save()
            write1_done.release()

    def write2():
        try:
            while write1_done.acquire(False):
                write1_done.release()
            write1_done.acquire()
            session = sessionmaker(cookie)
            assert "kéy" not in session
            session["kéy"] = "valué2"
        finally:
            session.save()
            write1_done.release()

    run_thread_test(write1, write2)
    session = sessionmaker(cookie)
    assert session["kéy"] == "valué2"
