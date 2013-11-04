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
        for t in threads:
            thread_list.append(Thread(target=threadmon.wrap(t)))
        for t in thread_list:
            t.start()
        for t in thread_list:
            t.join()
    return _run


def test_two_thread_read_lock(run_thread_test, cookie, sessionmaker):
    data_read = Lock()

    def write_data():
        try:
            while data_read.acquire(False):
                data_read.release()
            data_read.acquire()
            session = sessionmaker(cookie)
            session["kéy"] = "valué"
            session.save()
        finally:
            data_read.release()

    def read_data():
        try:
            data_read.acquire()
            session = sessionmaker(cookie)
            assert "kéy" not in session
        finally:
            data_read.release()
            session.abort()

    run_thread_test(write_data, read_data)
    session = sessionmaker(cookie)
    assert session["kéy"] == "valué"


def test_write_lock(run_thread_test, cookie, sessionmaker):
    order_lock = Lock()

    def write1():
        try:
            order_lock.acquire()
            session = sessionmaker(cookie)
            session.load()
            order_lock.release()
            while order_lock.acquire(False):
                order_lock.release()
            order_lock.acquire()
            session["key"] = "value"
        finally:
            session.save()
            order_lock.release()

    def write2():
        try:
            order_lock.acquire()
            session = sessionmaker(cookie)
            session.load()
            order_lock.release()
            while order_lock.acquire(False):
                order_lock.release()
            order_lock.acquire()
            session["key2"] = "value2"
        finally:
            session.save()
            order_lock.release()

    run_thread_test(write1, write2)
    session = sessionmaker(cookie)
    assert session["key2"] == "value2"
    assert session["key"] == "value"


def test_write_conflict(run_thread_test, cookie, sessionmaker):
    order_lock = Lock()

    def write1():
        try:
            order_lock.acquire()
            session = sessionmaker(cookie)
            session["key"] = "value"
        finally:
            order_lock.release()
            session.save()

    def write2():
        try:
            while order_lock.acquire(False):
                order_lock.release()
            session = sessionmaker(cookie)
            with pytest.raises(RuntimeError):
                session["key"] = "value2"
        finally:
            session.save()

    run_thread_test(write1, write2)
    session = sessionmaker(cookie)
    assert session["key"] == "value"

