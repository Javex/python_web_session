# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from logging import NullHandler, NOTSET


class _LoggingTestHandler(NullHandler):
    def __init__(self, collector, level=NOTSET):
        self.collector = collector
        NullHandler.__init__(self, level)

    def handle(self, record):
        self.collector.records.append(record)


class LogCollector(object):
    """
    A simple helper class that records all log entries written within its
    context. It collects every log record in a list called ``records``.
    Each entry is a :cls:`logging.LogRecord` instance.

    Usage:

    .. code-block:: python

        log = logging.getLogger(__name__)
        with LogCollector(log) as log_collector:
            do_something_that_logs_to_log()
            assert len(log_collector.records) == 1
            assert log_collector.records[0].msg == "Some message"
    """

    def __init__(self, logger):
        self.records = []
        self.logger = logger

    def __enter__(self):
        self.handler = _LoggingTestHandler(self)
        self.logger.addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.removeHandler(self.handler)
