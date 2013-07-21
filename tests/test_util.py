# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import time
from datetime import datetime
from pysess.util import max_age_to_expires
from email.utils import formatdate
import calendar


def test_max_age_to_expires():
    max_age = 0
    basetime = datetime(2013, 01, 01, 14, 35, 23)
    fromtime = calendar.timegm(basetime.utctimetuple())
    assert max_age_to_expires(max_age, fromtime) == \
        'Tue, 01-Jan-2013 14:35:23 GMT'

