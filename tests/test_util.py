# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from datetime import datetime
from pysess.util import (max_age_to_expires, create_secret_file, get_secret_keys,
    permissions_okay, compare_constant_time, get_or_create_secret_keys)
from tempfile import NamedTemporaryFile
import calendar
import itertools
import json
import logging
import os
import pytest
import stat


log = logging.getLogger(__name__)

# TODO: Test get_or_create_secret_keys
# TODO: Test compare_constant_time


def test_max_age_to_expires():
    max_age = 0
    basetime = datetime(2013, 01, 01, 14, 35, 23)
    fromtime = calendar.timegm(basetime.utctimetuple())
    assert max_age_to_expires(max_age, fromtime) == \
        'Tue, 01-Jan-2013 14:35:23 GMT'


def test_max_age_to_expires_now():
    max_age = 0
    now = datetime.utcnow()
    assert max_age_to_expires(max_age) == \
        now.strftime('%a, %d-%b-%Y %H:%M:%S GMT')


def test_create_secret_file(filename):
    create_secret_file(filename)
    with open(filename) as f:
        keys = json.loads(f.read(), encoding='iso-8859-1')
        assert len(keys["encryption_key"]) == 32
        assert len(keys["signature_key"]) == 32


def test_create_secret_file_custom_length(filename):
    create_secret_file(filename, 64, 64)
    with open(filename) as f:
        keys = json.loads(f.read(), encoding='iso-8859-1')
        assert len(keys["encryption_key"]) == 64
        assert len(keys["signature_key"]) == 64


def test_create_secret_file_permissions(filename):
    create_secret_file(filename)
    st = os.stat(filename).st_mode
    assert st & stat.S_IRUSR
    assert st & stat.S_IWUSR
    for perm in ['RGRP', 'WGRP', 'XGRP', 'ROTH', 'WOTH', 'XOTH']:
        assert not st & getattr(stat, 'S_I%s' % perm)


def test_create_secret_file_no_overwrite(filename):
    create_secret_file(filename)
    with pytest.raises(ValueError):
        create_secret_file(filename)


def test_create_secret_file_overwrite(filename):
    create_secret_file(filename)
    with open(filename) as f:
        keys = json.loads(f.read(), encoding='iso-8859-1')
    create_secret_file(filename, overwrite=True)
    with open(filename) as f:
        new_keys = json.loads(f.read(), encoding='iso-8859-1')
    for key, value in new_keys.items():
        assert keys[key] != value
        assert len(keys[key]) == len(value)
    assert len(keys) == len(new_keys)


def test_get_secret_keys(filename):
    create_secret_file(filename)
    keys = get_secret_keys(filename)
    assert len(keys["encryption_key"]) == 32
    assert len(keys["signature_key"]) == 32


def test_get_secret_keys_fixed_values(filename):
    my_keys = {'encryption_key': '\0' * 32, 'signature_key': '\1' * 32}
    with open(filename, "w") as f:
        f.write(json.dumps(my_keys, encoding='iso-8859-1'))
    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
    keys = get_secret_keys(filename)
    assert keys['encryption_key'] == '\0' * 32
    assert keys['signature_key'] == '\1' * 32


def test_get_secret_keys_wrong_permissions(filename):
    create_secret_file(filename)
    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    with pytest.raises(ValueError):
        get_secret_keys(filename)


def test_get_secret_keys_wrong_permissions_ignore(filename):
    create_secret_file(filename)
    os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)
    assert get_secret_keys(filename, ignore_permissions=True)


def test_get_or_create_secret_keys_get(filename):
    create_secret_file(filename)
    assert get_or_create_secret_keys(filename) == get_secret_keys(filename)


def test_get_or_create_secret_keys_create(filename):
    assert not os.path.isfile(filename)
    get_or_create_secret_keys(filename)
    assert os.path.isfile(filename)


def test_get_or_create_secret_keys_both(filename):
    assert not os.path.exists(filename)
    ret = get_or_create_secret_keys(filename)
    assert os.path.exists(filename)
    assert get_or_create_secret_keys(filename) == ret


def test_permissions_okay():
    perms = [stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
             stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
             stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH]
    for i in range(1, 10):
        for items in itertools.combinations(perms, i):
            set_perm_to = 0
            for perm in items:
                set_perm_to |= perm
            with NamedTemporaryFile() as f:
                os.chmod(f.name, set_perm_to)
                assert permissions_okay(f.name, items)


def test_permissions_not_okay():
    perms = [stat.S_IWUSR, stat.S_IXUSR,
             stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
             stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH]
    for i in range(1, 9):
        for items in itertools.combinations(perms, i):
            set_perm_to = 0
            for perm in items:
                set_perm_to |= perm
            with NamedTemporaryFile() as f:
                os.chmod(f.name, set_perm_to)
                items = list(items)
                items.append(stat.S_IRUSR)
                assert not permissions_okay(f.name, items)


def test_compare_constant_time_works():
    assert compare_constant_time("A" * 30, "A" * 30)


def test_compare_constant_time_unequal_length():
    assert not compare_constant_time("A" * 30, "A" * 29)


def test_compare_constant_time_unequal_strings():
    assert not compare_constant_time("A" * 30, "A" * 29 + "B")
