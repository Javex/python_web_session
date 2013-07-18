# -*- coding: utf-8 -*-
import pytest
import hashlib
from pysess.crypto import encrypt_then_authenticate, decrypt_authenticated
import hmac

@pytest.fixture
def authed():
    return encrypt_then_authenticate("test", '0' * 32, '1' * 32,
                                            hashlib.sha256)

def test_encryption(authed):
    ciphertext, tag = authed
    plain = decrypt_authenticated(ciphertext, tag, '0' * 32, '1' * 32,
                                  hashlib.sha256)
    assert plain == "test"


def test_encryption_wrong_tag(authed):
    ciphertext, __ = authed
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, '0', '0' * 32, '3' * 32, hashlib.sha256)


def test_encryption_bad_ciphertext(authed):
    ciphertext, __ = authed
    new_ciphertext = '0' * len(ciphertext)
    new_tag = hmac.new('1' * 32, new_ciphertext, hashlib.sha256).hexdigest()
    plain = decrypt_authenticated(new_ciphertext, new_tag, '0' * 32, '1' * 32,
                          hashlib.sha256)
    assert plain != "test"


def test_encryption_bad_enc_key(authed):
    ciphertext, tag = authed
    plain = decrypt_authenticated(ciphertext, tag, '1' + '0' * 31, '1' * 32,
                                  hashlib.sha256)
    assert plain != "test"


def test_encryption_bad_sig_key(authed):
    ciphertext, tag = authed
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, tag, '0' * 32, 'hmac_key',
                              hashlib.sha256)


def test_encryption_wrpng_hashalg(authed):
    ciphertext, tag = authed
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, tag, '0' * 32, '1' * 32, hashlib.md5)
