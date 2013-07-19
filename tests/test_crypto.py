# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import pytest
import hashlib
from pysess.crypto import encrypt_then_authenticate, decrypt_authenticated, \
    get_hash_length, authenticate_data, verify_data
import hmac

test_enc_key = b'0' * 32
test_sig_key = b'1' * 32

@pytest.fixture(params=['test', 'tést'])
def authenced(request):
    testval = request.param
    ciphertext, tag = encrypt_then_authenticate(testval, test_enc_key,
                                                test_sig_key, hashlib.sha256)
    return testval, ciphertext, tag


@pytest.fixture
def authed():
    return authenticate_data('test', test_sig_key, hashlib.sha256)

def test_encryption(authenced):
    testval, ciphertext, tag = authenced
    plain = decrypt_authenticated(ciphertext, tag, test_enc_key, test_sig_key,
                                  hashlib.sha256)
    assert isinstance(plain, unicode)
    assert plain == testval


def test_encryption_wrong_tag(authenced):
    __, ciphertext, __ = authenced
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, '0', test_enc_key, test_sig_key,
                              hashlib.sha256)


def test_encryption_bad_ciphertext(authenced):
    __, ciphertext, __ = authenced
    new_ciphertext = 'é' * len(ciphertext)
    new_tag = hmac.new(test_sig_key, new_ciphertext.encode('utf-8'),
                       hashlib.sha256).hexdigest()
    with pytest.raises(ValueError):
        decrypt_authenticated(new_ciphertext, new_tag, test_enc_key,
                              test_sig_key, hashlib.sha256)


def test_encryption_bad_enc_key(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, tag, b'1' + test_enc_key[1:],
                              test_sig_key, hashlib.sha256)


def test_encryption_bad_sig_key(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, tag, test_enc_key, b'hmac_key',
                              hashlib.sha256)


def test_encryption_wrong_hashalg(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(ValueError):
        decrypt_authenticated(ciphertext, tag, test_enc_key,
                              test_sig_key, hashlib.md5)


def test_encryption_key_type_check():
    with pytest.raises(TypeError):
        encrypt_then_authenticate("", unicode(test_enc_key), test_sig_key,
                                  hashlib.sha256)
    with pytest.raises(TypeError):
        encrypt_then_authenticate("", test_enc_key, unicode(test_sig_key),
                                  hashlib.sha256)


def test_get_hash_length():
    for algname, length in [('md5', 128), ('sha1', 160), ('sha256', 256), ('sha512', 512)]:
        alg = getattr(hashlib, algname)
        assert get_hash_length(alg) == length


def test_authentication(authed):
    assert verify_data('test', authed, test_sig_key, hashlib.sha256)


def test_authentication_bad_tag(authed):
    with pytest.raises(ValueError):
        verify_data('test', '0' * 32, test_sig_key, hashlib.sha256)


def test_authentication_wrong_hashalg(authed):
    with pytest.raises(ValueError):
        verify_data('test', authed, test_sig_key, hashlib.md5)

def test_authentication_bad_key(authed):
    with pytest.raises(ValueError):
        verify_data('test', authed, b'0' + test_sig_key[1:], hashlib.sha256)

def test_authentication_key_type_check():
    with pytest.raises(TypeError):
        authenticate_data("", unicode("0"), hashlib.sha256)
