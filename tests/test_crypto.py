# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from pysess import crypto
from pysess.crypto import (encrypt_then_authenticate, decrypt_authenticated,
                           get_hash_length, authenticate_data, verify_data,
                           encryption_available)
import hashlib
import hmac
import pytest
from pysess.exc import CryptoError

test_enc_key = b'0' * 32
test_sig_key = b'1' * 32


@pytest.fixture(params=['test', 'tést', b'test', b't\xc3\xa9st'])
def authenced(request):
    """Encrypt and authenticate a testvalue and return a three-tuple
    (testval, ciphertext, tag)."""
    if not encryption_available():
        pytest.skip("pycrypto not available")
    testval = request.param
    ciphertext, tag = encrypt_then_authenticate(testval, test_enc_key,
                                                test_sig_key, hashlib.sha256)
    return testval, ciphertext, tag


@pytest.fixture(params=['test', 'tést', b'test', b't\xc3\xa9st'])
def authed(request):
    """Authenticate a test value and return the pair (testval, signature)."""
    testval = request.param
    return testval, authenticate_data(testval, test_sig_key, hashlib.sha256)


def test_encryption(authenced):
    testval, ciphertext, tag = authenced
    plain = decrypt_authenticated(ciphertext, tag, test_enc_key, test_sig_key,
                                  hashlib.sha256)
    assert isinstance(plain, unicode)
    if isinstance(testval, str):
        testval = testval.decode('utf-8')
    assert plain == testval


def test_encryption_wrong_tag(authenced):
    __, ciphertext, __ = authenced
    with pytest.raises(CryptoError):
        decrypt_authenticated(ciphertext, '0', test_enc_key, test_sig_key,
                              hashlib.sha256)


def test_encryption_bad_ciphertext(authenced):
    __, ciphertext, __ = authenced
    new_ciphertext = ('é' * len(ciphertext)).encode('utf-8')
    new_tag = hmac.new(test_sig_key, new_ciphertext,
                       hashlib.sha256).hexdigest()
    with pytest.raises(CryptoError):
        decrypt_authenticated(new_ciphertext, new_tag, test_enc_key,
                              test_sig_key, hashlib.sha256)


def test_encryption_bad_enc_key(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(CryptoError):
        decrypt_authenticated(ciphertext, tag, b'1' + test_enc_key[1:],
                              test_sig_key, hashlib.sha256)


def test_encryption_bad_sig_key(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(CryptoError):
        decrypt_authenticated(ciphertext, tag, test_enc_key, b'hmac_key',
                              hashlib.sha256)


def test_encryption_wrong_hashalg(authenced):
    __, ciphertext, tag = authenced
    with pytest.raises(CryptoError):
        decrypt_authenticated(ciphertext, tag, test_enc_key,
                              test_sig_key, hashlib.md5)


@pytest.mark.skipif("not encryption_available()",
                    reason="pycrypto not available")
def test_encryption_key_type_check():
    with pytest.raises(TypeError):
        encrypt_then_authenticate("", unicode(test_enc_key), test_sig_key,
                                  hashlib.sha256)
    with pytest.raises(TypeError):
        encrypt_then_authenticate("", test_enc_key, unicode(test_sig_key),
                                  hashlib.sha256)


def test_get_hash_length():
    for algname, length in [('md5', 128), ('sha1', 160), ('sha256', 256),
                            ('sha512', 512)]:
        alg = getattr(hashlib, algname)
        assert get_hash_length(alg) == length


def test_authentication(authed):
    val, sig = authed
    assert verify_data(val, sig, test_sig_key, hashlib.sha256)


def test_authentication_bad_tag(authed):
    val, _ = authed
    with pytest.raises(CryptoError):
        verify_data(val, '0' * 32, test_sig_key, hashlib.sha256)


def test_authentication_wrong_hashalg(authed):
    val, sig = authed
    with pytest.raises(CryptoError):
        verify_data(val, sig, test_sig_key, hashlib.md5)


def test_authentication_bad_key(authed):
    val, sig = authed
    with pytest.raises(CryptoError):
        verify_data(val, sig, b'0' + test_sig_key[1:], hashlib.sha256)


def test_authentication_key_type_check():
    with pytest.raises(TypeError):
        authenticate_data("", unicode("0"), hashlib.sha256)


@pytest.mark.skipif("not encryption_available()",
                    reason="pycrypto not available")
def test_encryption_available():
    assert encryption_available()


def test_encryption_available_fails():
    oldval = crypto.conf["encryption_available"]
    crypto.conf["encryption_available"] = False
    assert not encryption_available()
    crypto.conf["encryption_available"] = oldval


@pytest.mark.skipif("not encryption_available()",
                    reason="pycrypto not available")
def test_encryption_available_recheck():
    assert encryption_available()
    del crypto.conf["encryption_available"]
    with pytest.raises(KeyError):
        assert not encryption_available()
    assert encryption_available(recheck=True)
