# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import hmac
from pysess.util import compare_constant_time
from pysess.exc import CryptoError

conf = {}


def _check_encryption_available():
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return False
    else:
        return True
conf["encryption_available"] = _check_encryption_available()


def verify_data(data, signature, sig_key, hashalg):
    """
    Check whether ``data`` is authentic for ``signature`` with the key
    ``sig_key``.

    .. warning::
        ``sig_key`` must be a byte string of a sufficient length (recommended
        is ``32`` bytes).
    """
    if isinstance(data, unicode):
        data = data.encode('utf-8')
    reference = authenticate_data(data, sig_key, hashalg)
    if not compare_constant_time(reference, signature):
        raise ValueError("Invalid Signature")
    else:
        return True


def authenticate_data(data, sig_key, hashalg):
    """
    Create a signature for ``data`` with ``sig_key``.

    .. warning::
        ``sig_key`` must be a byte string of a sufficient length (recommended
        is ``32`` bytes).
    """
    if isinstance(data, unicode):
        data = data.encode('utf-8')
    if isinstance(sig_key, unicode):
        raise TypeError("The key must be a **byte** string not unicode!")
    return hmac.new(sig_key, data, hashalg).hexdigest().decode("ascii")


def get_hash_length(hashalg):
    """
    Return the length of a string produced by ``hashalg`` as a number of bits.
    """
    return len(hashalg().digest()) * 8


def encryption_available(recheck=False):
    """
    Check whether we can run encryption. Currently this requires pycrypto with
    no other implementation supported. Unless you pass in ``recheck=True``,
    this function will use the check made at import time. However, by giving
    ``recheck=True`` you can actually make it update that configuration, so in
    case pycrypto becomes available later, just call this once after you have
    made it available and pass in the ``recheck=True`` setting.
    """
    if recheck:
        conf["encryption_available"] = _check_encryption_available()
    return conf["encryption_available"]


def encrypt_then_authenticate(data, enc_key, hmac_key, hashalg):
    """
    Encrypt and sign a given piece of data with the given keys.

    Args:
        ``data``: A plain data string to secure.

        ``enc_key``: A 32 byte encryption key

        ``hmac_key``: A byte string hmac key for signature.

        ``hashalg``: A hash algorithm to use, e.g. :class:`hashlib.sha256`

    Returns:
        Tuple of ``(ciphertext, tag)`` where tag is the ``hexdigest()`` output.
    """
    from Crypto.Cipher import AES
    if not encryption_available():
        raise CryptoError("pycrypto is not available.")
    from Crypto.Util import Counter
    if isinstance(data, unicode):
        data = data.encode('utf-8')

    if isinstance(enc_key, unicode):
        raise TypeError("The encryption key must be a **byte** string not "
                        "unicode.")
    if isinstance(hmac_key, unicode):
        raise TypeError("The hmac key must be a **byte** string not unicode.")

    ctr = Counter.new(128)  # Length is half of the block size in bits
    cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(data)
    tag = hmac.new(hmac_key, ciphertext, hashalg)

    return ciphertext, tag.hexdigest().decode("ascii")


def decrypt_authenticated(ciphertext, tag, enc_key, hmac_key, hashalg):
    """
    This decrypts an authenticated ciphertext. It raises an exception if either
    the decryption fails or the ciphertext could not be authenticated.

    It is the inverse of :func:`encrypt_then_authenticate`

    Args:
        ``ciphertext``: A byte string ciphertext

        ``tag``: A byte string hmac, the output of :func:`hmac.HMAC.digest`.

        ``enc_key``: A 32 byte encryption key

        ``hmac_key``: A byte string hmac_key for signature.

        ``hashalg``: A hash algorithm to use, e.g. :class:`hashlib.sha256`

    Returns:
        The plain text

    Raises:
        :exc:`ValueError` when authentication fails or no plaintext could be
        decrypted.
    """
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    reference_tag = hmac.new(hmac_key, ciphertext, hashalg).hexdigest()
    if not compare_constant_time(reference_tag, tag):
        raise ValueError("Signature does not match, invalid ciphertext")

    cipher = AES.new(enc_key, AES.MODE_CTR, counter=Counter.new(128))
    plaintext = cipher.decrypt(ciphertext)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Could not retrieve plaintext back properly")
