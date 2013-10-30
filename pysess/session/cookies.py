# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import Cookie
from pysess.crypto import authenticate_data, get_hash_length, verify_data, \
    decrypt_authenticated, encrypt_then_authenticate
import logging
import base64

log = logging.getLogger(__name__)


class SignedCookie(Cookie.BaseCookie):

    def __init__(self, serializer, signature_key, hashalg, *args, **kwargs):
        self.sig_key = signature_key
        self.hashalg = hashalg
        self.serializer = serializer
        Cookie.BaseCookie.__init__(self, *args, **kwargs)

    def value_decode(self, val):
        log.debug("Got value to decode: %s" % val)
        encoded_data = val
        val = base64.b64decode(val.strip('"'))
        hashlength = get_hash_length(self.hashalg) / 4
        sig, data = val[:hashlength], val[hashlength:]
        if verify_data(data, sig, self.sig_key, self.hashalg):
            return self.serializer.loads(data), encoded_data

    def value_encode(self, val):
        orig_val = val
        val = self.serializer.dumps(val)
        sig = authenticate_data(val, self.sig_key, self.hashalg)
        return orig_val, base64.b64encode(b"{0}{1}".format(sig, val))


class EncryptedCookie(SignedCookie):

    def __init__(self, serializer, signature_key, hashalg, enc_key, *args,
                 **kwargs):
        self.enc_key = enc_key
        SignedCookie.__init__(self, serializer, signature_key, hashalg,
                              *args, **kwargs)

    def value_decode(self, val):
        encoded_data = val
        val = base64.b64decode(val.strip('"'))
        hashlength = get_hash_length(self.hashalg) / 4
        sig, ciphertext = val[:hashlength], val[hashlength:]
        data = decrypt_authenticated(ciphertext, sig, self.enc_key,
                                     self.sig_key, self.hashalg)
        return self.serializer.loads(data), encoded_data

    def value_encode(self, val):
        orig_val = val
        val = self.serializer.dumps(val)
        ciphertext, sig = encrypt_then_authenticate(val, self.enc_key,
                                                    self.sig_key, self.hashalg)
        return orig_val, base64.b64encode(b"{0}{1}".format(sig, ciphertext))
