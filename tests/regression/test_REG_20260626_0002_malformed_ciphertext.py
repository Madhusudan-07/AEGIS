"""Regression REG-20260626-0002 — malformed field ciphertext must fail closed.

Found by the property-based fuzz surface (tests/fuzz): a value with the AEGIS envelope
prefix but invalid base64 (e.g. ``aegis1:!!!``) previously raised binascii.Error instead
of failing closed. Decryption MUST raise CryptoError for any malformed/tampered input.
Threat: STRIDE T1 (Tampering) / OWASP A02 (Cryptographic Failures).
"""
from __future__ import annotations

import pytest

from aegis.core.crypto import FieldCipher, generate_field_key
from aegis.core.exceptions import CryptoError


@pytest.mark.parametrize("bad", ["aegis1:!!!", "aegis1:", "aegis1:zzz", "aegis1:____", "not-a-ciphertext"])
def test_reg_20260626_0002_malformed_ciphertext_fails_closed(bad):
    cipher = FieldCipher(generate_field_key())
    with pytest.raises(CryptoError):
        cipher.decrypt(bad)
