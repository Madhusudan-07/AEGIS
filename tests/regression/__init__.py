"""Append-only regression corpus.

Every confirmed vulnerability becomes a PERMANENT test here, committed BEFORE its fix
(spec §3). Files in this directory are immutable once locked in
``security/ratchet/corpus.lock.json`` — the ratchet guard (Subsystem C) fails any PR
that deletes or alters a locked regression test, unless a human applies the
``security-override-approved`` label. Add entries only via
``python security/ratchet/update_corpus.py``.

Naming: ``test_REG_<YYYYMMDD>_<NNNN>_<slug>.py`` with one ``test_reg_...`` function.
"""
