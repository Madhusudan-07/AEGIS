"""Security modules. Each is independently toggleable and replaceable (Requirement B).

Pipeline-gating modules raise :class:`~aegis.core.exceptions.SecurityViolation` from
``process_request`` to deny. Service/boot modules mostly implement ``self_check`` and
expose helpers used elsewhere. The canonical execution order is defined in
:func:`aegis.core.engine.build_modules`.
"""
