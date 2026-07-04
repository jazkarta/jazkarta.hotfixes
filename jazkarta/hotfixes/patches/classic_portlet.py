# -*- coding: utf-8 -*-
"""Backport of GHSA-rr49-f9g6-c9r5 (CVSS 9.9) for plone.app.portlets 4.4.x.

The Classic portlet builds a TALES *path* expression from the user-supplied
``template`` and ``macro`` fields::

    expr = 'context/%s' % self.data.template          # + '/macros/%s' % macro

and the template renders it with ``python:path(path_expression)``. Because the
fields are never validated, an authenticated user who can add/edit a Classic
portlet can inject a full TALES expression (e.g. containing ``python:`` or the
``|`` fallback operator) and achieve remote code execution.

The fix (from plone.app.portlets 7.0.2) is to restrict the two fields to plain
traversal steps -- letters, digits and ``_ @ . - /`` only -- which can never
introduce a TALES expression type or the ``|`` operator. We apply the check in
two places:

* as a schema ``constraint`` on the fields, so the add/edit forms reject bad
  input with a friendly error, and
* again inside ``path_expression`` at render time, so that assignments created
  by other means (GenericSetup import, scripts, or pre-existing malicious
  assignments already in the database) are also refused -- they now raise
  rather than execute.
"""

from logging import getLogger

import re


logger = getLogger("jazkarta.hotfixes")

# Legitimate Classic-portlet template/macro names are plain traversal steps
# (e.g. "portlet_recent", "@@view", "content-core"). They must never contain
# TALES metacharacters such as "|" or ":" (python:/string:), whitespace or
# parentheses, which would otherwise allow a TALES expression injection.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_@.\-/]*$")


def _import_validation_error():
    # Imported lazily so this module stays importable without a full Zope stack.
    from zope.schema import ValidationError

    class InvalidTALESName(ValidationError):
        __doc__ = "Only letters, digits and the characters _ @ . - / are allowed."

    return InvalidTALESName


def valid_name(value):
    """Raise if ``value`` is not a safe, plain traversal name."""
    if value and not _SAFE_NAME.match(value):
        raise _import_validation_error()(value)
    return True


def apply():
    from plone.app.portlets.portlets import classic

    # 1. Reject unsafe names in the add/edit forms.
    classic.IClassicPortlet["template"].constraint = valid_name
    classic.IClassicPortlet["macro"].constraint = valid_name

    # 2. Defense in depth: validate again when the expression is actually built,
    #    so programmatic / pre-existing assignments cannot reach ``path()``.
    def path_expression(self):
        valid_name(self.data.template)
        valid_name(self.data.macro)
        expr = "context/%s" % self.data.template
        if self.use_macro():
            expr += "/macros/%s" % self.data.macro
        return expr

    path_expression.__doc__ = (
        "Patched by jazkarta.hotfixes: validates template/macro against a "
        "strict whitelist before building the TALES path expression."
    )
    classic.Renderer.path_expression = path_expression

    logger.info(
        "Applied Classic portlet TALES-injection patch "
        "(GHSA-rr49-f9g6-c9r5) to plone.app.portlets."
    )
