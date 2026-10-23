# -*- coding: utf-8 -*-
"""Backport of GHSA-vhwp-qc29-j4xp for plone.app.content 3.8.x.

plone.restapi's ``@vocabularies`` endpoint protects each vocabulary with the
permission listed for it in ``plone.app.content.browser.vocabulary.PERMISSIONS``
and falls back to ``View`` for anything not listed. ``plone.app.vocabularies``
``Groups`` and ``Principals`` are not listed, so anonymous users can list every
user id, full name and group on the site, e.g.::

    GET /@vocabularies/plone.app.vocabularies.Principals
    Accept: application/json

The endpoint is registered for the default browser layer, so this applies
whenever plone.restapi's ZCML is loaded, whether or not its add-on profile is
installed.

The fix (from plone.app.content 4.2.1 / 5.0.1) maps both vocabularies to
``List portal members``, which the Member role has by default. Upstream also
moves ``Users`` to that permission; here ``Users`` stays at ``Modify portal
content``. That doesn't keep users hidden from Members, because ``Principals``
searches users as well as groups.

The same dict gates ``@@getVocabulary``. On a navigation root it now serves
both vocabularies, including ``query`` searches, to anyone with ``List portal
members``; before, it refused them unless a ``field`` permission check passed.
On other contexts with no field permission checker, it now checks ``List
portal members`` instead of ``View``. Upstream behaves the same way.
"""

from logging import getLogger


logger = getLogger("jazkarta.hotfixes")

_PERMISSION = "List portal members"
_VOCABULARIES = (
    "plone.app.vocabularies.Groups",
    "plone.app.vocabularies.Principals",
)


def apply():
    from plone.app.content.browser import vocabulary

    # plone.restapi imports this dict by reference, so mutate it in place.
    for name in _VOCABULARIES:
        vocabulary.PERMISSIONS[name] = _PERMISSION

    logger.info(
        "Applied principal vocabularies permission patch "
        "(GHSA-vhwp-qc29-j4xp) to plone.app.content: %s now require %r.",
        ", ".join(_VOCABULARIES),
        _PERMISSION,
    )
