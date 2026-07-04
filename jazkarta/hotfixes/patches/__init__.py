# -*- coding: utf-8 -*-
"""Apply all security monkeypatches, once, with clear logging."""

from logging import getLogger


logger = getLogger("jazkarta.hotfixes")

# (module, human label) pairs. Order is not significant; each is independent.
_PATCHES = (
    ("classic_portlet", "Classic portlet TALES injection (GHSA-rr49-f9g6-c9r5)"),
    ("rss_portlet", "RSS portlet DoS/SSRF/XSS (GHSA-x5g3-w747-2h8q)"),
    ("ical_import", "icalendar import DoS/SSRF/XSS (GHSA-r82h-mqw3-fc56)"),
)

_applied = False


def _log_target_versions():
    import pkg_resources

    # These are the last releases of the Plone 5.2 lines, and are the versions
    # these patches were written against. Anything else should be looked at.
    expected = {"plone.app.portlets": "4.4.8", "plone.app.event": "3.2.14"}
    for dist, want in expected.items():
        try:
            have = pkg_resources.get_distribution(dist).version
        except Exception:
            continue
        if have == want:
            logger.info("jazkarta.hotfixes: %s %s (expected).", dist, have)
        else:
            logger.warning(
                "jazkarta.hotfixes: %s is %s, patches were written for "
                "%s. Review the patches before trusting them.",
                dist,
                have,
                want,
            )


def apply_all():
    """Import and apply every patch. Idempotent; safe to call more than once."""
    global _applied
    if _applied:
        return
    _applied = True

    _log_target_versions()

    from importlib import import_module

    failures = []
    for name, label in _PATCHES:
        try:
            module = import_module("jazkarta.hotfixes.patches." + name)
            module.apply()
        except Exception:
            # A security patch that silently fails is worse than useless, so log
            # loudly -- but do not prevent the site from starting.
            logger.exception(
                "jazkarta.hotfixes: FAILED to apply patch for %s", label
            )
            failures.append(label)

    if failures:
        logger.error(
            "jazkarta.hotfixes: %d of %d patches did NOT apply: %s",
            len(failures),
            len(_PATCHES),
            "; ".join(failures),
        )
    else:
        logger.info(
            "jazkarta.hotfixes: all %d security patches applied.",
            len(_PATCHES),
        )
