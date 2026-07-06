=================
jazkarta.hotfixes
=================

Runtime monkeypatch backports of three Plone security advisories to the
end-of-life Plone 5.2 package lines, for which the Plone security team shipped
**no** fixed release (the fixes only exist on the Plone 6.x lines).

This package targets:

============================  ===================  ===========================
Package                       Version on 5.2       Fix backported from
============================  ===================  ===========================
``plone.app.portlets``        ``4.4.8``/``4.4.9``  ``7.0.2`` (Plone 6.2)
``plone.app.event``           ``3.2.14``           ``6.0.1`` (Plone 6.2)
============================  ===================  ===========================

These are the last releases of their respective lines (``4.4.9`` differs from
``4.4.8`` only in an unrelated template), so the source the patches are written
against is frozen and will not drift.

Advisories addressed
====================

1. **GHSA-rr49-f9g6-c9r5** (CVSS 9.9) -- TALES injection / remote code
   execution in the **Classic portlet**. The ``template``/``macro`` fields are
   now restricted to plain traversal names (letters, digits, ``_ @ . - /``),
   validated both on the add/edit forms and again at render time, so existing
   malicious assignments are refused instead of executed.

2. **GHSA-x5g3-w747-2h8q** (CVSS 9.1) -- DoS / SSRF / stored XSS in the **RSS
   portlet**. The feed url is validated against an anti-SSRF allowlist, the feed
   is downloaded with a byte cap, a timeout and redirects disabled, and each
   feed item link is validated (``javascript:`` links become ``#``).

3. **GHSA-r82h-mqw3-fc56 / CVE-2026-55247** (CVSS 9.1) -- DoS / SSRF / stored
   XSS in the **icalendar import**. The import url is validated against the same
   anti-SSRF allowlist, downloaded with a byte cap / timeout / no redirects, the
   number of imported events is capped, and each event's ``event_url`` is
   validated before storage.

How it works
============

Importing the package applies the patches as a side effect. The package
declares the ``z3c.autoinclude`` ``plone`` plugin, so simply having the egg on
the Zope instance causes it to be imported at startup -- no ZCML slug or profile
is required.

On startup it logs (logger name ``jazkarta.hotfixes``), e.g.::

    jazkarta.hotfixes: plone.app.portlets 4.4.8 (expected).
    jazkarta.hotfixes: plone.app.event 3.2.14 (expected).
    Applied Classic portlet TALES-injection patch ...
    Applied RSS portlet DoS/SSRF/XSS patch ...
    Applied icalendar import DoS/SSRF/XSS patch ...
    jazkarta.hotfixes: all 3 security patches applied.

If a target package is a different version than expected, or a patch fails to
apply, it logs a ``WARNING``/``ERROR`` (the site still starts). **Check the log
after deploying** to confirm all three patches applied.

Installation
============

Add ``jazkarta.hotfixes`` to the ``eggs`` of the instance part of your
buildout (or to the ``install_requires`` of a policy egg that is already
installed on the instance), then rerun buildout and restart Zope.

To track this repository as a development source with ``mr.developer``, add to
your sources config::

    [sources]
    jazkarta.hotfixes = git git@github.com:jazkarta/jazkarta.hotfixes.git

Tunables (environment variables)
================================

============================================  =========  ==================================
Variable                                      Default    Effect
============================================  =========  ==================================
``MAXIMUM_RSS_FEED_SIZE_BYTES``               1000000    Max bytes read per RSS feed
``MAXIMUM_ICAL_IMPORT_SIZE_BYTES``            500000     Max bytes read per ical url
``MAXIMUM_ICAL_IMPORT_EVENTS``                366        Max events per ical resource
``HOTFIXES_DOWNLOAD_TIMEOUT``                 3.5        Connect+read timeout (seconds)
============================================  =========  ==================================

Removing the patches
====================

These become unnecessary the moment the site is migrated to a Plone version
whose ``plone.app.portlets`` / ``plone.app.event`` already contains the fixes
(portlets >= 5.0.8, event >= 5.2.4). At that point remove the egg. The startup
version check will warn if the underlying packages move off 4.4.8/4.4.9 /
3.2.14, which is your signal to re-review or retire this package.
