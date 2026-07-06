Changelog
=========

1.0 (unreleased)
----------------

- The limited download helper accumulates chunks against a total byte cap
  instead of upstream's single-chunk read, which on the urllib3 1.26.x used
  with Plone 5.2 silently truncates chunked transfer-encoded responses.

- Initial release. Backports for:

  - GHSA-rr49-f9g6-c9r5 -- Classic portlet TALES injection (plone.app.portlets).
  - GHSA-x5g3-w747-2h8q -- RSS portlet DoS/SSRF/XSS (plone.app.portlets).
  - GHSA-r82h-mqw3-fc56 / CVE-2026-55247 -- icalendar import DoS/SSRF/XSS
    (plone.app.event).
