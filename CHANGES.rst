Changelog
=========

1.0 (unreleased)
----------------

- Document building Pillow and pi-heif from source against the OS libraries
  with a pip step that runs before buildout installs eggs.

- Fix the Pillow 13.0.0 advisories that reach Pillow 9.5.0 through uploaded
  images: a format allowlist (``HOTFIXES_PILLOW_FORMATS``) that admits WebP
  and HEIF by default only when Pillow and pi-heif link the OS libraries, MPO
  opened as JPEG, lossless JPEGs refused, JPEG comments written safely after a large ICC
  profile, the APNG canvas bomb check, and a cap on GIF comments. Adds
  ``HOTFIXES_PILLOW_MAX_IMAGE_PIXELS``.

- Backport GHSA-vhwp-qc29-j4xp -- users/groups disclosure through the
  ``@vocabularies`` endpoint (plone.app.content). ``Groups`` and ``Principals``
  require ``List portal members``.

- The limited download helper accumulates chunks against a total byte cap
  instead of upstream's single-chunk read, which on the urllib3 1.26.x used
  with Plone 5.2 silently truncates chunked transfer-encoded responses.

- Initial release. Backports for:

  - GHSA-rr49-f9g6-c9r5 -- Classic portlet TALES injection (plone.app.portlets).
  - GHSA-x5g3-w747-2h8q -- RSS portlet DoS/SSRF/XSS (plone.app.portlets).
  - GHSA-r82h-mqw3-fc56 / CVE-2026-55247 -- icalendar import DoS/SSRF/XSS
    (plone.app.event).
