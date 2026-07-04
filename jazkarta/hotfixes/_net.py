# -*- coding: utf-8 -*-
"""Shared URL validation and size/timeout limited download helpers.

These are backported (and lightly adapted) from the fixed Plone 6.x releases of
``plone.app.portlets`` (7.0.2) and ``plone.app.event`` (6.0.1), where the same
logic lives in ``rss.py`` and ``ical/importer.py`` respectively.

They are the building blocks for closing three classes of problem in any place
where the Plone server itself makes an outgoing request on behalf of a user:

* **DoS** -- an attacker points us at a multi-gigabyte file. We cap the number
  of bytes we read and add a short timeout.
* **SSRF** -- an attacker points us at ``http://169.254.169.254/`` or an
  internal host. We reject IP addresses, dot-less hostnames (``localhost``),
  host:port forms, and refuse to follow redirects (which could otherwise
  bounce us from an allowed host to an internal one).
* **Stored XSS** -- an attacker stores a ``javascript:`` (or ``file:``) URL that
  is later rendered as a link. ``normal_url_validator`` rejects anything that
  is not a plain ``http(s)`` URL.
"""

from html import unescape
from logging import getLogger
from urllib.parse import urlsplit
from zope.interface import Invalid

import os
import requests


logger = getLogger("jazkarta.hotfixes")


# Try downloading at most this many bytes. Overridable via the environment so
# operators can tune without editing code.
MAXIMUM_RSS_FEED_SIZE_BYTES = int(
    os.getenv("MAXIMUM_RSS_FEED_SIZE_BYTES", 1000000)
)
MAXIMUM_ICAL_IMPORT_SIZE_BYTES = int(
    os.getenv("MAXIMUM_ICAL_IMPORT_SIZE_BYTES", 500000)
)
# Allow importing at most this many events from a single icalendar resource.
# Default: one year of weekly events. Even a small file can expand to thousands
# of events, so this guards against resource exhaustion during import.
MAXIMUM_ICAL_IMPORT_EVENTS = int(
    os.getenv("MAXIMUM_ICAL_IMPORT_EVENTS", 366)
)

# A connect+read timeout of slightly more than 3 seconds is recommended by the
# requests documentation, so a dropped SYN/ACK gets one retry within the window.
DOWNLOAD_TIMEOUT = float(os.getenv("MTNEERS_DOWNLOAD_TIMEOUT", 3.5))


class TooManyEventsToImport(ValueError):
    """Raised when an icalendar resource contains more events than allowed."""

    def __init__(self, count, limit):
        super().__init__(count, limit)
        self.count = count
        self.limit = limit

    def __str__(self):
        return "Too many events to import: {0} > {1}".format(self.count, self.limit)


def normal_url_validator(value):
    """Validate that ``value`` is a 'normal', external, clickable url.

    It should be safe for a visitor to click on. Of course it could still lead
    to a malicious site: we have no way of checking that. But at least it must
    be no ``javascript:`` url, ``file:`` url, etc.

    Returns ``True`` if the value is good to be used unchanged, otherwise raises
    ``zope.interface.Invalid``. This is deliberately strict: for example a value
    with a leading space is rejected rather than silently stripped.
    """
    if not value:
        # nothing to validate
        return True
    if value != value.strip():
        raise Invalid("URL not accepted")
    if len(value.splitlines()) > 1:
        raise Invalid("URL not accepted")

    # lowercase for easier checking
    url = value.lower()
    parsed = urlsplit(url)
    scheme = parsed.scheme
    domain = parsed.netloc
    if not scheme:
        # We don't support relative urls, and we don't need to support
        # //example.org
        raise Invalid("URL not accepted")
    if scheme not in ("https", "http"):
        raise Invalid("URL not accepted")
    if not domain:
        # Example: https:example.org
        # When we redirect to this, some browsers fail, others happily go to
        # example.org.
        raise Invalid("URL not accepted")

    # Someone may be doing tricks with escaped html code.
    unescaped_url = unescape(url)
    if unescaped_url != url:
        # Check the unescaped url, then continue checking the current url.
        normal_url_validator(unescaped_url)

    return True


def strict_url_validator(value):
    """Validator for urls that the Plone server itself will fetch.

    Stricter than :func:`normal_url_validator`: on top of the basic checks we
    refuse IP addresses, host:port forms, and dot-less hostnames such as
    ``localhost`` or ``backend``. This makes it much harder to abuse the server
    as a port scanner or to reach internal-only services (SSRF).
    """
    if not value:
        # nothing to validate
        return True
    # lowercase for easier checking
    url = value.lower()

    # The normal url validator already does the basic checks.
    normal_url_validator(url)

    # We want to go further than that.
    domain = urlsplit(url).netloc

    # We don't want to be used as a port checker.
    if ":" in domain:
        raise Invalid("URL not accepted")

    # We don't want to allow an external visitor to indirectly request content
    # from localhost, or similar, like a backend.
    if "." not in domain:
        raise Invalid("URL not accepted")
    if "host.docker.internal" in domain:
        raise Invalid("URL not accepted")

    # Only proper domain names, not IP addresses. We don't want to allow access
    # to private IP addresses. Rather than enumerate the private ranges, we
    # simply refuse anything that looks like a dotted-quad of integers.
    try:
        [int(part) for part in domain.split(".")]
    except ValueError:
        # At least one part is not an integer: looks like a real hostname.
        pass
    else:
        # All parts are integers: an IP address. Refuse.
        raise Invalid("URL not accepted")

    # Someone may be doing tricks with escaped html code.
    unescaped_url = unescape(url)
    if unescaped_url != url:
        strict_url_validator(unescaped_url)

    return True


def download_limited(url, limit, headers=None):
    """Download ``url``, reading at most ``limit`` bytes, with a short timeout.

    The url is trusted: callers should already have validated it with
    :func:`strict_url_validator`. We do not follow redirects, because a redirect
    could otherwise bounce a validated public url to an internal one.

    Returns a ``(contents, response)`` tuple. ``contents`` is ``b""`` for a 304
    Not Modified response. May raise exceptions from the requests library, or
    its own ``ValueError`` if the response is too large; the caller should
    catch and handle these.
    """
    if limit <= 0:
        raise ValueError("You must pass a positive byte limit.")
    response = requests.get(
        url,
        stream=True,
        allow_redirects=False,
        timeout=DOWNLOAD_TIMEOUT,
        headers=headers or {},
    )
    response.raise_for_status()
    if response.status_code == 304:
        # not modified
        return b"", response

    # Check the content length header, if the server sent one.
    length = response.headers.get("Content-Length")
    if length and int(length) > limit:
        raise ValueError("Content-Length header too large")

    # Read at most ``limit + 1`` bytes. Using a chunk size of ``limit + 1`` means
    # a well-sized body arrives in a single chunk (<= limit, returned as-is),
    # while an oversized body trips the guard on the first chunk. Internally this
    # may use multiple chunked reads.
    chunk = b""
    for chunk in response.iter_content(limit + 1):
        if len(chunk) > limit:
            raise ValueError("Downloaded too much content.")
    return chunk, response
