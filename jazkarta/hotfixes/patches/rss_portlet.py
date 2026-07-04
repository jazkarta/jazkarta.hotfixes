# -*- coding: utf-8 -*-
"""Backport of GHSA-x5g3-w747-2h8q (CVSS 9.1) for plone.app.portlets 4.4.x.

The RSS portlet fetches an arbitrary feed url and renders its items. In 4.4.x
the only checks are that the url is single-line and ``http(s)``; there is no
size limit, no timeout, no redirect control and no SSRF protection, and feed
item links are rendered without scheme validation. This allows:

* **DoS** -- linking a very large file exhausts memory,
* **SSRF** -- pointing the feed url at an internal host / IP / port, and
* **Stored XSS** -- a ``javascript:`` url in a feed item's link.

The fix (from plone.app.portlets 7.0.2):

* validate the stored feed url with the strict (anti-SSRF) validator, both as a
  field ``constraint`` and again at fetch time,
* download the feed ourselves with a byte cap, a timeout, and redirects
  disabled, then hand the *bytes* to feedparser (instead of letting feedparser
  fetch the url), and
* validate each feed item link, replacing anything that is not a plain
  ``http(s)`` url with ``"#"``.
"""

from logging import getLogger


logger = getLogger("jazkarta.hotfixes")


def apply():
    from io import BytesIO
    import time

    from DateTime import DateTime
    from DateTime.interfaces import DateTimeError
    from zope.interface import Invalid

    from plone.app.portlets.portlets import rss as rss_module

    from jazkarta.hotfixes._net import (
        MAXIMUM_RSS_FEED_SIZE_BYTES,
        download_limited,
        normal_url_validator,
        strict_url_validator,
    )

    ACCEPTED = rss_module.ACCEPTED_FEEDPARSER_EXCEPTIONS
    feedparser = rss_module.feedparser

    # 1. Reject unsafe feed urls in the add/edit forms.
    rss_module.IRSSPortlet["url"].constraint = strict_url_validator

    # 2. Sanitize each feed item's link (stored XSS).
    def _buildItemDict(self, item):
        link = item.links[0]["href"]
        try:
            normal_url_validator(link)
        except Invalid:
            # We don't want JavaScript (or file:) links in here.
            logger.warning("Refusing to use link from RSS item %r", link)
            link = "#"
        itemdict = {
            "title": item.title,
            "url": link,
            "summary": item.get("description", ""),
        }
        if hasattr(item, "updated"):
            try:
                itemdict["updated"] = DateTime(item.updated)
            except DateTimeError:
                # It's okay to drop it because in the template this is checked
                # with ``exists:``.
                pass
        return itemdict

    # 3. Download the feed safely (size cap, timeout, no redirects), validating
    #    the stored url again at fetch time.
    def _retrieveFeed(self):
        url = self.url
        if url:
            try:
                strict_url_validator(url)
            except Invalid:
                logger.warning("Refusing to load stored RSS url %r", url)
                url = ""
        if url != "":
            self._last_update_time_in_minutes = time.time() / 60
            self._last_update_time = DateTime()
            headers = {}
            last_modified = getattr(self, "_last_modified", None) or getattr(
                self, "_modified", None
            )
            if last_modified:
                headers["If-Modified-Since"] = last_modified
            if self._etag:
                headers["If-None-Match"] = self._etag
            try:
                contents, response = download_limited(
                    url, MAXIMUM_RSS_FEED_SIZE_BYTES, headers=headers
                )
            except Exception as exc:
                self._loaded = True
                self._failed = True
                logger.info("failed to download RSS feed %s: %s", url, exc)
                return False

            # If the response was 304, nothing changed: don't reparse.
            if response.status_code != 304:
                download = BytesIO(contents)
                # feedparser resolves relative urls from Content-Location and
                # needs Content-Type; pass all response headers, lowercased per
                # RFC 2616, which is what feedparser does when it loads a url.
                response_headers = {
                    k.lower(): v for k, v in response.headers.items()
                }
                d = feedparser.parse(download, response_headers=response_headers)
                if getattr(d, "bozo", 0) == 1 and not isinstance(
                    d.get("bozo_exception"), ACCEPTED
                ):
                    self._loaded = True
                    self._failed = True
                    logger.info(
                        "failed to update RSS feed %s",
                        d.get("bozo_exception", None),
                    )
                    return False

                self._etag = response.headers.get("etag", None)
                self._last_modified = response.headers.get("last-modified", None)

                try:
                    self._title = d.feed.title
                except AttributeError:
                    self._title = ""
                try:
                    self._siteurl = d.feed.link
                except AttributeError:
                    self._siteurl = ""

                self._items = []
                for item in d["items"]:
                    try:
                        itemdict = self._buildItemDict(item)
                    except AttributeError:
                        continue
                    self._items.append(itemdict)

            self._loaded = True
            self._failed = False
            return True
        self._loaded = True
        self._failed = True  # no url set means failed
        return False

    rss_module.RSSFeed._buildItemDict = _buildItemDict
    rss_module.RSSFeed._retrieveFeed = _retrieveFeed

    logger.info(
        "Applied RSS portlet DoS/SSRF/XSS patch "
        "(GHSA-x5g3-w747-2h8q) to plone.app.portlets."
    )
