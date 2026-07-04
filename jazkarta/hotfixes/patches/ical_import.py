# -*- coding: utf-8 -*-
"""Backport of GHSA-r82h-mqw3-fc56 / CVE-2026-55247 (CVSS 9.1).

For plone.app.event 3.2.x. The icalendar import feature lets a user with the
"Import Ical" permission fetch an external url::

    ical_resource = urllib.request.urlopen(ical_url).read()

guarded only against ``file:`` urls, then imports every VEVENT it contains and
stores each event's ``URL`` property verbatim as ``event_url``. This allows:

* **DoS** -- an enormous file exhausts memory, or a small file expands into
  thousands of events,
* **SSRF** -- the url can point at an internal host / IP / port, and
* **Stored XSS** -- a ``javascript:`` URL property is stored and later rendered
  as a link.

The fix (from plone.app.event 6.0.1) applies, adapted to the 3.2.x code:

* validate the import url with the strict (anti-SSRF) validator, as the
  ``ical_url`` field constraint and again before fetching,
* download with a byte cap, a timeout and redirects disabled (so a redirect
  cannot bounce a validated url to an internal one),
* cap the number of events imported from a single resource, and
* validate ``event_url`` -- as a field constraint (edit form) and inside the
  accessor's ``__setattr__`` (which is what the importer uses), dropping any
  value that is not a plain ``http(s)`` url.
"""

from logging import getLogger


logger = getLogger("jazkarta.hotfixes")


def apply():
    from zope.interface import Invalid

    from plone.app.event import _
    from plone.app.event.ical import importer
    from plone.app.event.dx import behaviors
    from Products.statusmessages.interfaces import IStatusMessage

    from jazkarta.hotfixes._net import (
        MAXIMUM_ICAL_IMPORT_EVENTS,
        MAXIMUM_ICAL_IMPORT_SIZE_BYTES,
        TooManyEventsToImport,
        download_limited,
        normal_url_validator,
        strict_url_validator,
    )

    # ------------------------------------------------------------------ #
    # 1. Anti-SSRF validation of the import url (settings + edit form).
    # ------------------------------------------------------------------ #
    importer.no_file_protocol_url = strict_url_validator
    importer.IIcalendarImportSettings["ical_url"].constraint = strict_url_validator

    # ------------------------------------------------------------------ #
    # 2. event_url stored-XSS: reject non-http(s) urls on the edit form ...
    # ------------------------------------------------------------------ #
    behaviors.IEventContact["event_url"].constraint = normal_url_validator

    # ... and on every accessor assignment, which is the path the importer
    #     itself uses (``event.event_url = url``). We drop (rather than raise on)
    #     an unsafe value so a single bad event does not abort a whole import.
    _orig_setattr = behaviors.EventAccessor.__setattr__

    def _safe_setattr(self, name, value):
        if name == "event_url" and value:
            try:
                normal_url_validator(value)
            except Invalid:
                logger.warning("Dropping unsafe event_url %r", value)
                value = None
        return _orig_setattr(self, name, value)

    behaviors.EventAccessor.__setattr__ = _safe_setattr

    # ------------------------------------------------------------------ #
    # 3. Cap the number of events per imported resource (DoS). Wraps the
    #    original ical_import so we do not have to reimplement its body.
    # ------------------------------------------------------------------ #
    _orig_ical_import = importer.ical_import

    def _safe_ical_import(
        container,
        ics_resource,
        event_type,
        sync_strategy=importer.base.SYNC_KEEP_NEWER,
        limit=MAXIMUM_ICAL_IMPORT_EVENTS,
    ):
        if limit and limit > 0:
            # Even a fairly small file could generate thousands of events.
            cal = importer.icalendar.Calendar.from_ical(ics_resource)
            count = len(cal.walk("VEVENT"))
            if count > limit:
                raise TooManyEventsToImport(count, limit)
        return _orig_ical_import(
            container, ics_resource, event_type, sync_strategy
        )

    importer.ical_import = _safe_ical_import

    # ------------------------------------------------------------------ #
    # 4. Fetch the url safely (size cap, timeout, no redirects) and surface
    #    friendly errors. Replaces the "Save and Import" button handler.
    # ------------------------------------------------------------------ #
    def _handle_save_import(self, action):
        data, errors = self.extractData()
        if errors:
            return False
        self.save_data(data)

        ical_file = data["ical_file"]
        ical_url = data["ical_url"]
        event_type = data["event_type"]
        sync_strategy = data["sync_strategy"]

        if not (ical_file or ical_url):
            IStatusMessage(self.request).addStatusMessage(
                _(
                    "ical_import_no_ics",
                    default="Please provide either a icalendar ics file or a "
                    "URL to a file.",
                ),
                "error",
            )
            self.request.response.redirect(self.context.absolute_url())
            return

        if ical_file:
            # File upload is not saved in settings.
            ical_resource = ical_file.data
            ical_import_from = ical_file.filename
        else:
            ical_import_from = ical_url
            try:
                # Defense in depth: the field constraint already validated this,
                # but re-check before we make the outgoing request.
                strict_url_validator(ical_url)
                ical_resource, _response = download_limited(
                    ical_url, MAXIMUM_ICAL_IMPORT_SIZE_BYTES
                )
            except Exception:
                logger.exception("Failed downloading ical url %s", ical_url)
                IStatusMessage(self.request).addStatusMessage(
                    _(
                        "ical_import_download_error",
                        default="Failed downloading Icalendar URL. Probably a "
                        "timeout, too large, or a disallowed address.",
                    ),
                    "error",
                )
                self.request.response.redirect(self.context.absolute_url())
                return

        try:
            import_metadata = importer.ical_import(
                self.context,
                ics_resource=ical_resource,
                event_type=event_type,
                sync_strategy=sync_strategy,
                limit=MAXIMUM_ICAL_IMPORT_EVENTS,
            )
        except TooManyEventsToImport:
            logger.exception(
                "Refused to import ical with too many events: %s",
                ical_import_from,
            )
            IStatusMessage(self.request).addStatusMessage(
                _(
                    "ical_import_too_many_events",
                    default="Refused to import icalendar with too many events.",
                ),
                "error",
            )
            self.request.response.redirect(self.context.absolute_url())
            return

        count = import_metadata["count"]
        IStatusMessage(self.request).addStatusMessage(
            _(
                "ical_import_imported",
                default="${num} events imported from ${filename}",
                mapping={"num": count, "filename": ical_import_from},
            ),
            "info",
        )
        self.request.response.redirect(self.context.absolute_url())

    form_cls = importer.IcalendarImportSettingsForm
    swapped = False
    for _button, hdlr in form_cls.handlers._handlers:
        func = getattr(hdlr, "func", None)
        if func is not None and getattr(func, "__name__", "") == "handleSaveImport":
            hdlr.func = _handle_save_import
            swapped = True
    if not swapped:
        logger.error(
            "jazkarta.hotfixes: could not locate the ical "
            "'Save and Import' handler; the download DoS/SSRF fix is NOT active!"
        )

    logger.info(
        "Applied icalendar import DoS/SSRF/XSS patch "
        "(GHSA-r82h-mqw3-fc56 / CVE-2026-55247) to plone.app.event."
    )
