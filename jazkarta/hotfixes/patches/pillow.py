# -*- coding: utf-8 -*-
"""Pillow 9.5.0 fixes for the Pillow 13.0.0 advisories that reach a Plone site.

The fixes only exist in Pillow 13, which doesn't support Python 3.8. A source
build (see the README) covers the advisories in the libraries the wheels
bundle. This module covers the bugs in Pillow's own code that uploaded images
can reach:

* **Format allowlist.** Only the formats in ``HOTFIXES_PILLOW_FORMATS`` can be
  opened. That excludes the BMP, MSP and XBM decoders and the TIFF decode leaks
  (GHSA-24rc-8hj2-v98c, GHSA-gg2r-wvfm-q9rx, GHSA-xgh8-jp6q-p5x8,
  GHSA-c6hw-5grf-ff96, GHSA-q45j-58j2-45rg). WebP is allowed by default only
  when Pillow links the system libwebp, because the libwebp bundled in the 9.5
  wheels has CVE-2023-4863. HEIF is allowed by default only when pi-heif links
  the system libheif, because its wheels bundle a libheif and libde265 with
  known buffer overflows.
* **MPO** files open as plain JPEG, so frame seeking can't bypass the
  decompression bomb check (GHSA-p8hx-v2p6-rp84).
* **Lossless JPEGs** are refused at open. libjpeg-turbo 3.x decodes them, which
  exposes the heap overflow in GHSA-8g5g-8vmr-9782; 2.x refuses them anyway.
* **JPEG comments** are written as part of the ``extra`` marker data, whose
  output buffer is sized for it, instead of through the encoder's unchecked
  COM write (GHSA-g7cr-3p24-7wf7).
* **APNG** canvas size goes through the decompression bomb check before
  ``_seek`` allocates the disposal canvas (GHSA-5xm2-6676-qcp9).
* **GIF** files carrying more than ``GIF_MAX_COMMENT_BYTES`` of comments are
  refused, which bounds the quadratic comment concatenation in
  ``GifImageFile._seek`` (GHSA-74r2-7ff9-mjj2) and in GIF saving
  (GHSA-fc9g-5qg7-mf45).
"""

from logging import getLogger

import os
import struct


logger = getLogger("jazkarta.hotfixes")

DEFAULT_FORMATS = ("JPEG", "PNG", "GIF")
# pi_heif registers these when the site calls its register_*_opener functions,
# which may happen after the patch is applied.
PI_HEIF_FORMATS = ("HEIF", "AVIF")
GIF_MAX_COMMENT_BYTES = 64 * 1024
# A COM segment's 16-bit length includes its own two bytes.
JPEG_MAX_COMMENT_BYTES = 65533
LOSSLESS_JPEG_MARKERS = (0xFFC3, 0xFFC7, 0xFFCB, 0xFFCF)


def _bundles_libraries(package_file, libs_dir):
    """True when the package is a wheel install linking the libraries it ships.

    macOS wheels keep them in ``<package>/.dylibs``, Linux wheels in a
    ``<distribution>.libs`` directory beside the package.
    """
    package_dir = os.path.dirname(package_file)
    return os.path.isdir(os.path.join(package_dir, ".dylibs")) or os.path.isdir(
        os.path.join(package_dir, os.pardir, libs_dir)
    )


def uses_bundled_libraries():
    import PIL

    return _bundles_libraries(PIL.__file__, "Pillow.libs")


def pi_heif_libheif():
    """pi-heif's libheif as ``(version, bundled)``, or None if it can't load."""
    try:
        import pi_heif

        version = pi_heif.libheif_version()
    except Exception:
        return None
    return version, _bundles_libraries(pi_heif.__file__, "pi_heif.libs")


def allowed_formats():
    configured = [
        name.strip().upper()
        for name in os.getenv("HOTFIXES_PILLOW_FORMATS", "").split(",")
        if name.strip()
    ]
    if configured:
        return frozenset(configured)
    formats = set(DEFAULT_FORMATS)
    if not uses_bundled_libraries():
        formats.add("WEBP")
    libheif = pi_heif_libheif()
    if libheif and not libheif[1]:
        formats.add("HEIF")
    return frozenset(formats)


def _refuse(prefix):
    return False


def _restrict_formats(Image, allowed):
    Image.init()
    for name, (factory, accept) in list(Image.OPEN.items()):
        if name not in allowed:
            Image.OPEN[name] = (factory, _refuse)

    _orig_register_open = Image.register_open

    def register_open(id, factory, accept=None):
        if id.upper() not in allowed:
            accept = _refuse
        return _orig_register_open(id, factory, accept)

    Image.register_open = register_open


def _refuse_lossless_jpeg(JpegImagePlugin):
    def lossless(self, marker):
        raise SyntaxError("lossless JPEG (SOF%d) is not supported" % (marker & 0xF))

    for marker in LOSSLESS_JPEG_MARKERS:
        name, description, _handler = JpegImagePlugin.MARKER[marker]
        JpegImagePlugin.MARKER[marker] = (name, description, lossless)


def _route_jpeg_comment(Image, JpegImagePlugin):
    _orig_save = JpegImagePlugin._save

    def _save(im, fp, filename):
        info = im.encoderinfo
        comment = info.get("comment", im.info.get("comment"))
        if isinstance(comment, str):
            comment = comment.encode()
        if isinstance(comment, bytes) and comment:
            if len(comment) > JPEG_MAX_COMMENT_BYTES:
                raise ValueError("JPEG comment is too long")
            segment = b"\xFF\xFE" + struct.pack(">H", len(comment) + 2) + comment
            im.encoderinfo = dict(
                info, comment=b"", extra=info.get("extra", b"") + segment
            )
        return _orig_save(im, fp, filename)

    JpegImagePlugin._save = _save
    Image.SAVE["JPEG"] = _save


def _check_apng_canvas(Image, PngImagePlugin):
    _orig_seek = PngImagePlugin.PngImageFile._seek

    def _seek(self, frame, rewind=False):
        Image._decompression_bomb_check(self.size)
        return _orig_seek(self, frame, rewind)

    PngImagePlugin.PngImageFile._seek = _seek


def _skip_sub_blocks(fp):
    """Skip a GIF data sub-block chain and return its payload size."""
    total = 0
    while True:
        length = fp.read(1)
        if not length or not length[0]:
            return total
        fp.seek(length[0], os.SEEK_CUR)
        total += length[0]


def _skip_colour_table(fp, flags):
    if flags & 0x80:
        fp.seek(3 << ((flags & 7) + 1), os.SEEK_CUR)


def gif_comment_bytes(fp, limit):
    """Count the bytes ``GifImageFile`` would collect from comment extensions.

    Walks the blocks the way ``GifImageFile._seek`` does, across every frame,
    and stops early once the count passes ``limit``. Each comment extension
    also costs one byte for the newline Pillow joins them with.
    """
    header = fp.read(13)
    if len(header) < 13:
        return 0
    _skip_colour_table(fp, header[10])
    total = 0
    while total <= limit:
        introducer = fp.read(1)
        if not introducer or introducer == b";":
            break
        if introducer == b"!":
            label = fp.read(1)
            payload = _skip_sub_blocks(fp)
            if label == b"\xFE":
                total += payload + 1
        elif introducer == b",":
            descriptor = fp.read(9)
            if len(descriptor) < 9:
                break
            _skip_colour_table(fp, descriptor[8])
            fp.read(1)  # LZW minimum code size
            _skip_sub_blocks(fp)
    return total


def _limit_gif_comments(GifImagePlugin):
    _orig_open = GifImagePlugin.GifImageFile._open

    def _open(self):
        start = self.fp.tell()
        size = gif_comment_bytes(self.fp, GIF_MAX_COMMENT_BYTES)
        self.fp.seek(start)
        if size > GIF_MAX_COMMENT_BYTES:
            raise SyntaxError(
                "GIF comments exceed %d bytes" % GIF_MAX_COMMENT_BYTES
            )
        return _orig_open(self)

    GifImagePlugin.GifImageFile._open = _open


def _set_max_image_pixels(Image):
    value = os.getenv("HOTFIXES_PILLOW_MAX_IMAGE_PIXELS", "").strip()
    if not value:
        return
    try:
        pixels = int(value)
    except ValueError:
        pixels = 0
    if pixels > 0:
        Image.MAX_IMAGE_PIXELS = pixels
    else:
        logger.warning(
            "jazkarta.hotfixes: ignoring HOTFIXES_PILLOW_MAX_IMAGE_PIXELS=%r, "
            "which is not a positive integer.",
            value,
        )


def apply():
    from PIL import GifImagePlugin
    from PIL import Image
    from PIL import JpegImagePlugin
    from PIL import PngImagePlugin

    Image.register_open(
        JpegImagePlugin.JpegImageFile.format,
        JpegImagePlugin.JpegImageFile,
        JpegImagePlugin._accept,
    )
    allowed = allowed_formats()
    _restrict_formats(Image, allowed)
    _refuse_lossless_jpeg(JpegImagePlugin)
    _route_jpeg_comment(Image, JpegImagePlugin)
    _check_apng_canvas(Image, PngImagePlugin)
    _limit_gif_comments(GifImagePlugin)
    _set_max_image_pixels(Image)

    unknown = allowed - set(Image.ID) - set(PI_HEIF_FORMATS)
    if unknown:
        logger.warning(
            "jazkarta.hotfixes: HOTFIXES_PILLOW_FORMATS names formats Pillow "
            "doesn't have: %s.",
            ", ".join(sorted(unknown)),
        )
    bundled = uses_bundled_libraries()
    if bundled and "WEBP" in allowed:
        logger.warning(
            "jazkarta.hotfixes: WEBP is allowed, but Pillow uses its bundled "
            "libraries, so its libwebp may have CVE-2023-4863."
        )
    libheif = pi_heif_libheif()
    if libheif is None:
        libheif_note = "not available"
    else:
        version, heif_bundled = libheif
        libheif_note = "%s (%s)" % (version, "bundled" if heif_bundled else "system")
        if heif_bundled and "HEIF" in allowed:
            logger.warning(
                "jazkarta.hotfixes: HEIF is allowed, but pi-heif uses its "
                "bundled libheif and libde265, which have known buffer overflows."
            )
    logger.info(
        "Applied Pillow 9.5 image hardening: formats %s; %s libraries; "
        "libheif %s; MAX_IMAGE_PIXELS %s.",
        ", ".join(sorted(allowed)),
        "bundled" if bundled else "system",
        libheif_note,
        Image.MAX_IMAGE_PIXELS,
    )
