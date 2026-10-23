# -*- coding: utf-8 -*-
"""Pillow 9.5 hardening. Needs only Pillow 9.5.0 on the path, not Zope."""

from io import BytesIO
from unittest import mock

import os
import subprocess
import sys
import unittest

# Importing the package applies every patch; those needing Plone log a failure
# when it isn't installed, and the Pillow one applies regardless.
from jazkarta.hotfixes.patches import pillow
from PIL import Image
from PIL import JpegImagePlugin
from PIL import UnidentifiedImageError


def _encode(im, fmt, **params):
    buf = BytesIO()
    im.save(buf, fmt, **params)
    return buf.getvalue()


def _jpeg(**params):
    return _encode(Image.new("RGB", (8, 8), "red"), "JPEG", **params)


def _gif_with_comment_extensions(extensions):
    data = _encode(Image.new("P", (1, 1)), "GIF")
    header_end = 13 + (3 << ((data[10] & 7) + 1) if data[10] & 0x80 else 0)
    return data[:header_end] + extensions + data[header_end:]


class TestFormatAllowlist(unittest.TestCase):
    def test_allowed_formats_open(self):
        for fmt in ("JPEG", "PNG", "GIF"):
            data = _encode(Image.new("RGB", (4, 4)), fmt)
            self.assertEqual(Image.open(BytesIO(data)).format, fmt)

    def test_other_formats_are_refused(self):
        for fmt in ("BMP", "TIFF", "PCX"):
            data = _encode(Image.new("RGB", (4, 4)), fmt)
            with self.assertRaises(UnidentifiedImageError, msg=fmt):
                Image.open(BytesIO(data))

    def test_explicit_formats_argument_is_refused_too(self):
        data = _encode(Image.new("RGB", (4, 4)), "TIFF")
        with self.assertRaises(UnidentifiedImageError):
            Image.open(BytesIO(data), formats=["TIFF"])

    def test_formats_registered_later_are_refused(self):
        Image.register_open("HOTFIXES_TEST", object, lambda prefix: True)
        try:
            self.assertIs(Image.OPEN["HOTFIXES_TEST"][1], pillow._refuse)
        finally:
            del Image.OPEN["HOTFIXES_TEST"]
            Image.ID.remove("HOTFIXES_TEST")

    def test_webp_needs_system_libraries(self):
        with mock.patch.dict(os.environ, clear=True):
            with mock.patch.object(pillow, "uses_bundled_libraries", return_value=True):
                self.assertNotIn("WEBP", pillow.allowed_formats())
            with mock.patch.object(pillow, "uses_bundled_libraries", return_value=False):
                self.assertIn("WEBP", pillow.allowed_formats())

    def test_heif_needs_system_libheif(self):
        cases = ((("1.12.0", False), True), (("1.17.5", True), False), (None, False))
        with mock.patch.dict(os.environ, clear=True):
            for libheif, allowed in cases:
                with mock.patch.object(pillow, "pi_heif_libheif", return_value=libheif):
                    self.assertEqual("HEIF" in pillow.allowed_formats(), allowed, libheif)

    def test_empty_formats_variable_means_the_default(self):
        with mock.patch.dict(os.environ, clear=True):
            default = pillow.allowed_formats()
        with mock.patch.dict(os.environ, HOTFIXES_PILLOW_FORMATS=" , "):
            self.assertEqual(pillow.allowed_formats(), default)


def _apply_in_subprocess(**env):
    """Import the package with ``env`` set, and return (stdout, stderr).

    stdout is the formats in effect, Image.MAX_IMAGE_PIXELS, and whether TIFF
    is refused.
    """
    script = (
        "from jazkarta.hotfixes.patches import pillow\n"
        "from PIL import Image\n"
        "print(sorted(pillow.allowed_formats()), Image.MAX_IMAGE_PIXELS,\n"
        "      Image.OPEN['TIFF'][1] is pillow._refuse)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), **env),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    return result.stdout.strip(), result.stderr


class TestEnvironment(unittest.TestCase):
    def test_overrides(self):
        out, _ = _apply_in_subprocess(
            HOTFIXES_PILLOW_FORMATS="jpeg, tiff",
            HOTFIXES_PILLOW_MAX_IMAGE_PIXELS="1000",
        )
        self.assertEqual(out, "['JPEG', 'TIFF'] 1000 False")

    def test_bad_pixel_limit_is_ignored_and_the_patches_still_apply(self):
        for value in ("1e8", "none", "0", "-5"):
            out, err = _apply_in_subprocess(
                HOTFIXES_PILLOW_FORMATS="JPEG",
                HOTFIXES_PILLOW_MAX_IMAGE_PIXELS=value,
            )
            self.assertEqual(
                out, "['JPEG'] %d True" % Image.MAX_IMAGE_PIXELS, value
            )
            self.assertIn("ignoring HOTFIXES_PILLOW_MAX_IMAGE_PIXELS", err, value)

    def test_unknown_format_names_are_logged(self):
        _, err = _apply_in_subprocess(HOTFIXES_PILLOW_FORMATS="JPG, PNG, HEIF")
        self.assertIn("formats Pillow doesn't have: JPG.", err)


class TestJpeg(unittest.TestCase):
    def test_mpo_opens_as_jpeg(self):
        data = _encode(
            Image.new("RGB", (8, 8)),
            "MPO",
            save_all=True,
            append_images=[Image.new("RGB", (8, 8))],
        )
        im = Image.open(BytesIO(data))
        self.assertIs(type(im), JpegImagePlugin.JpegImageFile)
        self.assertEqual(im.format, "JPEG")

    def test_lossless_jpeg_is_refused(self):
        baseline = _jpeg()
        for marker in (b"\xFF\xC3", b"\xFF\xC7", b"\xFF\xCB", b"\xFF\xCF"):
            data = baseline.replace(b"\xFF\xC0", marker, 1)
            with self.assertRaises(UnidentifiedImageError, msg=marker):
                Image.open(BytesIO(data))

    def test_comment_with_icc_profile_near_buffer_size(self):
        # SOI (2) + JFIF APP0 (18) + the APP2 segment of a 65498-byte profile
        # fill the encoder's 65536-byte buffer exactly. Unpatched, the 9-byte
        # COM segment written after it fails at 65489-65497 and overflows the
        # buffer from 65498, which only guard malloc or ASan can see. Writing
        # the comment ahead of the profile is what avoids both.
        for size in range(65486, 65506):
            icc_profile = b"\0" * size
            data = _jpeg(icc_profile=icc_profile, comment=b"hello")
            self.assertLess(
                data.index(b"\xFF\xFE\x00\x07hello"), data.index(b"\xFF\xE2"), size
            )
            im = Image.open(BytesIO(data))
            self.assertEqual(im.info["comment"], b"hello", size)
            self.assertEqual(im.info["icc_profile"], icc_profile, size)

    def test_comment_is_carried_over_from_the_source_image(self):
        source = Image.open(BytesIO(_jpeg(comment="café")))
        resaved = Image.open(BytesIO(_encode(source, "JPEG")))
        self.assertEqual(resaved.info["comment"], "café".encode())

    def test_empty_comment_writes_no_com_segment(self):
        self.assertNotIn(b"\xFF\xFE", _jpeg(comment=b""))

    def test_overlong_comment_is_refused(self):
        with self.assertRaises(ValueError):
            _jpeg(comment=b"x" * 65534)


class TestApng(unittest.TestCase):
    def _apng(self, size):
        frames = [Image.new("RGBA", size), Image.new("RGBA", size, "blue")]
        return _encode(
            frames[0], "PNG", save_all=True, append_images=frames[1:], disposal=1
        )

    def test_animated_png_still_opens(self):
        im = Image.open(BytesIO(self._apng((16, 16))))
        im.seek(1)
        im.load()
        self.assertEqual(im.n_frames, 2)

    def test_oversized_canvas_is_refused_before_allocation(self):
        data = self._apng((64, 64))
        with mock.patch.object(Image, "MAX_IMAGE_PIXELS", 100):
            with mock.patch.object(Image.core, "fill", side_effect=AssertionError):
                with self.assertRaises(Image.DecompressionBombError):
                    Image.open(BytesIO(data))


class TestGifComments(unittest.TestCase):
    def test_comment_within_limit(self):
        data = _encode(Image.new("P", (1, 1)), "GIF", comment=b"x" * 1000)
        self.assertEqual(Image.open(BytesIO(data)).info["comment"], b"x" * 1000)

    def test_one_long_comment_is_refused(self):
        data = _encode(Image.new("P", (1, 1)), "GIF", comment=b"x" * 70000)
        with self.assertRaises(UnidentifiedImageError):
            Image.open(BytesIO(data))

    def test_many_small_comments_are_refused(self):
        data = _gif_with_comment_extensions(b"\x21\xFE\x01A\x00" * 40000)
        with self.assertRaises(UnidentifiedImageError):
            Image.open(BytesIO(data))

    def test_comment_count_matches_pillow(self):
        data = _gif_with_comment_extensions(b"\x21\xFE\x02AB\x00" * 3)
        im = Image.open(BytesIO(data))
        self.assertEqual(im.info["comment"], b"AB\nAB\nAB")
        self.assertEqual(
            pillow.gif_comment_bytes(BytesIO(data), 1000), len(b"AB") * 3 + 3
        )


if __name__ == "__main__":
    unittest.main()
