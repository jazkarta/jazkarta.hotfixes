=================
jazkarta.hotfixes
=================

Runtime monkeypatch backports of four Plone security advisories to the
end-of-life Plone 5.2 package lines, for which the Plone security team shipped
**no** fixed release (the fixes only exist on the Plone 6.x lines), plus fixes
for the Pillow 13.0.0 advisories that reach Pillow 9.5.0.

This package targets:

======================  =====================  =========================
Package                 Version on 5.2         Fix backported from
======================  =====================  =========================
``plone.app.portlets``  ``4.4.8``/``4.4.9``    ``7.0.2`` (Plone 6.2)
``plone.app.event``     ``3.2.14``             ``6.0.1`` (Plone 6.2)
``plone.app.content``   ``3.8.10``/``3.8.11``  ``4.2.1`` (Plone 6.0/6.1)
``Pillow``              ``9.5.0``              ``13.0.0`` advisories
======================  =====================  =========================

These are the last releases of their respective lines (``4.4.9`` differs from
``4.4.8`` only in an unrelated template, and ``plone.app.content``'s
``browser/vocabulary.py`` is identical in ``3.8.10`` and ``3.8.11``), so the
source the patches are written against is frozen and will not drift.

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

4. **GHSA-vhwp-qc29-j4xp** (CVSS 5.3) -- anonymous listing of user ids, full
   names and groups through plone.restapi's ``@vocabularies`` endpoint. The
   ``plone.app.vocabularies.Groups`` and ``plone.app.vocabularies.Principals``
   vocabularies now require ``List portal members``, as upstream. The same
   permission applies to ``@@getVocabulary`` on any navigation root, such as
   the site root, which now serves these vocabularies to its holders. Member has that permission by default, so
   logged-in members can still list every user and group; to prevent that, take
   ``List portal members`` away from Member on the site root. ``Users`` stays at
   ``Modify portal content``, but that hides nothing from Members, because
   ``Principals`` includes users. The endpoint works whenever plone.restapi's
   ZCML is loaded, even if its add-on profile was never installed.

5. **Pillow 13.0.0 advisories** reachable on 9.5.0 through uploaded images.
   Pillow 13 doesn't support Python 3.8, so each fix is reimplemented against
   9.5.0's code:

   - Only the formats in ``HOTFIXES_PILLOW_FORMATS`` can be opened, which
     shuts out the BMP, MSP and XBM decoder bugs and the TIFF decode leaks
     (GHSA-24rc-8hj2-v98c, GHSA-gg2r-wvfm-q9rx, GHSA-xgh8-jp6q-p5x8,
     GHSA-c6hw-5grf-ff96, GHSA-q45j-58j2-45rg). The default is JPEG, PNG
     and GIF, plus WebP when Pillow links the system libwebp and HEIF when
     ``pi_heif`` links the system libheif. The libwebp bundled in the 9.5.0
     wheels has CVE-2023-4863; for pi-heif's bundled libraries see `HEIF
     support`_. The allowlist also applies to plugins registered later, such
     as ``pi_heif``'s. An empty value means the default, and names Pillow
     doesn't know are logged as a warning.
   - MPO files open as plain JPEG (first frame only), so seeking can't skip
     the decompression bomb check (GHSA-p8hx-v2p6-rp84).
   - Lossless JPEGs are refused. libjpeg-turbo 3.x decodes them, which exposes
     the heap overflow in GHSA-8g5g-8vmr-9782; 2.x refuses them anyway.
   - JPEG comments, including those carried over from the source image, are
     written as part of the encoder's ``extra`` marker data, ahead of the ICC
     profile. The encoder's own comment write overflows its buffer when an ICC
     profile fills it (GHSA-g7cr-3p24-7wf7). Comments over 65533 bytes, which
     no JPEG can hold, raise ``ValueError``.
   - Animated PNGs go through the decompression bomb check before the
     disposal canvas is allocated (GHSA-5xm2-6676-qcp9).
   - GIFs carrying more than 64 KB of comments are refused, which bounds the
     quadratic comment handling when opening and saving them
     (GHSA-74r2-7ff9-mjj2, GHSA-fc9g-5qg7-mf45).

   Refused images raise ``PIL.UnidentifiedImageError``, as any unrecognised
   file does, and images over the pixel limit raise
   ``PIL.Image.DecompressionBombError``. Plone's image scaling logs the error
   and serves no scale. The upload itself still succeeds, unless site code
   opens the image with Pillow while storing it and doesn't catch these
   errors.

How it works
============

Importing the package applies the patches as a side effect. The package
declares the ``z3c.autoinclude`` ``plone`` plugin, so simply having the egg on
the Zope instance causes it to be imported at startup -- no ZCML slug or profile
is required.

On startup it logs (logger name ``jazkarta.hotfixes``), e.g.::

    jazkarta.hotfixes: plone.app.portlets 4.4.8 (expected).
    jazkarta.hotfixes: plone.app.event 3.2.14 (expected).
    jazkarta.hotfixes: plone.app.content 3.8.10 (expected).
    jazkarta.hotfixes: Pillow 9.5.0 (expected).
    Applied Classic portlet TALES-injection patch ...
    Applied RSS portlet DoS/SSRF/XSS patch ...
    Applied icalendar import DoS/SSRF/XSS patch ...
    Applied principal vocabularies permission patch ...
    Applied Pillow 9.5 image hardening: formats GIF, HEIF, JPEG, PNG, WEBP; system libraries; libheif 1.12.0 (system); MAX_IMAGE_PIXELS 89478485.
    jazkarta.hotfixes: all 5 security patches applied.

If a target package is a different version than expected, or a patch fails to
apply, it logs a ``WARNING``/``ERROR`` (the site still starts). **Check the log
after deploying** to confirm all five patches applied, and that the Pillow line
says ``system libraries`` and, if the site uses HEIF, ``(system)`` after the
libheif version.

Installation
============

Add ``jazkarta.hotfixes`` to the ``eggs`` of the instance part of your
buildout (or to the ``install_requires`` of a policy egg that is already
installed on the instance), then rerun buildout and restart Zope.

To track this repository as a development source with ``mr.developer``, add to
your sources config::

    [sources]
    jazkarta.hotfixes = git git@github.com:jazkarta/jazkarta.hotfixes.git

Building Pillow from source
===========================

Pillow's wheels bundle their own copies of libjpeg-turbo, libwebp, libtiff,
OpenJPEG, FreeType and LittleCMS, and those copies never get security fixes:
the 9.5.0 wheels carry libwebp 1.3.0, which has CVE-2023-4863. Compiled from
source, Pillow links the operating system's libraries instead, so OS security
updates cover them. Restart Zope after the OS updates them.

Install a compiler and the headers for each library Pillow should use. On
Debian and Ubuntu, the minimum is::

    build-essential libjpeg-dev zlib1g-dev

Add ``libwebp-dev`` for WebP and ``libtiff-dev`` for compressed TIFF.
``libopenjp2-7-dev`` (JPEG 2000), ``libfreetype-dev`` (``ImageFont`` TrueType
text) and ``liblcms2-dev`` (``ImageCms`` colour conversion) are only worth
adding if something on the site uses them; plone.scale needs none of the three.
Pillow silently leaves out any library whose headers are missing.

zc.buildout 3 installs wheels and reuses any installed egg that matches the
version pin, so pinning alone never forces a source build. It does prefer a
distribution already installed in its Python's site-packages, when the version
matches the pin, over any egg. So have pip build from source in a part that
comes before all the others::

    [buildout]
    parts =
        source-builds
        ...

    [source-builds]
    recipe = collective.recipe.cmd
    on_install = true
    on_update = true
    packages = Pillow==${versions:Pillow}
    cmds =
        set -e
        if [ -n "${:packages}" ]; then
            names=$(echo "${:packages}" | sed 's/==[^ ]*//g' | tr ' ' ',')
            ${buildout:executable} -m pip install --no-deps --no-cache-dir --no-binary "$names" ${:packages}
            ${buildout:executable} -c 'import sys; from importlib.metadata import distribution; bundled = [n for n in sys.argv[1].split(",") if any(p.parts[0].endswith(".libs") or ".dylibs" in p.parts for p in distribution(n).files or [])]; sys.exit("Installed from a wheel with bundled libraries: " + ", ".join(bundled) if bundled else 0)' "$names"
        fi

The egg recipes (``zc.recipe.egg``, ``plone.recipe.zope2instance``) resolve
their eggs when their own part installs, so they see what pip installed. A
failed build stops buildout; without ``set -e`` only the last command's exit
status would count. ``packages`` takes its versions from ``[versions]``
because buildout quietly falls back to the egg if they differ. Leave
``packages`` empty in configs where the wheels should stay, such as
development machines.

pip doesn't rebuild a version it already has, even one installed from a wheel,
so the last command fails buildout if any of the packages still carries a
wheel's bundled libraries (a ``Pillow.libs`` or ``.dylibs`` directory). Fix
that, or rebuild after an OS upgrade changes a library's soname, by running
the pip command by hand with ``--force-reinstall``.
Removing a package from ``packages`` doesn't uninstall it, and buildout keeps
using it while its version matches the pin.

To check what Pillow is linked against::

    bin/zopepy -c "from PIL import features; print({k: features.version(k) for k in ('libjpeg_turbo', 'webp', 'libtiff', 'jpg_2000', 'freetype2', 'littlecms2')})"
    ldd $(bin/zopepy -c "import glob, os, PIL; print(' '.join(glob.glob(os.path.dirname(PIL.__file__) + '/*.so')))") | grep -Ei "jpeg|webp|tiff|openjp|freetype|lcms"

The libraries should resolve under ``/usr/lib``. A ``Pillow.libs`` directory
means the wheel's bundled copies are still in use.

A source build uses whatever libjpeg-turbo the OS provides. Version 3.x decodes
lossless JPEGs, which exposes GHSA-8g5g-8vmr-9782 on Pillow < 13 (heap overflow
when a lossless JPEG is scaled with ``draft()``); 2.x refuses them.

HEIF support
============

Sites that open HEIC/HEIF uploads through ``pi-heif`` get the decoder from its
wheel, and the same problem applies: the wheel bundles libheif and libde265
copies that never get security fixes. The 0.14.0 wheels carry libde265 1.0.14,
with heap and global buffer overflows (CVE-2023-49465, CVE-2023-49467,
CVE-2023-49468, fixed in 1.0.15), and libheif 1.17.5, with an out-of-bounds
read and write when parsing overlay images (CVE-2024-41311). libheif's own
advisories list many more fixed only in 1.23. So ``HEIF`` is in the default
formats only when pi-heif doesn't use the wheel's libraries, that is when
there is no ``pi_heif.libs`` or ``pi_heif/.dylibs`` directory. Otherwise HEIC
uploads still save but get no scales, and the startup log says ``libheif
<version> (bundled)``. Setting ``HOTFIXES_PILLOW_FORMATS`` overrides this, with
a warning in the log.

Compile pi-heif from source so it links the operating system's libheif and
libde265 instead. Which pi-heif release builds depends on the OS libheif:

- 0.14.0 and later need libheif 1.16.1 or newer.
- 0.13.1 is the newest release that builds against libheif 1.12, which
  Ubuntu 22.04 ships and patches through Ubuntu Pro (ESM).
- 0.18.0 is the last release that supports Python 3.8.

Install ``libheif-dev``. Without it, pi-heif's ``setup.py`` downloads and
builds its own libheif and libde265 (1.16.2 and 1.0.12 for 0.13.1) and
installs them under ``/usr``. Run as a user who can't write there, that step
fails and stops buildout. Run as root, it succeeds without saying so, and the
startup check can't tell those copies from the OS's, so check the result after
building.

Add it to the ``packages`` of the ``source-builds`` part described above::

    packages = Pillow==${versions:Pillow} pi-heif==${versions:pi-heif}

pip builds pi-heif's PyPI sdist. pi-heif's git repository builds the package
under the name ``pillow_heif`` instead. On macOS, Apple's clang rejects the
``-Ofast -Werror`` flags pi-heif compiles with; set
``CFLAGS=-Wno-deprecated-ofast``.

To check what pi-heif is linked against::

    bin/zopepy -c "import pi_heif; print(pi_heif.__version__, pi_heif.libheif_info())"
    ldd "$(bin/zopepy -c 'import _pi_heif; print(_pi_heif.__file__)')" | grep -Ei "heif|de265"

Both libraries should resolve under ``/usr/lib``; a ``pi_heif.libs`` directory
means the wheel's copies. To see which CVEs the OS packages fix::

    zcat /usr/share/doc/libheif1/changelog.Debian.gz | grep -o "CVE-[0-9]*-[0-9]*" | sort -u
    zcat /usr/share/doc/libde265-0/changelog.Debian.gz | grep -o "CVE-[0-9]*-[0-9]*" | sort -u

Tunables (environment variables)
================================

============================================  =========  ==================================
Variable                                      Default    Effect
============================================  =========  ==================================
``MAXIMUM_RSS_FEED_SIZE_BYTES``               1000000    Max bytes read per RSS feed
``MAXIMUM_ICAL_IMPORT_SIZE_BYTES``            500000     Max bytes read per ical url
``MAXIMUM_ICAL_IMPORT_EVENTS``                366        Max events per ical resource
``HOTFIXES_DOWNLOAD_TIMEOUT``                 3.5        Connect+read timeout (seconds)
``HOTFIXES_PILLOW_FORMATS``                   see above  Comma-separated formats Pillow may
                                                         open; replaces the default
``HOTFIXES_PILLOW_MAX_IMAGE_PIXELS``          Pillow's   Sets ``Image.MAX_IMAGE_PIXELS``;
                                              89478485   twice it raises an error
============================================  =========  ==================================

The variables must be set in every process that loads the patches: each Zope
client and the celery worker. Changing them takes a restart.

Running the tests
=================

The tests use plain ``unittest`` and need no Zope test layer. Run them with an
interpreter that has the site's eggs on its path, such as buildout's
``zopepy``::

    bin/zopepy -m unittest discover -s src/jazkarta.hotfixes/jazkarta/hotfixes/tests -t src/jazkarta.hotfixes

``test_pillow`` needs only Pillow 9.5.0 and this package on the path.

Removing the patches
====================

These become unnecessary the moment the site is migrated to a Plone version
whose ``plone.app.portlets`` / ``plone.app.event`` / ``plone.app.content``
already contains the fixes (portlets >= 5.0.8, event >= 5.2.4, content >=
4.2.1) and that runs a Pillow release with the 13.0.0 fixes. At that point
remove the egg. The startup version check will warn if the underlying packages
move off 4.4.8/4.4.9 / 3.2.14 / 3.8.10/3.8.11 / 9.5.0, which is your signal to
re-review or retire this package.
