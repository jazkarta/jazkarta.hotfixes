# -*- coding: utf-8 -*-
"""GHSA-vhwp-qc29-j4xp. Needs plone.app.content and plone.restapi importable."""

import unittest

# Importing the package applies every patch.
import jazkarta.hotfixes  # noqa: F401
from plone.app.content.browser import vocabulary


class TestPrincipalVocabularies(unittest.TestCase):
    def test_permissions(self):
        self.assertEqual(
            vocabulary.PERMISSIONS["plone.app.vocabularies.Groups"],
            "List portal members",
        )
        self.assertEqual(
            vocabulary.PERMISSIONS["plone.app.vocabularies.Principals"],
            "List portal members",
        )
        self.assertEqual(
            vocabulary.PERMISSIONS["plone.app.vocabularies.Users"],
            "Modify portal content",
        )

    def test_restapi_reads_the_patched_dict(self):
        from plone.restapi.services.vocabularies import get

        self.assertIs(get.PERMISSIONS, vocabulary.PERMISSIONS)


if __name__ == "__main__":
    unittest.main()
