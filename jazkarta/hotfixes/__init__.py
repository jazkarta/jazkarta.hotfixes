# -*- coding: utf-8 -*-
"""Security monkeypatches for the end-of-life Plone 5.2 package lines.

Importing this package applies the patches. It is pulled in at Zope startup via
the ``z3c.autoinclude`` ``plone`` plugin (see ``configure.zcml`` and the entry
point in ``setup.py``), so no manual ZCML wiring is required beyond having the
egg on the instance.
"""

from jazkarta.hotfixes.patches import apply_all


apply_all()
