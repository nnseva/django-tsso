from __future__ import absolute_import, print_function

import os
import re
import unittest

import django


class DjangoVersionMatchesToxEnvTest(unittest.TestCase):
    """
    Safety net for the tox setup.

    tox pins the Django version to test against via the `djangoX.Y` factor
    in the env name (see `deps=` in tox.ini), but that pin only applies to
    the `install_deps` step. If something installed afterwards - typically
    an unpinned `install_requires` of this package, or a fresh dependency
    of a transitive package like social-auth-app-django - has no matching
    upper bound, pip is free to upgrade/downgrade Django again when
    resolving it, silently running the whole suite against the wrong
    version (e.g. py312-django4.1 ending up with Django 6.1 installed).

    This test fails loudly instead, by comparing the Django version that
    is actually importable against the one requested by the tox env name.
    """

    def test_installed_django_matches_tox_factor(self):
        tox_env_name = os.environ.get('TOX_ENV_NAME')
        if not tox_env_name:
            self.skipTest("Not running under tox (TOX_ENV_NAME is not set)")

        match = re.search(r'django(\d+)\.(\d+)', tox_env_name)
        if not match:
            self.skipTest("tox env name %r has no djangoX.Y factor" % tox_env_name)

        expected = (int(match.group(1)), int(match.group(2)))
        actual = django.VERSION[:2]

        self.assertEqual(
            expected, actual,
            "tox env %r requested Django %s.%s but %s is actually installed "
            "(%s). Some dependency likely pulled in an unpinned Django "
            "version after tox's deps= step installed the pinned one - "
            "check `pip freeze` for this env." % (
                tox_env_name, expected[0], expected[1],
                django.get_version(), django.__file__,
            )
        )
