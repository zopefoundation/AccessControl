##############################################################################
#
# Copyright (c) 2008 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
import unittest

from AccessControl.ZopeGuards import import_default_level


class ModuleSecurityTests(unittest.TestCase):

    def setUp(self):
        from AccessControl import ModuleSecurityInfo as MSI
        mod = 'AccessControl.tests'
        MSI('%s.mixed_module' % mod).declarePublic('pub')  # NOQA: D001
        MSI('%s.public_module' % mod).declarePublic('pub')  # NOQA: D001
        MSI('%s.public_module.submodule' % mod).declarePublic('pub')  # NOQA

    def tearDown(self):
        import sys
        for module in ('AccessControl.tests.public_module',
                       'AccessControl.tests.public_module.submodule',
                       'AccessControl.tests.mixed_module',
                       'AccessControl.tests.mixed_module.submodule',
                       'AccessControl.tests.private_module',
                       'AccessControl.tests.private_module.submodule',
                       ):
            if module in sys.modules:
                del sys.modules[module]

    def assertUnauth(self, module, fromlist, level=import_default_level):
        from zExceptions import Unauthorized

        from AccessControl.ZopeGuards import guarded_import
        self.assertRaises(Unauthorized, guarded_import, module,
                          fromlist=fromlist, level=level)

    def assertAuth(self, module, fromlist, level=import_default_level):
        from AccessControl.ZopeGuards import guarded_import
        guarded_import(module, fromlist=fromlist, level=level)

    def test_unprotected_module(self):
        self.assertUnauth('os', ())

    def testPrivateModule(self):
        self.assertUnauth('AccessControl.tests.private_module', ())
        self.assertUnauth('AccessControl.tests.private_module', ('priv',))
        self.assertUnauth('AccessControl.tests.private_module.submodule', ())
        self.assertUnauth('AccessControl.tests.private_module.submodule',
                          ('priv',))

    def testMixedModule(self):
        self.assertAuth('AccessControl.tests.mixed_module', ())
        self.assertAuth('AccessControl.tests.mixed_module', ('pub',))
        self.assertUnauth('AccessControl.tests.mixed_module', ('priv',))
        self.assertUnauth('AccessControl.tests.mixed_module.submodule', ())

    def testPublicModule(self):
        self.assertAuth('AccessControl.tests.public_module', ())
        self.assertAuth('AccessControl.tests.public_module', ('pub',))
        self.assertAuth('AccessControl.tests.public_module.submodule', ())
        self.assertAuth('AccessControl.tests.public_module.submodule',
                        ('pub',))

    def testPublicModuleThreaded(self):
        """
        Import the same module from two threads simultaneously, checking that
        this does not result in a race condition.
        """
        import threading
        finished = []

        def threaded_run():
            self.assertAuth('AccessControl.tests.public_module', ())
            finished.append(True)

        threads = [threading.Thread(target=threaded_run) for _ in range(2)]

        [t.start() for t in threads]
        [t.join() for t in threads]

        self.assertEqual(len(finished), 2)

    def test_public_module_asterisk_not_allowed(self):
        self.assertUnauth('AccessControl.tests.public_module', ('*',))

    def test_failed_import_keeps_MSI(self):
        # LP #281156
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl.SecurityInfo import _moduleSecurity as MS
        from AccessControl.ZopeGuards import guarded_import
        MSI('AccessControl.tests.nonesuch').declarePublic('pub')  # NOQA: D001
        self.assertIn('AccessControl.tests.nonesuch', MS)
        self.assertRaises(ImportError,
                          guarded_import,
                          'AccessControl.tests.nonesuch',
                          ())
        self.assertIn('AccessControl.tests.nonesuch', MS)

    def test_level_default(self):
        self.assertAuth('AccessControl.tests.public_module', (),
                        level=import_default_level)

    def test_level_nondefault(self):
        self.assertUnauth('AccessControl.tests.public_module', (), level=1)
