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

    def test_allow_class_allow_module_unauthorized(self):
        """ Make sure security policy mutators are safe

        This test doesn't check the module or class guarding functionality per
        se but makes sure several powerful security policy mutator functions
        cannot be used from untrusted code, like ``allow_module`` and
        ``allow_class`` from AccessControl.SecurityInfo and ``allow_type`` from
        AccessControl.SimpleObjectPolicies.
        """
        from AccessControl import ModuleSecurityInfo as MSI

        # Malicious or careless code may try to remove safeguards
        MSI('AccessControl.tests.public_module').declarePublic('allow_class')
        MSI('AccessControl.tests.public_module').declarePublic('allow_module')
        MSI('AccessControl.tests.public_module').declarePublic('allow_type')

        # Additional security declarations on the functions prevent this
        self.assertUnauth('AccessControl.tests.public_module',
                          ('allow_class',))
        self.assertUnauth('AccessControl.tests.public_module',
                          ('allow_module',))
        self.assertUnauth('AccessControl.tests.public_module',
                          ('allow_type',))


class FrozenSecurityDeclarationsTests(unittest.TestCase):

    setUp = ModuleSecurityTests.setUp
    assertUnauth = ModuleSecurityTests.assertUnauth
    assertAuth = ModuleSecurityTests.assertAuth

    def tearDown(self):
        from AccessControl import frozen
        frozen._frozen = False
        ModuleSecurityTests.tearDown(self)

    def assertForbidden(self, func, *args):
        from zExceptions import Forbidden
        self.assertRaises(Forbidden, func, *args)

    def assertUnauthAttribute(self, obj, name):
        from zExceptions import Unauthorized

        from AccessControl.ZopeGuards import guarded_getattr
        self.assertRaises(Unauthorized, guarded_getattr, obj, name)

    def test_declared_modules_stay_importable(self):
        from AccessControl import freeze_security_declarations
        freeze_security_declarations()
        self.assertAuth('AccessControl.tests.public_module', ('pub',))
        self.assertAuth('AccessControl.tests.public_module.submodule', ())
        self.assertAuth('AccessControl.tests.mixed_module', ('pub',))
        self.assertUnauth('AccessControl.tests.mixed_module', ('priv',))
        self.assertUnauth('AccessControl.tests.private_module', ())

    def test_new_declarations_forbidden(self):
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import allow_module
        from AccessControl import freeze_security_declarations
        freeze_security_declarations()
        name = 'AccessControl.tests.private_module'
        self.assertForbidden(allow_module, name)
        self.assertForbidden(MSI, name)
        self.assertUnauth(name, ())

    def test_existing_declarations_forbidden(self):
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import freeze_security_declarations
        from AccessControl.SecurityInfo import _appliedModuleSecurity
        freeze_security_declarations()
        self.assertForbidden(MSI, 'AccessControl.tests.mixed_module')
        modsec = _appliedModuleSecurity['AccessControl.tests.mixed_module']
        self.assertForbidden(modsec.declarePublic, 'priv')
        self.assertForbidden(modsec.declarePrivate, 'pub')
        self.assertForbidden(modsec.setDefaultAccess, 1)
        # The declarations are unchanged.
        self.assertAuth('AccessControl.tests.mixed_module', ('pub',))
        self.assertUnauth('AccessControl.tests.mixed_module', ('priv',))

    def test_registry_changes_forbidden(self):
        from AccessControl import freeze_security_declarations
        from AccessControl.SecurityInfo import _appliedModuleSecurity
        from AccessControl.SecurityInfo import _moduleSecurity
        freeze_security_declarations()
        name = 'AccessControl.tests.public_module'
        for registry in (_moduleSecurity, _appliedModuleSecurity):
            self.assertForbidden(registry.__setitem__, name, None)
            self.assertForbidden(registry.setdefault, name, None)
            self.assertForbidden(registry.update, {name: None})
            self.assertForbidden(registry.clear)
            self.assertForbidden(registry.popitem)
        self.assertForbidden(_appliedModuleSecurity.__delitem__, name)
        self.assertForbidden(_appliedModuleSecurity.pop, name)
        self.assertAuth(name, ('pub',))

    def test_unimportable_module(self):
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import freeze_security_declarations
        from AccessControl.SecurityInfo import _moduleSecurity as MS
        from AccessControl.ZopeGuards import guarded_import
        MSI('AccessControl.tests.nonesuch').declarePublic('pub')  # NOQA: D001
        freeze_security_declarations()
        self.assertIn('AccessControl.tests.nonesuch', MS)
        self.assertRaises(ImportError,
                          guarded_import,
                          'AccessControl.tests.nonesuch',
                          ())

    def test_dangerous_modules_logged(self):
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import freeze_security_declarations
        MSI('AccessControl.tests.nonesuch_all').setDefaultAccess(1)
        MSI('AccessControl.tests.nonesuch_dict').setDefaultAccess({'x': 1})
        MSI('AccessControl.tests.nonesuch_none')
        # Only modules with all names accessible are logged, not those with
        # specific public names, like public_module.
        dangerous = frozenset([
            'AccessControl.tests.public_module',
            'AccessControl.tests.nonesuch_all',
            'AccessControl.tests.nonesuch_dict',
            'AccessControl.tests.nonesuch_none',
        ])
        with self.assertLogs('SecurityInfo', 'WARNING') as logs:
            freeze_security_declarations(dangerous_modules=dangerous)
        self.assertEqual(
            [record.getMessage() for record in logs.records],
            ["Module 'AccessControl.tests.nonesuch_all' is accessible"
             " from restricted code."])

    def test_freeze_twice(self):
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import freeze_security_declarations
        from AccessControl.frozen import is_frozen
        MSI('AccessControl.tests.nonesuch_all').setDefaultAccess(1)
        dangerous = frozenset(['AccessControl.tests.nonesuch_all'])
        with self.assertLogs('SecurityInfo', 'WARNING'):
            freeze_security_declarations(dangerous_modules=dangerous)
        # The second call does nothing, so it does not log again.
        with self.assertNoLogs('SecurityInfo'):
            freeze_security_declarations(dangerous_modules=dangerous)
        self.assertTrue(is_frozen())

    def test_check_dangerous_modules(self):
        # This can be called separately, also after the freeze.
        from AccessControl import ModuleSecurityInfo as MSI
        from AccessControl import freeze_security_declarations
        from AccessControl.SecurityInfo import check_dangerous_modules
        MSI('AccessControl.tests.nonesuch_all').setDefaultAccess(1)
        with self.assertNoLogs('SecurityInfo', 'WARNING'):
            freeze_security_declarations(dangerous_modules=frozenset())
        with self.assertLogs('SecurityInfo', 'WARNING') as logs:
            check_dangerous_modules({'AccessControl.tests.nonesuch_all'})
        self.assertEqual(
            [record.getMessage() for record in logs.records],
            ["Module 'AccessControl.tests.nonesuch_all' is accessible"
             " from restricted code."])

    def test_allow_class_forbidden(self):
        from AccessControl import allow_class
        from AccessControl import freeze_security_declarations

        class Dummy:
            def method(self):
                pass

        freeze_security_declarations()
        self.assertForbidden(allow_class, Dummy)
        self.assertFalse(hasattr(Dummy, '_security'))
        self.assertUnauthAttribute(Dummy(), 'method')

    def test_allow_type_forbidden(self):
        from AccessControl import allow_type
        from AccessControl import freeze_security_declarations
        from AccessControl.SimpleObjectPolicies import ContainerAssertions

        class Dummy:
            def method(self):
                pass

        freeze_security_declarations()
        self.assertForbidden(allow_type, Dummy)
        self.assertNotIn(Dummy, ContainerAssertions)
        self.assertUnauthAttribute(Dummy(), 'method')

    def test_container_assertions_changes_forbidden(self):
        from AccessControl import freeze_security_declarations
        from AccessControl.SimpleObjectPolicies import ContainerAssertions
        freeze_security_declarations()
        self.assertForbidden(ContainerAssertions.__setitem__, object, 1)
        self.assertForbidden(ContainerAssertions.__delitem__, str)
        self.assertForbidden(ContainerAssertions.update, {object: 1})
        self.assertForbidden(ContainerAssertions.setdefault, object, 1)
        self.assertForbidden(ContainerAssertions.pop, str)
        self.assertIn(str, ContainerAssertions)
        self.assertNotIn(object, ContainerAssertions)

    def test_class_security_info_still_works(self):
        # Classes may be imported after the freeze, for example when
        # loading objects from the database.
        from AccessControl import ClassSecurityInfo
        from AccessControl import freeze_security_declarations
        from AccessControl.class_init import InitializeClass
        from AccessControl.ZopeGuards import guarded_getattr

        class Dummy:
            security = ClassSecurityInfo()

            @security.public
            def method(self):
                return 'ok'

            @security.private
            def private_method(self):
                return 'private'

        freeze_security_declarations()
        InitializeClass(Dummy)
        self.assertEqual(guarded_getattr(Dummy(), 'method')(), 'ok')
        self.assertUnauthAttribute(Dummy(), 'private_method')
        # Python code can still call it.
        self.assertEqual(Dummy().private_method(), 'private')
