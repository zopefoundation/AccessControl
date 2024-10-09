##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Tests of PermissionRole
"""

import unittest

from Acquisition import Explicit
from Acquisition import Implicit
from Acquisition import aq_base

from ..Implementation import PURE_PYTHON


ViewPermission = 'View'
EditThingsPermission = 'Edit Things!'
DeletePermission = 'Delete'


class AppRoot(Explicit):
    _View_Permission = None
    _Edit_Things__Permission = ('Manager', 'Owner')
    # No default for delete permission.


class ImplicitContainer(Implicit):
    pass


class ExplicitContainer(Explicit):
    pass


class RestrictiveObject(Implicit):
    _View_Permission = ('Manager',)
    _Delete_Permission = ()  # Nobody


class PermissiveObject(Explicit):
    _Edit_Things__Permission = ['Anonymous']


class PermissionRoleTestBase:

    def assertPRoles(self, ob, permission, expect):
        """
        Asserts that in the context of ob, the given permission maps to
        the given roles.
        """
        pr = self._getTargetClass()(permission)
        roles = pr.__of__(ob)
        roles2 = aq_base(pr).__of__(ob)
        assert roles == roles2 or tuple(roles) == tuple(roles2), (
            'Different methods of checking roles computed unequal results')
        same = 0
        if roles:
            # When verbose security is enabled, permission names are
            # embedded in the computed roles.  Remove the permission
            # names.
            roles = [r for r in roles if not r.endswith('_Permission')]

        if roles is None or expect is None:
            if (roles is None or tuple(roles) == ('Anonymous', )) and \
                    (expect is None or tuple(expect) == ('Anonymous', )):
                same = 1
        else:
            got = {}
            for r in roles:
                got[r] = 1
            expected = {}
            for r in expect:
                expected[r] = 1
            if got == expected:  # Dict compare does the Right Thing.
                same = 1
        self.assertTrue(same, f'Expected roles: {expect!r}, got: {roles!r}')

    def testRestrictive(self, explicit=0):
        app = AppRoot()
        if explicit:
            app.c = ExplicitContainer()
        else:
            app.c = ImplicitContainer()
        app.c.o = RestrictiveObject()
        o = app.c.o
        self.assertPRoles(o, ViewPermission, ('Manager', ))
        self.assertPRoles(o, EditThingsPermission, ('Manager', 'Owner'))
        self.assertPRoles(o, DeletePermission, ())

    def testPermissive(self, explicit=0):
        app = AppRoot()
        if explicit:
            app.c = ExplicitContainer()
        else:
            app.c = ImplicitContainer()
        app.c.o = PermissiveObject()
        o = app.c.o
        self.assertPRoles(o, ViewPermission, ('Anonymous', ))
        self.assertPRoles(o, EditThingsPermission, ('Anonymous',
                                                    'Manager',
                                                    'Owner'))
        self.assertPRoles(o, DeletePermission, ('Manager', ))

    def testExplicit(self):
        self.testRestrictive(1)
        self.testPermissive(1)

    def testAppDefaults(self):
        o = AppRoot()
        self.assertPRoles(o, ViewPermission, ('Anonymous', ))
        self.assertPRoles(o, EditThingsPermission, ('Manager', 'Owner'))
        self.assertPRoles(o, DeletePermission, ('Manager', ))

    def testPermissionRoleSupportsGetattr(self):
        a = self._getTargetClass()('a')
        self.assertEqual(getattr(a, '__roles__'), ('Manager', ))
        self.assertEqual(getattr(a, '_d'), ('Manager', ))
        self.assertEqual(getattr(a, '__name__'), 'a')
        self.assertEqual(getattr(a, '_p'), '_a_Permission')

    def testErrorsDuringGetattr(self):
        pr = self._getTargetClass()('View')

        class AttributeErrorObject(Implicit):
            pass
        self.assertEqual(
            tuple(pr.__of__(AttributeErrorObject())), ('Manager', ))

        # Unauthorized errors are tolerated and equivalent to no
        # permission declaration
        class UnauthorizedErrorObject(Implicit):
            def __getattr__(self, name):
                from zExceptions import Unauthorized
                if name == '_View_Permission':
                    raise Unauthorized(name)
                raise AttributeError(name)
        self.assertEqual(
            tuple(pr.__of__(UnauthorizedErrorObject())), ('Manager', ))

        # other exceptions propagate
        class ErrorObject(Implicit):
            def __getattr__(self, name):
                if name == '_View_Permission':
                    raise RuntimeError("Error raised during getattr")
                raise AttributeError(name)
        with self.assertRaisesRegex(
                RuntimeError, "Error raised during getattr"):
            tuple(pr.__of__(ErrorObject()))


class Python_PermissionRoleTests(PermissionRoleTestBase, unittest.TestCase):
    def _getTargetClass(self):
        from AccessControl.ImplPython import PermissionRole
        return PermissionRole


@unittest.skipIf(PURE_PYTHON, reason="Test expects C impl.")
class C__PermissionRoleTests(PermissionRoleTestBase, unittest.TestCase):
    def _getTargetClass(self):
        from AccessControl.ImplC import PermissionRole
        return PermissionRole
