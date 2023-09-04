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

import unittest


class ClassSecurityInfoTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.SecurityInfo import ClassSecurityInfo
        return ClassSecurityInfo

    def assertRaises(self, excClass, callableObj, *args, **kwargs):
        """Fail unless an exception of class excClass is thrown
           by callableObj when invoked with arguments args and keyword
           arguments kwargs. If a different type of exception is
           thrown, it will not be caught, and the test case will be
           deemed to have suffered an error, exactly as for an
           unexpected exception.

           Return the raised exception object, if it matches the expected type.
        """
        try:
            callableObj(*args, **kwargs)
        except excClass as e:
            return e
        else:
            if getattr(excClass, '__name__', None) is not None:
                excName = excClass.__name__
            else:
                excName = str(excClass)
            raise self.failureException("%s not raised" % excName)

    def test_SetPermissionDefault(self):
        # Test setting default roles for permissions.
        from ExtensionClass import Base

        from AccessControl.class_init import InitializeClass

        ClassSecurityInfo = self._getTargetClass()

        # Setup a test class with default role -> permission decls.
        class Test(Base):
            """Test class
            """
            __ac_roles__ = ('Role A', 'Role B', 'Role C')
            meta_type = "Test"
            security = ClassSecurityInfo()
            security.setPermissionDefault('Make food', ('Chef', ))
            security.setPermissionDefault(
                'Test permission',
                ('Manager', 'Role A', 'Role B', 'Role C'),
            )

            security.declarePublic('public')  # NOQA: D001

            def public(self, REQUEST=None):
                """ """

            security.declarePrivate('private')  # NOQA: D001

            def private(self, REQUEST=None):
                """ """

            security.declareProtected('Test permission', 'protected')   # NOQA

            def protected(self, REQUEST=None):
                """ """

            # same with decorators

            @security.public
            def public_new(self, REQUEST=None):
                """ """

            @security.private
            def private_new(self, REQUEST=None):
                """ """

            @security.protected('Test permission')
            def protected_new(self, REQUEST=None):
                """ """

        # Do class initialization.
        InitializeClass(Test)

        # Now check the resulting class to see if the mapping was made
        # correctly. Note that this uses carnal knowledge of the internal
        # structures used to store this information!
        object = Test()
        self.assertEqual(object.public__roles__, None)
        self.assertEqual(object.private__roles__, ())
        imPermissionRole = [r for r in object.protected__roles__
                            if not r.endswith('_Permission')]
        self.assertTrue(len(imPermissionRole) == 4)

        for item in ('Manager', 'Role A', 'Role B', 'Role C'):
            self.assertTrue(item in imPermissionRole)

        # functions exist, i.e. decorators returned them
        self.assertEqual(object.public_new.__name__, 'public_new')
        self.assertEqual(object.private_new.__name__, 'private_new')
        self.assertEqual(object.protected_new.__name__, 'protected_new')

        # roles for functions have been set via decorators
        self.assertEqual(object.public_new__roles__, None)
        self.assertEqual(object.private_new__roles__, ())
        imPermissionRole = [r for r in object.protected_new__roles__
                            if not r.endswith('_Permission')]
        self.assertTrue(len(imPermissionRole) == 4)

        for item in ('Manager', 'Role A', 'Role B', 'Role C'):
            self.assertTrue(item in imPermissionRole)

        # Make sure that a permission defined without accompanying method
        # is still reflected in __ac_permissions__
        self.assertEqual([t for t in Test.__ac_permissions__ if not t[1]],
                         [('Make food', (), ('Chef',))])

    def test_EnsureProtectedDecoCall(self):
        from ExtensionClass import Base

        from AccessControl.class_init import InitializeClass

        ClassSecurityInfo = self._getTargetClass()

        class Test(Base):
            """Test class
            """
            meta_type = "Test"

            security = ClassSecurityInfo()

            # security not used as a decorator, so does not protect
            security.protected('Test permission 1')

            def unprotected1(self, REQUEST=None):
                """ """

            # see above
            security.protected('Test permission 2')

            def unprotected2(self, REQUEST=None):
                """ """

            @security.protected('Test permission 3')
            def protected(self, REQUEST=None):
                """ """

        # Do class initialization.
        exc = self.assertRaises(AssertionError,
                                InitializeClass, Test)
        self.assertTrue('has 2 non-decorator' in str(exc))

    def test_aq_context_in_decorators(self):
        from Acquisition import Implicit
        info = self._getTargetClass()

        class A(Implicit):
            security = info()
            a = 1

            @security.public
            def public(self):
                return self.a

            @security.private
            def private(self):
                # make sure the acquisition context is still intact
                return self.b

        class B(Implicit):
            security = info()
            b = 2

        a = A()
        b = B()
        a = a.__of__(b)

        self.assertEqual(a.b, 2)
        self.assertEqual(a.public(), 1)
        self.assertEqual(a.private(), 2)
