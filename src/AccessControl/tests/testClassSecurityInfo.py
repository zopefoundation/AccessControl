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
""" Unit tests for ClassSecurityInfo.
"""

import unittest


class ClassSecurityInfoTests(unittest.TestCase):


    def _getTargetClass(self):

        from AccessControl.SecurityInfo import ClassSecurityInfo
        return ClassSecurityInfo

    def test_SetPermissionDefault(self):

        # Test setting default roles for permissions.

        from AccessControl.class_init import InitializeClass
        from ExtensionClass import Base

        ClassSecurityInfo = self._getTargetClass()

        # Setup a test class with default role -> permission decls.
        class Test(Base):
            """Test class
            """
            __ac_roles__ = ('Role A', 'Role B', 'Role C')

            meta_type = "Test"

            security = ClassSecurityInfo()

            security.setPermissionDefault('Make food', ('Chef',))

            security.setPermissionDefault(
                'Test permission',
                ('Manager', 'Role A', 'Role B', 'Role C')
                )

            security.declarePublic('public')
            def public(self, REQUEST=None):
                """ """

            security.declarePrivate('private')
            def private(self, REQUEST=None):
                """ """

            security.declareProtected('Test permission', 'protected')
            def protected(self, REQUEST=None):
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
        self.failUnless(len(imPermissionRole) == 4)

        for item in ('Manager', 'Role A', 'Role B', 'Role C'):
            self.failUnless(item in imPermissionRole)

        # Make sure that a permission defined without accompanying method
        # is still reflected in __ac_permissions__
        self.assertEquals([t for t in Test.__ac_permissions__ if not t[1]],
                          [('Make food', (), ('Chef',))])


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ClassSecurityInfoTests))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
