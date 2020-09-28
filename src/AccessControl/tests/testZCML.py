##############################################################################
#
# Copyright (c) 2004, 2005 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Test security induced by ZCML
"""

import doctest
import unittest

from zope.interface import Interface
from zope.interface import implementer
from zope.schema import TextLine

from AccessControl.SecurityInfo import ClassSecurityInfo


class ISuperDummy(Interface):
    """
    """

    def superMethod():
        """
        """


class IDummy(ISuperDummy):
    """Just a marker interface"""

    def foo():
        """
        """


@implementer(IDummy)
class Dummy1(object):

    def foo(self):
        pass

    def bar(self):
        pass

    def baz(self):
        pass

    def keg(self):
        pass

    def wot(self):
        pass

    def superMethod(self):
        pass


class Dummy2(Dummy1):
    security = ClassSecurityInfo()
    security.declarePublic('foo')  # NOQA: D001
    security.declareProtected('View management screens', 'bar')  # NOQA: D001
    security.declarePrivate('baz')  # NOQA: D001
    security.declareProtected('View management screens', 'keg')  # NOQA: D001


class IDummy3(Interface):
    attr = TextLine(title=u"Attribute")


@implementer(IDummy3)
class Dummy3(object):
    attr = None


class Dummy4(object):
    foo = None


class Dummy5(object):
    pass


class TestSecurity(unittest.TestCase):

    def setUp(self):
        from zope.component.testing import setUp
        setUp()

    def tearDown(self):
        from zope.component.testing import tearDown

        from AccessControl.security import clearSecurityInfo
        clearSecurityInfo(Dummy1)
        clearSecurityInfo(Dummy2)
        tearDown()

    def test_security_equivalence(self):
        """
        This test demonstrates that the traditional declarative security of
        Zope 2 can be replaced by ZCML statements without any loss of
        information.
        """

        # We start out with two classes, ``Dummy1`` and ``Dummy2``.  They
        # are identical in every way, except that ``Dummy2`` has security
        # declarations and ``Dummy1`` does not.  Before we do anything, none
        # of them have security access controls:

        from AccessControl.tests.testZCML import Dummy1
        from AccessControl.tests.testZCML import Dummy2
        self.assertFalse(hasattr(Dummy1, '__ac_permissions__'))
        self.assertFalse(hasattr(Dummy2, '__ac_permissions__'))

        # Before we can make security declarations through ZCML, we need to
        # register the directive and the permission:

        from zope.configuration.xmlconfig import XMLConfig

        import AccessControl
        XMLConfig('meta.zcml', AccessControl)()
        XMLConfig('permissions.zcml', AccessControl)()

        # Now we initialize the security for ``Dummy2`` and provide some
        # ZCML declarations for ``Dummy1``:

        from io import StringIO
        configure_zcml = StringIO(u'''
            <configure xmlns="http://namespaces.zope.org/zope">
              <class class="AccessControl.tests.testZCML.Dummy1">
                <allow attributes="foo" />
                <!--deny attributes="baz" /--> <!-- XXX not yet supported -->
              </class>
              <class class="AccessControl.tests.testZCML.Dummy1">
                <require attributes="bar keg"
                         permission="zope2.ViewManagementScreens"
                         />
              </class>
            </configure>
            ''')
        from zope.configuration.xmlconfig import xmlconfig
        xmlconfig(configure_zcml)

        from AccessControl.class_init import InitializeClass
        InitializeClass(Dummy2)

        # Now we compare their access controls:

        ac1 = getattr(Dummy1, '__ac_permissions__')
        ac2 = getattr(Dummy2, '__ac_permissions__')
        self.assertEqual(
            [(perm, set(attr)) for perm, attr in dict(ac1).items()],
            [(perm, set(attr)) for perm, attr in dict(ac2).items()])

        # Now we look at the individual permissions:

        from AccessControl import ACCESS_PRIVATE
        from AccessControl import ACCESS_PUBLIC
        from AccessControl.ZopeSecurityPolicy import getRoles

        dummy1 = Dummy1()
        self.assertEqual(
            getRoles(dummy1, 'bar', dummy1.bar, ('Def', )),
            ('Manager', ))

        self.assertEqual(
            getRoles(dummy1, 'keg', dummy1.keg, ('Def', )),
            ('Manager', ))

        self.assertEqual(
            getRoles(dummy1, 'foo', dummy1.foo, ('Def', )),
            ACCESS_PUBLIC)

        # XXX Not yet supported.
        # self.assertEqual(
        #     getRoles(dummy1, 'baz', dummy1.baz, ('Def', )),
        #     ACCESS_PRIVATE)

        dummy2 = Dummy2()
        self.assertEqual(
            getRoles(dummy2, 'bar', dummy2.bar, ('Def', )),
            ('Manager', ))

        self.assertEqual(
            getRoles(dummy2, 'keg', dummy2.keg, ('Def', )),
            ('Manager', ))

        self.assertEqual(
            getRoles(dummy2, 'foo', dummy2.foo, ('Def', )),
            ACCESS_PUBLIC)

        self.assertEqual(
            getRoles(dummy2, 'baz', dummy2.baz, ('Def', )),
            ACCESS_PRIVATE)


def test_set_warnings():
    """This test demonstrates that set_attributes and set_schema will result
    in warnings, not errors. This type of protection doesn't make sense in
    Zope 2, but we want to be able to re-use Zope Toolkit packages that use
    them without error.

      >>> from zope.component.testing import setUp, tearDown
      >>> setUp()

    Before we can make security declarations through ZCML, we need to
    register the directive and the permission:

      >>> import AccessControl
      >>> from zope.configuration.xmlconfig import XMLConfig
      >>> XMLConfig('meta.zcml', AccessControl)()
      >>> XMLConfig('permissions.zcml', AccessControl)()

    Now we provide some ZCML declarations for ``Dummy1``:

      >>> from io import StringIO
      >>> configure_zcml = StringIO(u'''
      ... <configure xmlns="http://namespaces.zope.org/zope">
      ...
      ...   <class class="AccessControl.tests.testZCML.Dummy3">
      ...       <require
      ...           permission="zope2.View"
      ...           interface="AccessControl.tests.testZCML.IDummy3"
      ...           />
      ...       <require
      ...           permission="zope2.ChangeConfig"
      ...           set_schema="AccessControl.tests.testZCML.IDummy3"
      ...           />
      ...   </class>
      ...
      ...   <class class="AccessControl.tests.testZCML.Dummy4">
      ...       <require
      ...           permission="zope2.ChangeConfig"
      ...           set_attributes="foo"
      ...           />
      ...   </class>
      ...
      ... </configure>
      ... ''')

      Running this should not throw an exception (but will print a warning to
      stderr)

      >>> from warnings import catch_warnings
      >>> from zope.configuration.xmlconfig import xmlconfig
      >>> warned = []
      >>> with catch_warnings(record=True) as trapped:
      ...      xmlconfig(configure_zcml)
      ...      warned.extend(list(trapped))
      >>> len(warned)
      2
      >>> str(warned[0].message).startswith('The set_schema option')
      True
      >>> str(warned[1].message).startswith('The set_attribute option')
      True
      >>> tearDown()
    """


def test_checkPermission():
    """
    Test checkPermission

      >>> from zope.component.testing import setUp, tearDown
      >>> setUp()

      >>> from zope.component import eventtesting
      >>> eventtesting.setUp()

    zope.security has a function zope.security.checkPermission which provides
    an easy way of checking whether the currently authenticated user
    has the permission to access an object.  The function delegates to
    the security policy's checkPermission() method.

    Zope2 has the same function, AccessControl.security.checkPermission,
    but in a Zope2-compatible implementation.  It too uses the currently
    active security policy of Zope 2 for the actual permission
    checking.

      >>> import AccessControl
      >>> from zope.configuration.xmlconfig import XMLConfig
      >>> XMLConfig('meta.zcml', AccessControl)()
      >>> XMLConfig('permissions.zcml', AccessControl)()

      >>> from AccessControl.tests.testZCML import Dummy5
      >>> dummy = Dummy5()

    In the following we want to test AccessControl's checkPermission function.
    What we want to assure is that checkPermission translates the Zope 2
    permissions correctly, especially the edge cases:

    a) zope2.Public (which should always be available to everyone)

      >>> from AccessControl.security import checkPermission
      >>> checkPermission('zope2.Public', dummy)
      True

    b) zope2.Private (which should never available to anyone)

      >>> checkPermission('zope.Private', dummy)
      False
      >>> checkPermission('zope2.Private', dummy)
      False

    Any other standard Zope 2 permission will also resolve correctly:

      >>> checkPermission('zope2.ViewManagementScreens', dummy)
      False

    Invalid permissions will obviously result in a negative response:

      >>> checkPermission('notapermission', dummy)
      False


    In addition to using AccessControl's ``checkPermission`` function
    directly, we also expect the same behaviour when we use zope.security's
    checkPermission function. Code from within other Zope packages will use
    that and therefore it should work transparently.
    For that to work, a new AccessControl "interaction" needs to be started
    (the old one from placelesssetup needs to be ended first):

      >>> from zope.security.management import endInteraction
      >>> endInteraction()

      >>> from AccessControl.security import newInteraction
      >>> newInteraction()

    a) zope2.Public (which should always be available to everyone)

      >>> from zope.security import checkPermission
      >>> checkPermission('zope2.Public', dummy)
      True

    b) zope2.Private (which should never available to anyone)

      >>> checkPermission('zope.Private', dummy)
      False
      >>> checkPermission('zope2.Private', dummy)
      False

    Any other standard Zope 2 permission will also resolve correctly:

      >>> checkPermission('zope2.ViewManagementScreens', dummy)
      False

    Invalid permissions will obviously result in a negative response:

      >>> checkPermission('notapermission', dummy)
      False

    Clean up:

      >>> tearDown()
    """


def test_register_permission():
    """This test demonstrates that if the <permission /> directive is used
    to create a permission that does not already exist, it is created on
    startup, with roles defaulting to Manager.

      >>> from zope.component.testing import setUp, tearDown
      >>> setUp()

      >>> from zope.component import eventtesting
      >>> eventtesting.setUp()

    First, we need to configure the relevant parts of AccessControl:

      >>> import AccessControl
      >>> from zope.configuration.xmlconfig import XMLConfig
      >>> XMLConfig('meta.zcml', AccessControl)()
      >>> XMLConfig('permissions.zcml', AccessControl)()

    We can now register a permission in ZCML:

      >>> from io import StringIO
      >>> configure_zcml = StringIO(u'''
      ... <configure xmlns="http://namespaces.zope.org/zope"
      ...            i18n_domain="test">
      ...
      ...   <permission
      ...       id="AccessControl.tests.DummyPermission"
      ...       title="AccessControl: Dummy permission"
      ...       />
      ...
      ... </configure>
      ... ''')
      >>> from zope.configuration.xmlconfig import xmlconfig
      >>> xmlconfig(configure_zcml)

    The permission will be made available globally, with default role set
    of ('Manager',).

      >>> from AccessControl.Permission import getPermissions
      >>> permissions = getPermissions()
      >>> [p[2] for p in permissions
      ...          if p[0] == 'AccessControl: Dummy permission']
      [('Manager',)]

    Let's also ensure that permissions are not overwritten if they exist
    already:

      >>> from AccessControl.Permission import addPermission
      >>> addPermission('Dummy: Other dummy', ('Anonymous', ))

      >>> from io import StringIO
      >>> configure_zcml = StringIO(u'''
      ... <configure xmlns="http://namespaces.zope.org/zope"
      ...            i18n_domain="test">
      ...
      ...   <permission
      ...       id="AccessControl.tests.OtherDummy"
      ...       title="Dummy: Other dummy"
      ...       />
      ...
      ... </configure>
      ... ''')
      >>> from zope.configuration.xmlconfig import xmlconfig
      >>> xmlconfig(configure_zcml)

      >>> permissions = getPermissions()
      >>> [p[2] for p in permissions if p[0] == 'Dummy: Other dummy']
      [('Anonymous',)]

      >>> tearDown()
    """


def test_register_permission_with_non_default_roles():
    """This test demonstrates that the <permission /> directive can be used
    as a grouping directive with <role/> subdirectives that specify the default
    roles for the permission.

      >>> from zope.component.testing import setUp, tearDown
      >>> setUp()

    First, we need to configure the relevant parts of AccessControl:

      >>> import AccessControl
      >>> from zope.configuration.xmlconfig import XMLConfig
      >>> XMLConfig('meta.zcml', AccessControl)()
      >>> XMLConfig('permissions.zcml', AccessControl)()

    We can now register a permission in ZCML:

      >>> from io import StringIO
      >>> configure_zcml = StringIO(u'''
      ... <configure xmlns="http://namespaces.zope.org/zope"
      ...            i18n_domain="test">
      ...
      ...   <permission
      ...       id="AccessControl.tests.DummyPermission2"
      ...       title="AccessControl: Dummy permission 2">
      ...       <role name="Anonymous"/>
      ...   </permission>
      ...
      ... </configure>
      ... ''')
      >>> from zope.configuration.xmlconfig import xmlconfig
      >>> xmlconfig(configure_zcml)

    The permission will be made available globally, with the specified role set
    of ('Anonymous',).

      >>> from AccessControl.Permission import getPermissions
      >>> permissions = getPermissions()
      >>> [p[2] for p in permissions
      ...          if p[0] == 'AccessControl: Dummy permission 2']
      [('Anonymous',)]

      >>> tearDown()
    """


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSecurity))
    suite.addTest(doctest.DocTestSuite(optionflags=doctest.ELLIPSIS))
    return suite
