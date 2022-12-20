##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" Unit tests for AccessControl.User
"""
import unittest


class BasicUserTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.users import BasicUser
        return BasicUser

    def _makeOne(self, name, password, roles, domains):
        return self._getTargetClass()(name, password, roles, domains)

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IUser

        verifyClass(IUser, self._getTargetClass())

    def _makeDerived(self, **kw):
        class Derived(self._getTargetClass()):
            def __init__(self, **kw):
                self.name = 'name'
                self.password = 'password'
                self.roles = ['Manager']
                self.domains = []
                self.__dict__.update(kw)
        return Derived(**kw)

    def test_ctor_is_abstract(self):
        # Subclasses must override __init__, and mustn't call the base version.
        self.assertRaises(NotImplementedError,
                          self._makeOne, 'name', 'password', ['Manager'], [])

    def test_abstract_methods(self):
        # Subclasses must override these methods.
        derived = self._makeDerived()
        self.assertRaises(NotImplementedError, derived.getUserName)
        self.assertRaises(NotImplementedError, derived.getId)
        self.assertRaises(NotImplementedError, derived._getPassword)
        self.assertRaises(NotImplementedError, derived.getRoles)
        self.assertRaises(NotImplementedError, derived.getDomains)

    def test_getRolesInContext_no_aq_no_local_roles(self):
        derived = self._makeDerived()
        derived.getId = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Manager']
        self.assertEqual(derived.getRolesInContext(self), ['Manager'])

    def test_getRolesInContext_no_aq_w_local_roles_as_dict(self):
        class Target:
            __ac_local_roles__ = {'user': ['Other']}

        derived = self._makeDerived()
        derived.getId = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Manager']
        self.assertEqual(derived.getRolesInContext(Target()),
                         ['Manager', 'Other'])

    def test_getRolesInContext_no_aq_w_local_roles_as_callable(self):
        class Context:
            def __ac_local_roles__(self):
                return {'user': ['Other']}

        derived = self._makeDerived()
        derived.getId = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Manager']
        self.assertEqual(derived.getRolesInContext(Context()),
                         ['Manager', 'Other'])

    def test_getRolesInContext_w_aq(self):
        class Context:
            pass

        derived = self._makeDerived()
        derived.getId = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Manager']
        parent = Context()
        parent.__ac_local_roles__ = {'user': ['Another']}
        target = Context()
        target.__ac_local_roles__ = {'user': ['Other']}
        target.__parent__ = parent
        self.assertEqual(set(derived.getRolesInContext(target)),
                         {'Manager', 'Other', 'Another'})

    def test_getRolesInContext_w_method(self):
        class Context:
            __ac_local_roles__ = {'user': ['Other']}

            def method(self):
                pass

        derived = self._makeDerived()
        derived.getId = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Manager']
        target = Context()
        self.assertEqual(derived.getRolesInContext(target.method),
                         ['Manager', 'Other'])

    def test_authenticate_miss_wo_domains(self):
        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ()
        self.assertFalse(derived.authenticate('notpassword', {}))

    def test_authenticate_hit_wo_domains(self):
        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ()
        self.assertTrue(derived.authenticate('password', {}))

    def test_authenticate_hit_w_domains_any(self):
        class Request(dict):
            def getClientAddr(self):
                return '192.168.1.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('*',)
        request = Request(REMOTE_HOST='example.com')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_both(self):
        class Request(dict):
            def getClientAddr(self):
                return '192.168.1.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('127.0.0.1',)
        request = Request(REMOTE_HOST='example.com')
        self.assertFalse(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_wo_host_wo_addr(self):
        class Request(dict):
            def getClientAddr(self):
                return ''

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('127.0.0.1',)
        request = Request(REMOTE_HOST='')
        self.assertFalse(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_host_hit_addr(self):
        class Request(dict):
            def getClientAddr(self):
                return '127.0.0.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('127.0.0.1',)
        request = Request(REMOTE_HOST='example.com')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_host_hit_addr_wo_host(self):
        class Request(dict):
            def getClientAddr(self):
                return '127.0.0.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('127.0.0.1',)
        request = Request(REMOTE_HOST='')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_host_hit_addr_wo_addr(self):
        class Request(dict):
            def getClientAddr(self):
                return ''

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('127.0.0.1',)
        request = Request(REMOTE_HOST='localhost')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_addr_hit_host(self):
        class Request(dict):
            def getClientAddr(self):
                return '192.168.1.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('example.com',)
        request = Request(REMOTE_HOST='host.example.com')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_addr_hit_host_wo_addr(self):
        class Request(dict):
            def getClientAddr(self):
                return ''

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('example.com',)
        request = Request(REMOTE_HOST='host.example.com')
        self.assertTrue(derived.authenticate('password', request))

    def test_authenticate_hit_w_domains_miss_addr_hit_host_wo_host(self):
        class Request(dict):
            def getClientAddr(self):
                return '127.0.0.1'

        derived = self._makeDerived()
        derived._getPassword = lambda *x: 'password'
        derived.getDomains = lambda *x: ('localhost',)
        request = Request(REMOTE_HOST='localhost')
        self.assertTrue(derived.authenticate('password', request))

    def test_allowed__what_not_even_god_should_do(self):
        from AccessControl.PermissionRole import _what_not_even_god_should_do

        derived = self._makeDerived()
        self.assertFalse(derived.allowed(self, _what_not_even_god_should_do))

    def test_allowed_w_roles_is_None(self):
        derived = self._makeDerived()
        self.assertTrue(derived.allowed(self, None))

    def test_allowed_w_Anonymous_in_roles(self):
        derived = self._makeDerived()
        self.assertTrue(derived.allowed(self, ['Anonymous']))

    def test_allowed_w_Authenticated_in_roles_w_Anonymous(self):
        derived = self._makeDerived()
        derived.getUserName = lambda *x: 'Anonymous User'
        derived.getRoles = lambda *x: ['Anonymous']
        self.assertFalse(derived.allowed(self, ['Authenticated']))

    def test_allowed_w_Authenticated_in_roles_not_Anonymous(self):
        derived = self._makeDerived()
        derived.getUserName = lambda *x: 'user'
        self.assertTrue(derived.allowed(self, ['Authenticated']))

    def test_allowed_w_Authenticated_in_roles_not_Anonymous_context_miss(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: []
        self.assertFalse(derived.allowed(self, ['Authenticated']))

    def test_allowed_w_Authenticated_in_roles_not_Anonymous_context_hit(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: []
        self.assertTrue(derived.allowed(folder, ['Authenticated']))

    # TODO: def test_allowed_w_Shared_in_roles XXX rip that out instead

    def test_allowed_w_global_roles_hit_context_miss(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Editor']
        self.assertFalse(derived.allowed(self, ['Editor']))

    def test_allowed_w_global_roles_hit_context_hit(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Editor']
        self.assertTrue(derived.allowed(folder, ['Editor']))

    def test_allowed_w_global_roles_miss_wo_local_roles_wo_aq(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Author']
        self.assertFalse(derived.allowed(self, ['Editor']))

    def test_allowed_w_global_roles_miss_w_local_roles_miss_wo_aq(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        class Folder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        other = Folder()  # no aq
        other.__ac_local_roles__ = {'user': ['Editor']}
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Author']
        self.assertFalse(derived.allowed(other, ['Reviewer']))

    def test_allowed_w_global_roles_miss_w_local_roles_hit_wo_aq(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        class Folder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        other = Folder()  # no aq
        other.__ac_local_roles__ = {'user': ['Editor']}
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Author']
        self.assertFalse(derived.allowed(other, ['Editor']))

    def test_allowed_w_global_roles_miss_w_local_roles_hit_w_aq(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        class Folder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        other = Folder().__of__(root)
        other.__ac_local_roles__ = {'user': ['Editor']}
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: ['Author']
        self.assertTrue(derived.allowed(other, ['Editor']))

    def test_has_role_w_str_wo_context_miss(self):
        derived = self._makeDerived()
        derived.getRoles = lambda *x: ['Author']
        self.assertFalse(derived.has_role('Editor'))

    def test_has_role_w_list_wo_context_hit(self):
        derived = self._makeDerived()
        derived.getRoles = lambda *x: ['Author']
        self.assertTrue(derived.has_role(['Author']))

    def test_has_role_w_list_w_context_miss(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class Folder(Implicit):
            pass

        root = Root()
        root.__ac_local_roles__ = {'user': ['Editor']}
        folder = Folder().__of__(root)
        derived = self._makeDerived()
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: []
        self.assertFalse(derived.has_role(['Author'], folder))

    def test_has_role_w_list_w_context_hit(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class Folder(Implicit):
            pass

        root = Root()
        root.__ac_local_roles__ = {'user': ['Editor']}
        folder = Folder().__of__(root)
        derived = self._makeDerived()
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: []
        self.assertTrue(derived.has_role(['Editor'], folder))

    def test_has_permission_miss(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getUserName = lambda *x: 'user'
        derived.getRoles = lambda *x: []
        self.assertFalse(derived.has_permission('Permission', folder))

    def test_has_permission_hit(self):
        from Acquisition import Implicit

        class Root(Implicit):
            pass

        class UserFolder(Implicit):
            pass

        root = Root()
        folder = UserFolder().__of__(root)
        derived = self._makeDerived().__of__(folder)
        derived.getRoles = lambda *x: ['Manager']
        self.assertTrue(derived.has_permission('Permission', folder))

    def test___len__(self):
        derived = self._makeDerived()
        self.assertEqual(len(derived), 1)

    def test___str__(self):
        derived = self._makeDerived(getUserName=lambda: 'phred')
        self.assertEqual(str(derived), 'phred')

    def test___repr__(self):
        derived = self._makeDerived(getUserName=lambda: 'phred')
        self.assertEqual(repr(derived), "<Derived 'phred'>")


class SimpleUserTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.users import SimpleUser
        return SimpleUser

    def _makeOne(self, name='admin', password='123', roles=None, domains=None):
        if roles is None:
            roles = ['Manager']
        if domains is None:
            domains = []
        return self._getTargetClass()(name, password, roles, domains)

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IUser

        verifyClass(IUser, self._getTargetClass())

    def test_overrides(self):
        simple = self._makeOne()
        self.assertEqual(simple.getUserName(), 'admin')
        self.assertEqual(simple.getId(), 'admin')
        self.assertEqual(simple._getPassword(), '123')
        self.assertEqual(simple.getDomains(), ())

    def test_getRoles_anonymous(self):
        simple = self._makeOne('Anonymous User', roles=())
        self.assertEqual(simple.getRoles(), ())

    def test_getRoles_non_anonymous(self):
        simple = self._makeOne('phred', roles=())
        self.assertEqual(simple.getRoles(), ('Authenticated',))

    def test___repr__(self):
        special = self._makeOne()
        self.assertEqual(repr(special), "<SimpleUser 'admin'>")


class SpecialUserTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.users import SpecialUser
        return SpecialUser

    def _makeOne(self, name='admin', password='123', roles=None, domains=None):
        if roles is None:
            roles = ['Manager']
        if domains is None:
            domains = []
        return self._getTargetClass()(name, password, roles, domains)

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IUser

        verifyClass(IUser, self._getTargetClass())

    def test_overrides(self):
        special = self._makeOne()
        self.assertEqual(special.getUserName(), 'admin')
        self.assertEqual(special.getId(), None)
        self.assertEqual(special._getPassword(), '123')
        self.assertEqual(special.getDomains(), ())

    def test___repr__(self):
        special = self._makeOne()
        self.assertEqual(repr(special), "<SpecialUser 'admin'>")


class UnrestrictedUserTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.users import UnrestrictedUser
        return UnrestrictedUser

    def _makeOne(self, name='admin', password='123', roles=None, domains=None):
        if roles is None:
            roles = ['Manager']
        if domains is None:
            domains = []
        return self._getTargetClass()(name, password, roles, domains)

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IUser

        verifyClass(IUser, self._getTargetClass())

    def test_allowed__what_not_even_god_should_do(self):
        from AccessControl.PermissionRole import _what_not_even_god_should_do
        unrestricted = self._makeOne()
        self.assertFalse(unrestricted.allowed(self,
                                              _what_not_even_god_should_do))

    def test_allowed_empty(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.allowed(self, ()))

    def test_allowed_other(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.allowed(self, ('Manager',)))

    def test_has_role_empty_no_object(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.has_role(()))

    def test_has_role_empty_w_object(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.has_role((), self))

    def test_has_role_other_no_object(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.has_role(('Manager',)))

    def test_has_role_other_w_object(self):
        unrestricted = self._makeOne()
        self.assertTrue(unrestricted.has_role(('Manager',), self))

    def test___repr__(self):
        unrestricted = self._makeOne()
        self.assertEqual(repr(unrestricted),
                         "<UnrestrictedUser 'admin'>")


class NullUnrestrictedUserTests(unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.users import NullUnrestrictedUser
        return NullUnrestrictedUser

    def _makeOne(self):
        return self._getTargetClass()()

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IUser

        verifyClass(IUser, self._getTargetClass())

    def test_overrides(self):
        simple = self._makeOne()
        self.assertEqual(simple.getUserName(), (None, None))
        self.assertEqual(simple.getId(), None)
        self.assertEqual(simple._getPassword(), (None, None))
        self.assertEqual(simple.getRoles(), ())
        self.assertEqual(simple.getDomains(), ())

    def test_getRolesInContext(self):
        null = self._makeOne()
        self.assertEqual(null.getRolesInContext(self), ())

    def test_authenticate(self):
        null = self._makeOne()
        self.assertFalse(null.authenticate('password', {}))

    def test_allowed(self):
        null = self._makeOne()
        self.assertFalse(null.allowed(self, ()))

    def test_has_role(self):
        null = self._makeOne()
        self.assertFalse(null.has_role('Authenticated'))

    def test_has_role_w_object(self):
        null = self._makeOne()
        self.assertFalse(null.has_role('Authenticated', self))

    def test_has_permission(self):
        null = self._makeOne()
        self.assertFalse(null.has_permission('View', self))

    def test___repr__(self):
        null = self._makeOne()
        self.assertEqual(repr(null), "<NullUnrestrictedUser (None, None)>")

    def test___str__(self):
        # See https://bugs.launchpad.net/zope2/+bug/142563
        null = self._makeOne()
        self.assertEqual(str(null), "<NullUnrestrictedUser (None, None)>")
