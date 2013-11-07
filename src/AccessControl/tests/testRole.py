import unittest

from AccessControl.rolemanager import RoleManager
from Acquisition import Implicit, Explicit


class DummyContext(Implicit, RoleManager):
    __roles__ = ('Manager',)


class DummyUser(Explicit):
    def getRoles(self):
        return ('Manager',)

    def getRolesInContext(self, context):
        return ('Manager',)

    def has_permission(self, permission, context):
        return True


class DummyAclUsers(Explicit):
    def getUser(self, user_id):
        user = DummyUser()
        return user.__of__(self)

    def absolute_url(self, relative=0):
        return 'acl_users'


class DummyRoot(Explicit):
    acl_users = DummyAclUsers()


class TestRoleManager(unittest.TestCase):

    def tearDown(self):
        from AccessControl.SecurityManagement import noSecurityManager
        noSecurityManager()

    def test_interfaces(self):
        from AccessControl.interfaces import IRoleManager
        from AccessControl.rolemanager import RoleManager
        from zope.interface.verify import verifyClass

        verifyClass(IRoleManager, RoleManager)

    def test_manage_getUserRolesAndPermissions(self):
        from AccessControl.ImplPython import verifyAcquisitionContext
        from AccessControl.SecurityManagement import getSecurityManager
        from AccessControl.SecurityManagement import newSecurityManager

        root = DummyRoot()
        root.acl_users = DummyAclUsers()
        user = DummyUser().__of__(root.acl_users)
        newSecurityManager(None, user)
        root.context1 = DummyContext()
        root.context2 = DummyContext()
        root.context1.manage_getUserRolesAndPermissions('dummy_user')
        user = getSecurityManager().getUser()
        self.assertIsNotNone(verifyAcquisitionContext(user, root.context2, ()))
