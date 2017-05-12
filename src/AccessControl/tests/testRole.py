import unittest


def _makeRootAndUser():
    from AccessControl.rolemanager import RoleManager
    from Acquisition import Implicit
    from Acquisition import Explicit

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

    root = DummyRoot()
    root.acl_users = DummyAclUsers()
    root.context1 = DummyContext()
    root.context2 = DummyContext()
    user = DummyUser().__of__(root.acl_users)

    return root, user


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
        root, user = _makeRootAndUser()
        newSecurityManager(None, user)
        root.context1.manage_getUserRolesAndPermissions('dummy_user')
        user = getSecurityManager().getUser()
        self.assertTrue(verifyAcquisitionContext(user, root.context2, ()))

    def test_has_local_roles(self):
        root, user = _makeRootAndUser()
        self.assertFalse(root.context1.has_local_roles())

    def test_get_local_roles(self):
        root, user = _makeRootAndUser()
        root.context1.__ac_local_roles__ = {'user1': ['Role1']}
        roles = root.context1.get_local_roles()
        self.assertEqual(roles, (
            ('user1', ('Role1',)),
        ))

    def test_manage_addLocalRoles(self):
        root, user = _makeRootAndUser()
        root.context1.manage_addLocalRoles('user1', ['Role1'])
        roles = root.context1.get_local_roles_for_userid('user1')
        self.assertEqual(roles, ('Role1',))

    def test_manage_setLocalRoles(self):
        root, user = _makeRootAndUser()
        root.context1.__ac_local_roles__ = {'user1': ('Role1',)}
        root.context1.manage_setLocalRoles('user1', ['Role2'])
        roles = root.context1.get_local_roles_for_userid('user1')
        self.assertEqual(roles, ('Role2',))

    def test_manage_delLocalRoles(self):
        root, user = _makeRootAndUser()
        root.context1.__ac_local_roles__ = {'user1': ('Role1',)}
        root.context1.manage_delLocalRoles(['user1'])
        roles = root.context1.get_local_roles_for_userid('user1')
        self.assertEqual(roles, ())

    def test_valid_roles(self):
        from AccessControl.rolemanager import RoleManager
        root, user = _makeRootAndUser()

        # default case, __ac_roles__ not overridden
        self.assertEqual(set(root.context1.valid_roles()), 
                         set(RoleManager.__ac_roles__))

        # forcing our own roles
        root.context1.__ac_roles__ = ('Role2', 'Role1')
        roles = root.context1.valid_roles()
        self.assertEqual(roles, ('Role1', 'Role2'))
       
    def test_validate_roles(self):
        from AccessControl.rolemanager import RoleManager
        root, user = _makeRootAndUser()

        # default case, __ac_roles__ not overridden
        self.assertTrue(root.context1.validate_roles(RoleManager.__ac_roles__))
        self.assertFalse(root.context1.validate_roles(('Role1', 'Role2')))

        # forcing our own roles
        root.context1.__ac_roles__ = ('Role2', 'Role1')
        self.assertFalse(root.context1.validate_roles(RoleManager.__ac_roles__))
        self.assertTrue(root.context1.validate_roles(('Role1', 'Role2')))

    def test_userdefined_roles(self):
        from AccessControl.rolemanager import RoleManager
        root, user = _makeRootAndUser()

        # default case, __ac_roles__ not overridden
        self.assertEqual(root.context1.userdefined_roles(), ())

        # forcing our own roles
        root.context1.__ac_roles__ = ('Role2', 'Role1')
        self.assertEqual(set(root.context1.userdefined_roles()),
                         set(('Role1', 'Role2')))

