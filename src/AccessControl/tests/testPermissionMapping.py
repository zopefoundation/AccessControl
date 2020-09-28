import unittest


class TestRoleManager(unittest.TestCase):

    def test_interfaces(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IPermissionMappingSupport
        from AccessControl.PermissionMapping import RoleManager

        verifyClass(IPermissionMappingSupport, RoleManager)
