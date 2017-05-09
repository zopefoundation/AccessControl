# Standard Library Imports
import unittest


class TestRoleManager(unittest.TestCase):

    def test_interfaces(self):
        from AccessControl.interfaces import IPermissionMappingSupport
        from AccessControl.PermissionMapping import RoleManager
        from zope.interface.verify import verifyClass

        verifyClass(IPermissionMappingSupport, RoleManager)
