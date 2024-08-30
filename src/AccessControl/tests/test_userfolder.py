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


# TODO class Test_readUserAccessFile(unittest.TestCase)


# TODO class BasicUserFoldertests(unittest.TestCase)


class UserFolderTests(unittest.TestCase):

    def setUp(self):
        import transaction
        transaction.begin()

    def tearDown(self):
        import transaction

        from AccessControl.SecurityManagement import noSecurityManager
        noSecurityManager()
        transaction.abort()

    def _getTargetClass(self):
        from AccessControl.userfolder import UserFolder
        return UserFolder

    def _makeOne(self):
        uf = self._getTargetClass()()
        uf._doAddUser('user1', 'secret', ['role1'], [])
        return uf

    def _makeBasicAuthToken(self, creds='user1:secret'):
        import base64
        return 'Basic %s' % base64.b64encode(creds.encode()).decode()

    def _login(self, uf, name):
        from AccessControl.SecurityManagement import newSecurityManager
        user = uf.getUserById(name)
        user = user.__of__(uf)
        newSecurityManager(None, user)

    def test_class_conforms_to_IStandardUserFolder(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import IStandardUserFolder
        verifyClass(IStandardUserFolder, self._getTargetClass())

    def testGetUser(self):
        uf = self._makeOne()
        self.assertNotEqual(uf.getUser('user1'), None)

    def testGetBadUser(self):
        uf = self._makeOne()
        self.assertEqual(uf.getUser('user2'), None)

    def testGetUserById(self):
        uf = self._makeOne()
        self.assertNotEqual(uf.getUserById('user1'), None)

    def testGetBadUserById(self):
        uf = self._makeOne()
        self.assertEqual(uf.getUserById('user2'), None)

    def testGetUsers(self):
        uf = self._makeOne()
        users = uf.getUsers()
        self.assertTrue(users)
        self.assertEqual(users[0].getUserName(), 'user1')

    def testGetUserNames(self):
        uf = self._makeOne()
        names = uf.getUserNames()
        self.assertTrue(names)
        self.assertEqual(names[0], 'user1')

    def testIdentify(self):
        uf = self._makeOne()
        authtoken = self._makeBasicAuthToken()

        # Test with an unencoded value
        name, password = uf.identify(authtoken)
        self.assertEqual(name, 'user1')
        self.assertEqual(password, 'secret')

        # Test with a binary string
        name, password = uf.identify(authtoken.encode('UTF-8'))
        self.assertEqual(name, 'user1')
        self.assertEqual(password, 'secret')

    def testGetRoles(self):
        uf = self._makeOne()
        user = uf.getUser('user1')
        self.assertIn('role1', user.getRoles())

    def testMaxListUsers(self):
        # create a folder-ish thing which contains a roleManager,
        # then put an acl_users object into the folde-ish thing
        from AccessControl.userfolder import BasicUserFolder

        class Folderish(BasicUserFolder):
            def __init__(self, size, count):
                self.maxlistusers = size
                self.users = []
                self.acl_users = self
                self.__allow_groups__ = self
                for i in range(count):
                    self.users.append("Nobody")

            def getUsers(self):
                return self.users

            def user_names(self):
                return self.getUsers()

        tinyFolderOver = Folderish(15, 20)
        tinyFolderUnder = Folderish(15, 10)

        assert tinyFolderOver.maxlistusers == 15
        assert tinyFolderUnder.maxlistusers == 15
        assert len(tinyFolderOver.user_names()) == 20
        assert len(tinyFolderUnder.user_names()) == 10

        try:
            tinyFolderOver.get_valid_userids()
            assert 0, "Did not raise overflow error"
        except OverflowError:
            pass

        try:
            tinyFolderUnder.get_valid_userids()
            pass
        except OverflowError:
            assert 0, "Raised overflow error erroneously"

    def test__doAddUser_with_not_yet_encrypted_passwords(self):
        # See collector #1869 && #1926
        from AuthEncoding.AuthEncoding import pw_validate

        USER_ID = 'not_yet_encrypted'
        PASSWORD = 'password'

        uf = self._makeOne()
        uf.encrypt_passwords = True
        self.assertFalse(uf._isPasswordEncrypted(PASSWORD))

        uf._doAddUser(USER_ID, PASSWORD, [], [])
        user = uf.getUserById(USER_ID)
        self.assertTrue(uf._isPasswordEncrypted(user.__))
        self.assertTrue(pw_validate(user.__, PASSWORD))

    def test__doAddUser_with_preencrypted_passwords(self):
        # See collector #1869 && #1926
        from AuthEncoding.AuthEncoding import pw_validate

        USER_ID = 'already_encrypted'
        PASSWORD = 'password'

        uf = self._makeOne()
        uf.encrypt_passwords = True
        ENCRYPTED = uf._encryptPassword(PASSWORD)

        uf._doAddUser(USER_ID, ENCRYPTED, [], [])
        user = uf.getUserById(USER_ID)
        self.assertEqual(user.__, ENCRYPTED)
        self.assertTrue(uf._isPasswordEncrypted(user.__))
        self.assertTrue(pw_validate(user.__, PASSWORD))

    def test_acquisition_influences_encryption(self):
        from Acquisition import Implicit

        class ImplicitContainer(Implicit):
            pass

        uf = self._makeOne()
        fake_parent = ImplicitContainer()
        wrapped_uf = uf.__of__(fake_parent)

        # Make sure that acquisition works for this fixture
        setattr(fake_parent, 'testflag', True)
        self.assertTrue(wrapped_uf.testflag)

        # The real test. Can we influence the ``encrypt_passwords`` flag?
        setattr(fake_parent, 'encrypt_passwords', False)
        self.assertTrue(wrapped_uf.encrypt_passwords)
