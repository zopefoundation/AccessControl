##############################################################################
#
# Copyright (c) 2005 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""AccessControl interfaces.
"""

from AccessControl.SimpleObjectPolicies import _noroles
from zope.interface import Attribute
from zope.interface import Interface


class IOwned(Interface):

    def owner_info():
        """Get ownership info for display
        """

    def getOwner(info=0):
        """Get the owner

        If a true argument is provided, then only the owner path and id are
        returned. Otherwise, the owner object is returned.
        """

    def getOwnerTuple():
        """Return a tuple, (userdb_path, user_id) for the owner.

        o Ownership can be acquired, but only from the containment path.

        o If unowned, return None.
        """

    def getWrappedOwner():
        """Get the owner, modestly wrapped in the user folder.

        o If the object is not owned, return None.

        o If the owner's user database doesn't exist, return Nobody.

        o If the owner ID does not exist in the user database, return Nobody.
        """

    def changeOwnership(user, recursive=0):
        """Change the ownership to the given user.

        If 'recursive' is true then also take ownership of all sub-objects,
        otherwise sub-objects retain their ownership information.
        """

    def userCanTakeOwnership():
        """
        """

    def _deleteOwnershipAfterAdd():
        """
        """

    def manage_fixupOwnershipAfterAdd():
        """
        """


class IPermissionMappingSupport(Interface):

    def manage_getPermissionMapping():
        """Return the permission mapping for the object

        This is a list of dictionaries with:

          permission_name -- The name of the native object permission

          class_permission -- The class permission the permission is
             mapped to.
        """

    def manage_setPermissionMapping(permission_names=[],
                                    class_permissions=[], REQUEST=None):
        """Change the permission mapping
        """


class IRoleManager(IPermissionMappingSupport):

    """An object that has configurable permissions"""

    permissionMappingPossibleValues = Attribute("""Acquired attribute""")

    def ac_inherited_permissions(all=0):
        """Get all permissions not defined in ourself that are inherited.

        This will be a sequence of tuples with a name as the first item and an
        empty tuple as the second.
        """

    def permission_settings(permission=None):
        """Return user-role permission settings.

        If 'permission' is passed to the method then only the settings for
        'permission' is returned.
        """

    def manage_role(role_to_manage, permissions=[]):
        """Change the permissions given to the given role.
        """

    def manage_acquiredPermissions(permissions=[]):
        """Change the permissions that acquire.
        """

    def manage_permission(permission_to_manage, roles=[], acquire=0):
        """Change the settings for the given permission.

        If optional arg acquire is true, then the roles for the permission
        are acquired, in addition to the ones specified, otherwise the
        permissions are restricted to only the designated roles.
        """

    def permissionsOfRole(role):
        """Returns a role to permission mapping.
        """

    def rolesOfPermission(permission):
        """Returns a permission to role mapping.
        """

    def acquiredRolesAreUsedBy(permission):
        """
        """

    def has_local_roles():
        """
        """

    def get_local_roles():
        """
        """

    def users_with_local_role(role):
        """
        """

    def get_valid_userids():
        """
        """

    def get_local_roles_for_userid(userid):
        """
        """

    def manage_addLocalRoles(userid, roles):
        """Set local roles for a user."""

    def manage_setLocalRoles(userid, roles):
        """Set local roles for a user."""

    def manage_delLocalRoles(userids):
        """Remove all local roles for a user."""

    def access_debug_info():
        """Return debug info.
        """

    def valid_roles():
        """Return list of valid roles.
        """

    def validate_roles(roles):
        """Return true if all given roles are valid.
        """

    def userdefined_roles():
        """Return list of user-defined roles.
        """

    def possible_permissions():
        """
        """

    def manage_getUserRolesAndPermissions(user_id):
        """ Used for permission/role reporting for a given user_id.
            Returns a dict mapping

            'user_defined_in' -> path where the user account is defined
            'roles' -> global roles,
            'roles_in_context' -> roles in context of the current object,
            'allowed_permissions' -> permissions allowed for the user,
            'disallowed_permissions' -> all other permissions
        """


class IStandardUserFolder(Interface):

    def getUser(name):
        """Get the user object specified by name.

        If there is no user named 'name' in the user folder, return None.
        """

    def getUsers():
        """Get a sequence of all user objects which reside in the user folder.
        """

    def getUserNames():
        """Get a sequence of names of the users which reside in the user folder.
        """


class IUser(Interface):

    """Public User object interface.

    This interface needs to be supported by objects that are returned by user
    validation and used for access control.
    """

    def getId():
        """Get the ID of the user.

        The ID can be used from Python to get the user from the user's
        UserDatabase.
        """

    def getUserName():
        """Get the name used by the user to log into the system.

        Note that this may not be identical to the user's 'getId' (to allow
        users to change their login names without changing their identity).
        """

    def getRoles():
        """Get a sequence of the global roles assigned to the user.
        """

    def getRolesInContext(object):
        """Get a sequence of the roles assigned to the user in a context.

        Roles include both global roles (ones assigned to the user directly
        inside the user folder) and local roles (assigned in context of the
        passed in object).
        """

    def getDomains():
        """Get a sequence of the domain restrictions for the user.
        """


class ISecurityPolicy(Interface):

    """Plug-in policy for checking access to objects within untrusted code.
    """

    def validate(accessed, container, name, value, context, roles=_noroles):
        """Check that the current user (from context) has access.

        o Raise Unauthorized if access is not allowed;  otherwise, return
          a true value.

        Arguments:

        accessed -- the object that was being accessed

        container -- the object the value was found in

        name -- The name used to access the value

        value -- The value retrieved though the access.

        context -- the security context (normally supplied by the security
                   manager).

        roles -- The roles of the object if already known.
        """

    def checkPermission(permission, object, context):
        """Check whether the current user has a permission w.r.t. an object.
        """


class ISecurityManager(Interface):

    """Check access and manages executable context and policies.
    """

    _policy = Attribute(u'Current Security Policy')

    def validate(accessed=None,
                 container=None,
                 name=None,
                 value=None,
                 roles=_noroles,
                 ):
        """Validate access.

        Arguments:

        accessed -- the object that was being accessed

        container -- the object the value was found in

        name -- The name used to access the value

        value -- The value retrieved though the access.

        roles -- The roles of the object if already known.

        The arguments may be provided as keyword arguments. Some of these
        arguments may be ommitted, however, the policy may reject access
        in some cases when arguments are ommitted.  It is best to provide
        all the values possible.
        """

    def DTMLValidate(accessed=None,
                     container=None,
                     name=None,
                     value=None,
                     md=None,
                     ):
        """Validate access.
        * THIS EXISTS FOR DTML COMPATIBILITY *

        Arguments:

        accessed -- the object that was being accessed

        container -- the object the value was found in

        name -- The name used to access the value

        value -- The value retrieved though the access.

        md -- multidict for DTML (ignored)

        The arguments may be provided as keyword arguments. Some of these
        arguments may be ommitted, however, the policy may reject access
        in some cases when arguments are ommitted.  It is best to provide
        all the values possible.

        """

    def checkPermission(permission, object):
        """Check whether the security context allows the given permission on
        the given object.

        Arguments:

        permission -- A permission name

        object -- The object being accessed according to the permission
        """

    def addContext(anExecutableObject):
        """Add an ExecutableObject to the current security context.

        o If it declares a custom security policy,  make that policy
          "current";  otherwise, make the "default" security policy
          current.
        """

    def removeContext(anExecutableObject):
        """Remove an ExecutableObject from the current security context.

        o Remove all objects from the top of the stack "down" to the
          supplied object.

        o If the top object on the stack declares a custom security policy,
          make that policy "current".

        o If the stack is empty, or if the top declares no custom security
          policy, restore the 'default" security policy as current.
        """

    def getUser():
        """Get the currently authenticated user
        """

    def calledByExecutable():
        """Return a boolean value indicating whether this context was called
           in the context of an by an executable (i.e., one added via
           'addContext').
        """
