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
"""Access control support
"""

from base64 import urlsafe_b64encode

from Acquisition import Acquired
from Acquisition import aq_base
from Acquisition import aq_get
from ExtensionClass import Base
from zope.interface import implementer

from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from AccessControl.interfaces import IRoleManager
from AccessControl.Permission import getPermissions
from AccessControl.Permission import Permission
from AccessControl.PermissionMapping import RoleManager
from AccessControl.Permissions import change_permissions
from AccessControl.SecurityManagement import newSecurityManager

try:
    from html import escape
except ImportError:  # PY2
    from cgi import escape


DEFAULTMAXLISTUSERS = 250


def _isBeingUsedAsAMethod(self):
    return aq_get(self, '_isBeingUsedAsAMethod_', 0)


def _isNotBeingUsedAsAMethod(self):
    return not aq_get(self, '_isBeingUsedAsAMethod_', 0)


def _string_hash(s):
    return urlsafe_b64encode(str(s.__hash__()).encode('ascii')).decode('ascii')


@implementer(IRoleManager)
class RoleManager(Base, RoleManager):
    """An object that has configurable permissions"""
    permissionMappingPossibleValues = Acquired
    security = ClassSecurityInfo()

    __ac_roles__ = ('Manager', 'Owner', 'Anonymous', 'Authenticated')
    __ac_local_roles__ = None

    security.declareProtected(change_permissions, 'ac_inherited_permissions')
    def ac_inherited_permissions(self, all=0):
        # Get all permissions not defined in ourself that are inherited
        # This will be a sequence of tuples with a name as the first item and
        # an empty tuple as the second.
        d = {}
        perms = self.__ac_permissions__
        for p in perms:
            d[p[0]] = None

        r = gather_permissions(self.__class__, [], d)
        if all:
            if hasattr(self, '_subobject_permissions'):
                for p in self._subobject_permissions():
                    pname = p[0]
                    if pname not in d:
                        d[pname] = 1
                        r.append(p)

            r = list(perms) + r

        return tuple(sorted(r))

    security.declareProtected(change_permissions, 'permission_settings')
    def permission_settings(self, permission=None):
        """Return user-role permission settings.

        If 'permission' is passed to the method then only the settings for
        'permission' is returned.
        """
        result = []
        valid = self.valid_roles()
        indexes = range(len(valid))
        ip = 0

        permissions = self.ac_inherited_permissions(1)
        # Filter permissions
        if permission:
            permissions = [p for p in permissions if p[0] == permission]

        for p in permissions:
            permission_name = p[0]
            name, value = p[:2]
            p = Permission(name, value, self)
            roles = p.getRoles(default=[])
            d = {
                'name': name,
                'hashed_name': _string_hash(name),
                'acquire': isinstance(roles, list) and 'CHECKED' or '',
                'roles': tuple(map(
                    lambda ir, roles=roles, valid=valid, ip=ip:
                    {
                       'name': "permission_%srole_%s" % (_string_hash(permission_name), _string_hash(valid[ir])),
                       'checked': (valid[ir] in roles) and 'CHECKED' or '',
                    },
                    indexes
                ))
            }

            ip = ip + 1
            result.append(d)
        return result

    security.declareProtected(change_permissions, 'manage_role')
    def manage_role(self, role_to_manage, permissions=[]):
        """Change the permissions given to the given role.
        """
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            p = Permission(name, value, self)
            p.setRole(role_to_manage, name in permissions)

    security.declareProtected(change_permissions, 'manage_acquiredPermissions')
    def manage_acquiredPermissions(self, permissions=[]):
        """Change the permissions that acquire.
        """
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            p = Permission(name, value, self)
            roles = p.getRoles()
            if roles is None:
                continue
            if name in permissions:
                p.setRoles(list(roles))
            else:
                p.setRoles(tuple(roles))

    def manage_getUserRolesAndPermissions(self, user_id):
        """ Used for permission/role reporting for a given user_id.
            Returns a dict mapping

            'user_defined_in' -> path where the user account is defined
            'roles' -> global roles,
            'roles_in_context' -> roles in context of the current object,
            'allowed_permissions' -> permissions allowed for the user,
            'disallowed_permissions' -> all other permissions
        """
        d = {}
        current = self

        while 1:
            try:
                uf = current.acl_users
            except AttributeError:
                raise ValueError('User %s could not be found' % user_id)

            userObj = uf.getUser(user_id)
            if userObj:
                break
            else:
                current = current.__parent__

        userObj = userObj.__of__(uf)

        d = {'user_defined_in': '/' + uf.absolute_url(1)}

        # roles
        roles = sorted(userObj.getRoles())
        d['roles'] = roles

        # roles in context
        roles = sorted(userObj.getRolesInContext(self))
        d['roles_in_context'] = roles

        # permissions
        allowed = []
        disallowed = []
        permMap = self.manage_getPermissionMapping()
        for item in permMap:
            p = item['permission_name']
            if userObj.has_permission(p, self):
                allowed.append(p)
            else:
                disallowed.append(p)

        d['allowed_permissions'] = allowed
        d['disallowed_permissions'] = disallowed

        return d

    security.declareProtected(change_permissions, 'manage_permission')
    def manage_permission(self, permission_to_manage, roles=[], acquire=0):
        """Change the settings for the given permission.

        If optional arg acquire is true, then the roles for the permission
        are acquired, in addition to the ones specified, otherwise the
        permissions are restricted to only the designated roles.
        """
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            if name == permission_to_manage:
                p = Permission(name, value, self)
                if acquire:
                    roles = list(roles)
                else:
                    roles = tuple(roles)
                p.setRoles(roles)
                return

        raise ValueError(
            "The permission <em>%s</em> is invalid." %
            escape(permission_to_manage))

    security.declareProtected(change_permissions, 'permissionsOfRole')
    def permissionsOfRole(self, role):
        """Returns a role to permission mapping.
        """
        r = []
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            p = Permission(name, value, self)
            roles = p.getRoles()
            r.append({'name': name,
                      'selected': role in roles and 'SELECTED' or '',
                      })
        return r

    security.declareProtected(change_permissions, 'rolesOfPermission')
    def rolesOfPermission(self, permission):
        """Returns a permission to role mapping.
        """
        valid_roles = self.valid_roles()
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            if name == permission:
                p = Permission(name, value, self)
                roles = p.getRoles()
                return tuple(map(
                    lambda role, roles=roles:
                    {'name': role,
                     'selected': role in roles and 'SELECTED' or '',
                     },
                    valid_roles))

        raise ValueError(
            "The permission <em>%s</em> is invalid." % escape(permission))

    security.declareProtected(change_permissions, 'acquiredRolesAreUsedBy')
    def acquiredRolesAreUsedBy(self, permission):
        """
        """
        for p in self.ac_inherited_permissions(1):
            name, value = p[:2]
            if name == permission:
                p = Permission(name, value, self)
                roles = p.getRoles()
                return isinstance(roles, list) and 'CHECKED' or ''

        raise ValueError(
            "The permission <em>%s</em> is invalid." % escape(permission))

    # Local roles support
    # -------------------
    #
    # Local roles allow a user to be given extra roles in the context
    # of a particular object (and its children). When a user is given
    # extra roles in a particular object, an entry for that user is made
    # in the __ac_local_roles__ dict containing the extra roles.

    def has_local_roles(self):
        rolemap = self.__ac_local_roles__ or {}
        return len(rolemap)

    def get_local_roles(self):
        rolemap = self.__ac_local_roles__ or {}
        info = []
        for key in sorted(rolemap.keys()):
            info.append((key, tuple(rolemap[key])))
        return tuple(info)

    def users_with_local_role(self, role):
        got = {}
        for user, roles in self.get_local_roles():
            if role in roles:
                got[user] = 1
        return got.keys()

    def get_valid_userids(self):
        item = self
        userids = {}
        _notfound = []
        while 1:
            aclu = getattr(aq_base(item), '__allow_groups__', _notfound)
            if aclu is not _notfound:
                mlu = getattr(aclu, 'maxlistusers', _notfound)
                if not isinstance(mlu, int):
                    mlu = DEFAULTMAXLISTUSERS
                if mlu < 0:
                    raise OverflowError
                un = getattr(aclu, 'user_names', _notfound)
                if un is not _notfound:
                    un = aclu.__of__(item).user_names  # rewrap
                    unl = un()
                    # maxlistusers of 0 is list all
                    if len(unl) > mlu and mlu != 0:
                        raise OverflowError
                    for name in unl:
                        userids[name] = 1
            item = getattr(item, '__parent__', _notfound)
            if item is _notfound:
                break
        return tuple(sorted(userids.keys()))

    def get_local_roles_for_userid(self, userid):
        rolemap = self.__ac_local_roles__ or {}
        return tuple(rolemap.get(userid, []))

    security.declareProtected(change_permissions, 'manage_addLocalRoles')
    def manage_addLocalRoles(self, userid, roles):
        """Set local roles for a user."""
        if not roles:
            raise ValueError('One or more roles must be given!')
        rolemap = self.__ac_local_roles__
        if rolemap is None:
            self.__ac_local_roles__ = rolemap = {}
        local_roles = list(rolemap.get(userid, []))
        for r in roles:
            if r not in local_roles:
                local_roles.append(r)
        rolemap[userid] = local_roles
        self._p_changed = True

    security.declareProtected(change_permissions, 'manage_setLocalRoles')
    def manage_setLocalRoles(self, userid, roles):
        """Set local roles for a user."""
        if not roles:
            raise ValueError('One or more roles must be given!')
        rolemap = self.__ac_local_roles__
        if rolemap is None:
            self.__ac_local_roles__ = rolemap = {}
        rolemap[userid] = roles
        self._p_changed = True

    security.declareProtected(change_permissions, 'manage_delLocalRoles')
    def manage_delLocalRoles(self, userids):
        """Remove all local roles for a user."""
        rolemap = self.__ac_local_roles__
        if rolemap is None:
            self.__ac_local_roles__ = rolemap = {}
        for userid in userids:
            if userid in rolemap:
                del rolemap[userid]
        self._p_changed = True

    security.declarePrivate('access_debug_info')
    def access_debug_info(self):
        """Return debug info.
        """
        clas = class_attrs(self)
        inst = instance_attrs(self)
        data = []
        _add = data.append
        for key, value in inst.items():
            if key.find('__roles__') >= 0:
                _add({'name': key, 'value': value, 'class': 0})
            if hasattr(value, '__roles__'):
                _add({'name': '%s.__roles__' % key, 'value': value.__roles__,
                      'class': 0})
        for key, value in clas.items():
            if key.find('__roles__') >= 0:
                _add({'name': key, 'value': value, 'class': 1})
            if hasattr(value, '__roles__'):
                _add({'name': '%s.__roles__' % key, 'value': value.__roles__,
                      'class': 1})
        return data

    def valid_roles(self):
        """Return list of valid roles.
        """
        obj = self
        valid = set()
        x = 0
        while x < 100:
            valid.update(getattr(obj, '__ac_roles__', ()))
            if getattr(obj, '__parent__', None) is None:
                break
            obj = obj.__parent__
            x = x + 1
        return tuple(sorted(valid))

    def validate_roles(self, roles):
        """Return true if all given roles are valid.
        """
        return set(roles) <= set(self.valid_roles())

    security.declareProtected(change_permissions, 'userdefined_roles')
    def userdefined_roles(self):
        """Return list of user-defined roles.
        """
        default_roles = classattr(self.__class__, '__ac_roles__')
        return tuple(set(self.__ac_roles__) - set(default_roles))

    def possible_permissions(self):
        d = {}
        permissions = getPermissions()
        for p in permissions:
            d[p[0]] = 1
        for p in self.ac_inherited_permissions(1):
            d[p[0]] = 1

        d = sorted(d.keys())
        return d


InitializeClass(RoleManager)


def reqattr(request, attr):
    try:
        return request[attr]
    except:
        return None


def classattr(cls, attr):
    if hasattr(cls, attr):
        return getattr(cls, attr)
    try:
        bases = cls.__bases__
    except:
        bases = ()
    for base in bases:
        if classattr(base, attr):
            return attr
    return None


def instance_dict(inst):
    try:
        return inst.__dict__
    except:
        return {}


def class_dict(_class):
    try:
        return _class.__dict__
    except:
        return {}


def instance_attrs(inst):
    return instance_dict(inst)


def class_attrs(inst, _class=None, data=None):
    if _class is None:
        _class = inst.__class__
        data = {}

    clas_dict = class_dict(_class)
    inst_dict = instance_dict(inst)
    inst_attr = inst_dict.has_key
    for key, value in clas_dict.items():
        if not inst_attr(key):
            data[key] = value
    for base in _class.__bases__:
        data = class_attrs(inst, base, data)
    return data


def gather_permissions(klass, result, seen):
    for base in klass.__bases__:
        if '__ac_permissions__' in base.__dict__:
            for p in base.__ac_permissions__:
                name = p[0]
                if name in seen:
                    continue
                result.append((name, ()))
                seen[name] = None
        gather_permissions(base, result, seen)
    return result
