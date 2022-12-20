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
"""Access control package.
"""


import os
import re
import socket

from Acquisition import Implicit
from Acquisition import aq_inContextOf
from AuthEncoding import AuthEncoding
from Persistence import Persistent
from zope.interface import implementer

from AccessControl import SpecialUsers
from AccessControl.interfaces import IUser
from AccessControl.PermissionRole import _what_not_even_god_should_do
from AccessControl.PermissionRole import rolesForPermissionOn


_marker = []


@implementer(IUser)
class BasicUser(Implicit):

    """Base class for all User objects"""
    zmi_icon = 'fa fa-user'

    # ----------------------------
    # Public User object interface
    # ----------------------------

    # Maybe allow access to unprotected attributes. Note that this is
    # temporary to avoid exposing information but without breaking
    # everyone's current code. In the future the security will be
    # clamped down and permission-protected here. Because there are a
    # fair number of user object types out there, this method denies
    # access to names that are private parts of the standard User
    # interface or implementation only. The other approach (only
    # allowing access to public names in the User interface) would
    # probably break a lot of other User implementations with extended
    # functionality that we cant anticipate from the base scaffolding.
    def __allow_access_to_unprotected_subobjects__(self, name, value=None):
        deny_names = (
            'name',
            '__',
            'roles',
            'domains',
            '_getPassword',
            'authenticate',
        )
        if name in deny_names:
            return 0
        return 1

    def __init__(self, name, password, roles, domains):
        raise NotImplementedError

    def getId(self):
        """Get the ID of the user.
        """
        return self.getUserName()

    def getUserName(self):
        """Get the name used by the user to log into the system.
        """
        raise NotImplementedError

    def getRoles(self):
        """Get a sequence of the global roles assigned to the user.
        """
        raise NotImplementedError

    def getRolesInContext(self, object):
        """Get a sequence of the roles assigned to the user in a context.
        """
        userid = self.getId()
        roles = self.getRoles()
        local = {}
        object = getattr(object, 'aq_inner', object)
        while True:
            local_roles = getattr(object, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles()
                dict = local_roles or {}
                for r in dict.get(userid, []):
                    local[r] = 1
            inner = getattr(object, 'aq_inner', object)
            parent = getattr(inner, '__parent__', None)
            if parent is not None:
                object = parent
                continue
            if getattr(object, '__self__', None) is not None:
                object = object.__self__
                object = getattr(object, 'aq_inner', object)
                continue
            break
        roles = list(roles) + list(local.keys())
        return roles

    def getDomains(self):
        """Get a sequence of the domain restrictions for the user.
        """
        raise NotImplementedError

    # ------------------------------
    # Internal User object interface
    # ------------------------------

    def _getPassword(self):
        """Return the password of the user.
        """
        raise NotImplementedError

    def authenticate(self, password, request):
        passwrd = self._getPassword()
        result = AuthEncoding.pw_validate(passwrd, password)
        domains = self.getDomains()
        if domains:
            return result and domainSpecMatch(domains, request)
        return result

    def _check_context(self, object):
        # Check that 'object' exists in the acquisition context of
        # the parent of the acl_users object containing this user,
        # to prevent "stealing" access through acquisition tricks.
        # Return true if in context, false if not or if context
        # cannot be determined (object is not wrapped).
        parent = getattr(self, '__parent__', None)
        context = getattr(parent, '__parent__', None)
        if context is not None:
            if object is None:
                return 1
            if getattr(object, '__self__', None) is not None:
                # This is a method.  Grab its self.
                object = object.__self__
            return aq_inContextOf(object, context, 1)

        # This is lame, but required to keep existing behavior.
        return 1

    def allowed(self, object, object_roles=None):
        """Check whether the user has access to object. The user must
           have one of the roles in object_roles to allow access."""

        if object_roles is _what_not_even_god_should_do:
            return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        if 'Authenticated' in object_roles and \
                self.getUserName() != 'Anonymous User':
            if self._check_context(object):
                return 1

        # Check for a role match with the normal roles given to
        # the user, then with local roles only if necessary. We
        # want to avoid as much overhead as possible.
        user_roles = self.getRoles()
        for role in object_roles:
            if role in user_roles:
                if self._check_context(object):
                    return 1
                return None

        # Still have not found a match, so check local roles. We do
        # this manually rather than call getRolesInContext so that
        # we can incur only the overhead required to find a match.
        inner_obj = getattr(object, 'aq_inner', object)
        userid = self.getId()
        parents = set()
        while True:
            local_roles = getattr(inner_obj, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles()
                dict = local_roles or {}
                local_roles = dict.get(userid, [])
                for role in object_roles:
                    if role in local_roles:
                        if self._check_context(object):
                            return 1
                        return 0
            inner = getattr(inner_obj, 'aq_inner', inner_obj)
            parent = getattr(inner, '__parent__', None)
            if parent is not None:
                if parent in parents:
                    break
                parents.add(parent)
                inner_obj = parent
                continue
            if getattr(inner_obj, '__self__', None) is not None:
                inner_obj = inner_obj.__self__
                inner_obj = getattr(inner_obj, 'aq_inner', inner_obj)
                continue
            break
        return None

    domains = []

    def has_role(self, roles, object=None):
        """Check if the user has at least one role from a list of roles.

        If object is specified, check in the context of the passed in object.
        """
        if isinstance(roles, str):
            roles = [roles]
        if object is not None:
            user_roles = self.getRolesInContext(object)
        else:
            # Global roles only...
            user_roles = self.getRoles()
        for role in roles:
            if role in user_roles:
                return 1
        return 0

    def has_permission(self, permission, object):
        """Check if the user has a permission on an object.

        This method is just for inspecting permission settings. For access
        control use getSecurityManager().checkPermission() instead.
        """
        roles = rolesForPermissionOn(permission, object)
        if isinstance(roles, str):
            roles = [roles]
        return self.allowed(object, roles)

    def __len__(self):
        return 1

    def __str__(self):
        return self.getUserName()

    def __repr__(self):
        return '<{} {!r}>'.format(self.__class__.__name__, self.getUserName())


class SimpleUser(BasicUser):
    """A very simple user implementation

    that doesn't make a database commitment"""

    def __init__(self, name, password, roles, domains):
        self.name = name
        self.__ = password
        self.roles = roles
        self.domains = domains

    def getUserName(self):
        """Get the name used by the user to log into the system.
        """
        return self.name

    def getRoles(self):
        """Get a sequence of the global roles assigned to the user.
        """
        if self.name == 'Anonymous User':
            return tuple(self.roles)
        else:
            return tuple(self.roles) + ('Authenticated', )

    def getDomains(self):
        """Get a sequence of the domain restrictions for the user.
        """
        return tuple(self.domains)

    def _getPassword(self):
        """Return the password of the user.
        """
        return self.__


class SpecialUser(SimpleUser):
    """Class for special users, like emergency user and nobody"""

    def getId(self):
        pass


class User(SimpleUser, Persistent):
    """Standard User object"""


class UnrestrictedUser(SpecialUser):
    """User that passes all security checks.  Note, however, that modules
    like Owner.py can still impose restrictions.
    """

    def allowed(self, parent, roles=None):
        return roles is not _what_not_even_god_should_do

    def has_role(self, roles, object=None):
        return 1

    def has_permission(self, permission, object):
        return 1


class NullUnrestrictedUser(SpecialUser):
    """User created if no emergency user exists. It is only around to
       satisfy third party userfolder implementations that may
       expect the emergency user to exist and to be able to call certain
       methods on it (in other words, backward compatibility).

       Note that when no emergency user is installed, this object that
       exists in its place is more of an anti-superuser since you cannot
       login as this user and it has no privileges at all."""

    __null_user__ = 1

    def __init__(self):
        pass

    def getUserName(self):
        # return an unspellable username
        return (None, None)
    _getPassword = getUserName

    def getRoles(self):
        return ()
    getDomains = getRoles

    def getRolesInContext(self, object):
        return ()

    def authenticate(self, password, request):
        return 0

    def allowed(self, parent, roles=None):
        return 0

    def has_role(self, roles, object=None):
        return 0

    def has_permission(self, permission, object):
        return 0

    def __str__(self):
        return repr(self)


def readUserAccessFile(filename):
    '''Reads an access file from the instance home.
    Returns name, password, domains, remote_user_mode.
    '''
    environ = os.environ
    instancehome = environ.get('INSTANCE_HOME', None)
    if not instancehome:
        return None

    try:
        with open(os.path.join(instancehome, filename), 'rb') as f:
            line = f.readline()
    except OSError:
        return None

    if line:
        data = line.strip().split(b':')
        user = data[0].decode('utf-8')
        remote_user_mode = not data[1]
        try:
            ds = data[2].split(b' ')
        except IndexError:
            ds = []
        return (user, data[1], ds, remote_user_mode)
    else:
        return None


# Create emergency user.
_remote_user_mode = 0

info = readUserAccessFile('access')
if info:
    _remote_user_mode = info[3]
    emergency_user = UnrestrictedUser(info[0], info[1], ('manage', ), info[2])
else:
    emergency_user = NullUnrestrictedUser()

del info


nobody = SpecialUser('Anonymous User', '', ('Anonymous', ), [])
system = UnrestrictedUser('System Processes', '', ('manage', ), [])

# stuff these in a handier place for importing
SpecialUsers.nobody = nobody
SpecialUsers.system = system
SpecialUsers.emergency_user = emergency_user
# Note: use of the 'super' name is deprecated.
SpecialUsers.super = emergency_user


def rolejoin(roles, other):
    return sorted(set(roles).union(other))


addr_match = re.compile(r'((\d{1,3}\.){1,3}\*)|((\d{1,3}\.){3}\d{1,3})').match
host_match = re.compile(r'(([\_0-9a-zA-Z\-]*\.)*[0-9a-zA-Z\-]*)').match


def domainSpecMatch(spec, request):
    # Fast exit for the match-all case
    if len(spec) == 1 and spec[0] == '*':
        return 1

    host = request.get('REMOTE_HOST', '')
    addr = request.getClientAddr()

    if not host and not addr:
        return 0

    if not host:
        try:
            host = socket.gethostbyaddr(addr)[0]
        except Exception:
            pass

    if not addr:
        try:
            addr = socket.gethostbyname(host)
        except Exception:
            # always define localhost, even if the underlying system
            # doesn't know about it, this fixes tests on travis
            if host == 'localhost':
                addr = '127.0.0.1'

    _host = host.split('.')
    _addr = addr.split('.')
    _hlen = len(_host)

    for ob in spec:
        sz = len(ob)
        _ob = ob.split('.')
        _sz = len(_ob)

        mo = addr_match(ob)
        if mo is not None:
            if mo.end(0) == sz:
                fail = 0
                for i in range(_sz):
                    a = _addr[i]
                    o = _ob[i]
                    if (o != a) and (o != '*'):
                        fail = 1
                        break
                if fail:
                    continue
                return 1

        mo = host_match(ob)
        if mo is not None:
            if mo.end(0) == sz:
                if _hlen < _sz:
                    continue
                elif _hlen > _sz:
                    _item = _host[-_sz:]
                else:
                    _item = _host
                fail = 0
                for i in range(_sz):
                    h = _item[i]
                    o = _ob[i]
                    if (o != h) and (o != '*'):
                        fail = 1
                        break
                if fail:
                    continue
                return 1
    return 0


def absattr(attr):
    if callable(attr):
        return attr()
    return attr


def reqattr(request, attr):
    try:
        return request[attr]
    except BaseException:
        return None
