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
"""Permission Mapping

Sometimes, we need an object's permissions to be remapped to other permissions
when the object is used in special ways.  This is rather hard, since we
need the object's ordinary permissions intact so we can manage it.
"""

from Acquisition import ImplicitAcquisitionWrapper
from ExtensionClass import Base
from zope.interface import implementer

from AccessControl.class_init import InitializeClass
from AccessControl.interfaces import IPermissionMappingSupport
from AccessControl.owner import UnownableOwner
from AccessControl.Permission import getPermissionIdentifier
from AccessControl.requestmethod import requestmethod


try:
    from html import escape
except ImportError:  # PY2
    from cgi import escape


@implementer(IPermissionMappingSupport)
class RoleManager:

    # XXX: No security declarations?

    def manage_getPermissionMapping(self):
        """Return the permission mapping for the object

        This is a list of dictionaries with:

          permission_name -- The name of the native object permission

          class_permission -- The class permission the permission is
             mapped to.
        """
        wrapper = getattr(self, '_permissionMapper', None)
        if wrapper is None:
            wrapper = PM()

        perms = {}
        for p in self.possible_permissions():
            perms[getPermissionIdentifier(p)] = p

        r = []
        a = r.append
        for ac_perms in self.ac_inherited_permissions(1):
            p = perms.get(getPermissionMapping(ac_perms[0], wrapper), '')
            a({'permission_name': ac_perms[0], 'class_permission': p})
        return r

    @requestmethod('POST')
    def manage_setPermissionMapping(self,
                                    permission_names=[],
                                    class_permissions=[],
                                    REQUEST=None):
        """Change the permission mapping
        """
        wrapper = getattr(self, '_permissionMapper', None)
        if wrapper is None:
            wrapper = PM()

        perms = self.possible_permissions()
        for i in range(len(permission_names)):
            name = permission_names[i]
            p = class_permissions[i]
            if p and (p not in perms):
                __traceback_info__ = perms, p, i
                raise ValueError(
                    """Attempted to map a permission to a permission, %s,
                    that is not valid. This should never happen. (Waaa).
                    """ % escape(p))
            setPermissionMapping(name, wrapper, p)

        self._permissionMapper = wrapper

        if REQUEST is not None:
            return self.manage_access(
                REQUEST,
                manage_tabs_message='The permission mapping has been updated')

    def _isBeingUsedAsAMethod(self, REQUEST=None, wannaBe=0):
        try:
            if hasattr(self, 'aq_self'):
                r = self.aq_acquire('_isBeingUsedAsAMethod_')
            else:
                r = self._isBeingUsedAsAMethod_
        except BaseException:
            r = 0

        if REQUEST is not None:
            if not r != (not wannaBe):
                REQUEST.response.notFoundError()

        return r


InitializeClass(RoleManager)


def getPermissionMapping(name, obj, st=type('')):
    obj = getattr(obj, 'aq_base', obj)
    name = getPermissionIdentifier(name)
    r = getattr(obj, name, '')
    if not isinstance(r, st):
        r = ''
    return r


def setPermissionMapping(name, obj, v):
    name = getPermissionIdentifier(name)
    if v:
        setattr(obj, name, getPermissionIdentifier(v))
    elif name in obj.__dict__:
        delattr(obj, name)


class PM(Base):
    _owner = UnownableOwner

    _View_Permission = '_View_Permission'
    _is_wrapperish = 1

    def __getattr__(self, name):
        # We want to make sure that any non-explicitly set methods are
        # private!
        if name.startswith('_') and name.endswith("_Permission"):
            return ''
        raise AttributeError(escape(name))


PermissionMapper = PM


def aqwrap(object, wrapper, parent):
    r = Rewrapper()
    r._ugh = wrapper, object, parent
    return r


class Rewrapper(Base):
    def __of__(self, parent):
        w, m, p = self._ugh
        return m.__of__(ImplicitAcquisitionWrapper(w, parent))

    def __getattr__(self, name):
        w, m, parent = self._ugh
        self = m.__of__(ImplicitAcquisitionWrapper(w, parent))
        return getattr(self, name)

    def __call__(self, *args, **kw):
        w, m, parent = self._ugh
        self = m.__of__(ImplicitAcquisitionWrapper(w, parent))
        return self(*args, **kw)
