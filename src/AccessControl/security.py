##############################################################################
#
# Copyright (c) 2004-2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Security handling
"""

import six
from zope.component import getUtility
from zope.component import queryUtility
from zope.component.zcml import utility
from zope.configuration.config import GroupingContextDecorator
from zope.configuration.interfaces import IConfigurationContext
from zope.interface import implementer
from zope.interface import Interface
from zope.interface import provider
from zope.schema import ASCIILine
from zope.security.checker import CheckerPublic
from zope.security.interfaces import IInteraction
from zope.security.interfaces import IPermission
from zope.security.interfaces import ISecurityPolicy
from zope.security.management import thread_local
from zope.security.permission import Permission
from zope.security.simplepolicies import ParanoidSecurityPolicy
from zope.security.zcml import IPermissionDirective

from AccessControl.Permission import addPermission
from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.SecurityManagement import getSecurityManager


CheckerPublicId = 'zope.Public'
CheckerPrivateId = 'zope2.Private'


def getSecurityInfo(klass):
    sec = {}
    info = vars(klass)
    if '__ac_permissions__' in info:
        sec['__ac_permissions__'] = info['__ac_permissions__']
    for k, v in info.items():
        if k.endswith('__roles__'):
            sec[k] = v
    return sec


def clearSecurityInfo(klass):
    info = vars(klass)
    if '__ac_permissions__' in info:
        delattr(klass, '__ac_permissions__')
    for k, v in list(info.items()):
        if k.endswith('__roles__'):
            delattr(klass, k)


def checkPermission(permission, object, interaction=None):
    """Return whether security policy allows permission on object.

    Arguments:
    permission -- A permission name
    object -- The object being accessed according to the permission
    interaction -- This zope.security concept has no equivalent in Zope 2,
        and is ignored.

    checkPermission is guaranteed to return True if permission is
    CheckerPublic or None.
    """
    if (permission in ('zope.Public', 'zope2.Public') or
            permission is None or permission is CheckerPublic):
        return True

    if isinstance(permission, six.string_types):
        permission = queryUtility(IPermission, six.u(permission))
        if permission is None:
            return False

    if getSecurityManager().checkPermission(permission.title, object):
        return True

    return False


@implementer(IInteraction)
@provider(ISecurityPolicy)
class SecurityPolicy(ParanoidSecurityPolicy):
    """Security policy that bridges between zope.security security mechanisms
    and Zope 2's security policy.

    Don't let the name of the base class fool you... This really just
    delegates to Zope 2's security manager."""

    def checkPermission(self, permission, object):
        return checkPermission(permission, object)


def newInteraction():
    """Con zope.security to use Zope 2's checkPermission.

    zope.security when it does a checkPermission will turn around and
    ask the thread local interaction for the checkPermission method.
    By making the interaction *be* Zope 2's security manager, we can
    con zope.security into using Zope 2's checker...
    """
    if getattr(thread_local, 'interaction', None) is None:
        thread_local.interaction = SecurityPolicy()


def _getSecurity(klass):
    # a Zope 2 class can contain some attribute that is an instance
    # of ClassSecurityInfo. Zope 2 scans through things looking for
    # an attribute that has the name __security_info__ first
    info = vars(klass)
    for k, v in info.items():
        if hasattr(v, '__security_info__'):
            return v
    # we stuff the name ourselves as __security__, not security, as this
    # could theoretically lead to name clashes, and doesn't matter for
    # zope 2 anyway.
    security = ClassSecurityInfo()
    setattr(klass, '__security__', security)
    return security


def protectName(klass, name, permission_id, override_existing_protection=True):
    """Protect the attribute 'name' on 'klass' using the given
       permission"""
    security = _getSecurity(klass)
    # Zope 2 uses string, not unicode yet
    name = str(name)
    if not override_existing_protection and \
            ('%s__roles__' % name) in dir(klass):
        # There is already a declaration for this name from a base class.
        return
    if permission_id == CheckerPublicId or permission_id is CheckerPublic:
        # Sometimes, we already get a processed permission id, which
        # can mean that 'zope.Public' has been interchanged for the
        # CheckerPublic object
        security.declarePublic(name)
    elif permission_id == CheckerPrivateId:
        security.declarePrivate(name)
    else:
        permission = getUtility(IPermission, name=permission_id)
        # Zope 2 uses string, not unicode yet
        perm = str(permission.title)
        security.declareProtected(perm, name)


def protectClass(klass, permission_id):
    """Protect the whole class with the given permission"""
    security = _getSecurity(klass)
    if permission_id == CheckerPublicId or permission_id is CheckerPublic:
        # Sometimes, we already get a processed permission id, which
        # can mean that 'zope.Public' has been interchanged for the
        # CheckerPublic object
        security.declareObjectPublic()
    elif permission_id == CheckerPrivateId:
        security.declareObjectPrivate()
    else:
        permission = getUtility(IPermission, name=permission_id)
        # Zope 2 uses string, not unicode yet
        perm = str(permission.title)
        security.declareObjectProtected(perm)


@implementer(IConfigurationContext, IPermissionDirective)
class PermissionDirective(GroupingContextDecorator):

    def __init__(self, context, id, title, description=''):
        self.context = context
        self.id, self.title, self.description = id, title, description
        self.roles = []

    def after(self):
        permission = Permission(self.id, self.title, self.description)
        utility(self.context, IPermission, permission, name=self.id)

        zope2_permission = str(self.title)
        if self.roles:
            addPermission(zope2_permission, default_roles=tuple(self.roles))
        elif self.id == CheckerPrivateId:
            addPermission(zope2_permission, default_roles=())
        else:
            addPermission(zope2_permission)


class IRoleDirective(Interface):

    name = ASCIILine()


def RoleDirective(context, name):
    permission_directive = context.context
    if name not in permission_directive.roles:
        permission_directive.roles.append(name)
