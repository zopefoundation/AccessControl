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

from zope.deferredimport import deprecated

# BBB
from AccessControl.rolemanager import DEFAULTMAXLISTUSERS
from AccessControl.rolemanager import _isBeingUsedAsAMethod
from AccessControl.rolemanager import _isNotBeingUsedAsAMethod
from AccessControl.rolemanager import class_attrs
from AccessControl.rolemanager import class_dict
from AccessControl.rolemanager import classattr
from AccessControl.rolemanager import gather_permissions
from AccessControl.rolemanager import instance_attrs
from AccessControl.rolemanager import instance_dict
from AccessControl.rolemanager import reqattr


deprecated(
    "RoleManager has moved to OFS.role. Please "
    "depend on Zope and import from OFS.role or use the new minimal "
    "RoleManager class from AccessControl.rolemanager. "
    "This backward compatibility shim will be removed in AccessControl "
    "version 5.",
    RoleManager='OFS.role:RoleManager',
)
