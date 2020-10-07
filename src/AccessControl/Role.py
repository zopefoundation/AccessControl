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


deprecated(
    "The functionality of AccessControl.Role has moved to"
    " AccessControl.rolemanager. Please import from there."
    " This backward compatibility shim will be removed in AccessControl"
    " version 6.",
    DEFAULTMAXLISTUSERS='AccessControl.rolemanager:DEFAULTMAXLISTUSERS',
    _isBeingUsedAsAMethod='AccessControl.rolemanager:_isBeingUsedAsAMethod',
    _isNotBeingUsedAsAMethod='AccessControl.rolemanager:_isNotBeingUsedAsAMethod',  # noqa
    class_attrs='AccessControl.rolemanager:class_attrs',
    class_dict='AccessControl.rolemanager:class_dict',
    classattr='AccessControl.rolemanager:classattr',
    gather_permissions='AccessControl.rolemanager:gather_permissions',
    instance_attrs='AccessControl.rolemanager:instance_attrs',
    instance_dict='AccessControl.rolemanager:instance_dict',
    reqattr='AccessControl.rolemanager:reqattr',
)
