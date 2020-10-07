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

from zope.deferredimport import deprecated


deprecated(
    "The functionality of AccessControl.User has moved to"
    " AccessControl.users. Please import from there."
    " This backward compatibility shim will be removed in AccessControl"
    " version 6.",
    BasicUser='AccessControl.users:BasicUser',
    NullUnrestrictedUser='AccessControl.users:NullUnrestrictedUser',
    SimpleUser='AccessControl.users:SimpleUser',
    SpecialUser='AccessControl.users:SpecialUser',
    Super='AccessControl.users:UnrestrictedUser',
    UnrestrictedUser='AccessControl.users:UnrestrictedUser',
    User='AccessControl.users:User',
    _remote_user_mode='AccessControl.users:_remote_user_mode',
    absattr='AccessControl.users:absattr',
    addr_match='AccessControl.users:addr_match',
    domainSpecMatch='AccessControl.users:domainSpecMatch',
    emergency_user='AccessControl.users:emergency_user',
    host_match='AccessControl.users:host_match',
    nobody='AccessControl.users:nobody',
    readUserAccessFile='AccessControl.users:readUserAccessFile',
    reqattr='AccessControl.users:reqattr',
    rolejoin='AccessControl.users:rolejoin',
    system='AccessControl.users:system',
)

deprecated(
    "The standard Zope user folder implementation has moved to"
    " OFS.userfolder.  Please depend on Zope and import from "
    " OFS.userfolder or use the new minimal "
    " user folder classes from AccessControl.userfolder."
    " This backward compatibility shim will be removed in AccessControl"
    " version 6.",
    BasicUserFolder='OFS.userfolder:BasicUserFolder',
    manage_addUserFolder='OFS.userfolder:manage_addUserFolder',
    UserFolder='OFS.userfolder:UserFolder',
)
