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

# BBB
from AccessControl.users import emergency_user
from AccessControl.users import UnrestrictedUser
from AccessControl.users import UnrestrictedUser as Super
from AccessControl.users import _remote_user_mode
from AccessControl.users import absattr
from AccessControl.users import addr_match
from AccessControl.users import BasicUser
from AccessControl.users import domainSpecMatch
from AccessControl.users import host_match
from AccessControl.users import nobody
from AccessControl.users import NullUnrestrictedUser
from AccessControl.users import readUserAccessFile
from AccessControl.users import reqattr
from AccessControl.users import rolejoin
from AccessControl.users import SimpleUser
from AccessControl.users import SpecialUser
from AccessControl.users import system
from AccessControl.users import User
from zope.deferredimport import deprecated


deprecated(
    "User folders are no longer part of AccessControl, please depend "
    "on Zope2 and import from OFS.userfolder or use the new minimal "
    "user folder classes from AccessControl.userfolder.",
    BasicUserFolder='OFS.userfolder:BasicUserFolder',
    manage_addUserFolder='OFS.userfolder:manage_addUserFolder',
    UserFolder='OFS.userfolder:UserFolder',
)
