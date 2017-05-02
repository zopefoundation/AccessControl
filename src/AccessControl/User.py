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

# BBB
from .users import emergency_user as super
from .users import UnrestrictedUser as Super
from .users import _remote_user_mode
from .users import absattr
from .users import addr_match
from .users import BasicUser
from .users import domainSpecMatch
from .users import host_match
from .users import nobody
from .users import NullUnrestrictedUser
from .users import readUserAccessFile
from .users import reqattr
from .users import rolejoin
from .users import SimpleUser
from .users import SpecialUser
from .users import system
from .users import User


deprecated("User folders are no longer part of AccessControl, please depend "
           "on Zope2 and import from OFS.userfolder or use the new minimal "
           "user folder classes from AccessControl.userfolder.",
    BasicUserFolder = 'OFS.userfolder:BasicUserFolder',
    manage_addUserFolder = 'OFS.userfolder:manage_addUserFolder',
    UserFolder = 'OFS.userfolder:UserFolder',
)
