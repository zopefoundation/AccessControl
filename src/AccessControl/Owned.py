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
"""Support for owned objects
"""

from zope.deferredimport import deprecated

# BBB
from AccessControl.owner import EditUnowned
from AccessControl.owner import EmergencyUserCannotOwn
from AccessControl.owner import UnownableOwner
from AccessControl.owner import absattr
from AccessControl.owner import ownableFilter
from AccessControl.owner import ownerInfo


deprecated(
    "The Owned class has moved to OFS.owner. This compatibility "
    "shim will be removed in AccessControl version 5. Please "
    "depend on Zope2 and import from OFS.owner or use the "
    "new minimal Owned class from AccessControl.owner.",
    Owned='OFS.owner:Owned',
)
