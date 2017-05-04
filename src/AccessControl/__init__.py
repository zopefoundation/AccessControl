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

# flake8: NOQA: E401

# This has to happen early so things get initialized properly
from AccessControl.Implementation import setImplementation
from AccessControl.SecurityInfo import ACCESS_NONE
from AccessControl.SecurityInfo import ACCESS_PRIVATE
from AccessControl.SecurityInfo import ACCESS_PUBLIC
from AccessControl.SecurityInfo import allow_class
from AccessControl.SecurityInfo import allow_module
from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.SecurityInfo import ModuleSecurityInfo
from AccessControl.SecurityInfo import secureModule
from AccessControl.SecurityManagement import getSecurityManager
from AccessControl.SecurityManagement import setSecurityPolicy
from AccessControl.SimpleObjectPolicies import allow_type
from AccessControl.unauthorized import Unauthorized
from AccessControl.ZopeGuards import full_write_guard
from AccessControl.ZopeGuards import safe_builtins


ModuleSecurityInfo('AccessControl').declarePublic('getSecurityManager')

# allow imports of utility_builtins

for name in ('string', 'math', 'random', 'sets'):
    ModuleSecurityInfo(name).setDefaultAccess('allow')

ModuleSecurityInfo('DateTime').declarePublic('DateTime')
