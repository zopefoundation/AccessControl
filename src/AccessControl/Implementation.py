##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################

"""Controller that can switch between security machinery implementations.

This module allows configuration of the security implementation after
the initial import of the modules.  It is intended to allow runtime
selection of the machinery based on Zope's configuration file.

The helper function defined here switches between the 'C' and 'PYTHON'
security implementations by loading the appropriate implementation
module and wiring the implementation into the other modules of the
AccessControl package that defined the various components before this
module was introduced.

"""
from __future__ import absolute_import

from logging import getLogger


def getImplementationName():
    """Return the name of the implementation currently being used."""
    return _implementation_name


def setImplementation(name):
    """Select the policy implementation to use. The 'name' must be either
       'PYTHON' or 'C'. NOTE: this function is intended to be called
       exactly once, so that the Zope config file can dictate the policy
       implementation to be used. Subsequent calls to this function will
       have no effect!!
    """
    import sys
    global _implementation_name
    global _implementation_set

    if _implementation_set:
        return

    name = name.upper()
    if name == _implementation_name:
        return
    impl = None
    if name == "C":
        try:
            from AccessControl import ImplC as impl
        except ImportError:  # fall back to "PYTHON"
            getLogger(__name__).warn(
                "C implementation not available -- faling back to Python",
                exc_info=True)
            name = "PYTHON"
    if name == "PYTHON":
        from AccessControl import ImplPython as impl
    if impl is None:
        raise ValueError("unknown policy implementation: %r" % name)

    _implementation_name = name
    for modname, names in _policy_names.items():
        __import__(modname)
        mod = sys.modules[modname]
        for n in names:
            setattr(mod, n, getattr(impl, n))
        if hasattr(mod, "initialize"):
            mod.initialize(impl)

    from AccessControl.SecurityManager import setSecurityPolicy
    policy = impl.ZopeSecurityPolicy(True, True)
    setSecurityPolicy(policy)

    _implementation_set = 1


# start with the default, mostly because we need something for the tests
from ExtensionClass import Base, BasePy

# use `PYTHON` if `ExtensionClass` does
_default_implementation = 'PYTHON' if Base is BasePy else 'C'
_implementation_name = None
_implementation_set = 0

_policy_names = {
    "AccessControl": ("setDefaultBehaviors",
                      ),
    "AccessControl.PermissionRole": ("_what_not_even_god_should_do",
                                     "rolesForPermissionOn",
                                     "PermissionRole",
                                     "imPermissionRole",
                                     ),
    "AccessControl.SecurityManagement": ("SecurityManager",
                                         ),
    "AccessControl.SecurityManager": ("SecurityManager",
                                      ),
    "AccessControl.ZopeGuards": ("aq_validate",
                                 "guarded_getattr",
                                 ),
    "AccessControl.ZopeSecurityPolicy": ("ZopeSecurityPolicy",
                                         ),
}

setImplementation(_default_implementation)

# allow the implementation to change from the default
_implementation_set = 0
