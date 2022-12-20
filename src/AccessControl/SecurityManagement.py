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
"""Security management
"""

from _thread import get_ident

from AccessControl import SpecialUsers


def getSecurityManager():
    """Get a security manager, for the current thread.
    """
    thread_id = get_ident()
    manager = _managers.get(thread_id, None)
    if manager is None:
        nobody = getattr(SpecialUsers, 'nobody', None)
        if nobody is None:
            # Initialize SpecialUsers by importing User.py.
            from AccessControl import User  # NOQA: F401
            nobody = SpecialUsers.nobody
        manager = SecurityManager(thread_id, SecurityContext(nobody))  # NOQA
        _managers[thread_id] = manager

    return manager


def setSecurityManager(manager):
    """install *manager* as current security manager for this thread."""
    thread_id = get_ident()
    _managers[thread_id] = manager


# AccessControl.Implementation inserts SecurityManager.


_managers = {}


def newSecurityManager(request, user):
    """Set up a new security context for a request for a user
    """
    thread_id = get_ident()
    _managers[thread_id] = SecurityManager(  # NOQA: F821
        thread_id,
        SecurityContext(user),
    )


def noSecurityManager():
    try:
        del _managers[get_ident()]
    except BaseException:
        pass


def setSecurityPolicy(aSecurityPolicy):
    """Set the system default security policy.

    This method should only be caused by system startup code. It should
    never, for example, be called during a web request.
    """
    SecurityManager.setSecurityPolicy(aSecurityPolicy)  # NOQA: F821


class SecurityContext:
    """The security context is an object used internally to the security
    machinery. It captures data about the current security context.
    """

    def __init__(self, user):
        self.stack = []
        self.user = user
        self.objectCache = {}
