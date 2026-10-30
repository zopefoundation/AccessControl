##############################################################################
#
# Copyright (c) 2026 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Refuse changes to security declarations once they are frozen.

See AccessControl.SecurityInfo.freeze_security_declarations.
"""

from zExceptions import Forbidden


_frozen = False


def freeze():
    global _frozen
    _frozen = True


def is_frozen():
    return _frozen


def check_not_frozen():
    if _frozen:
        raise Forbidden('Security declarations are frozen.')


def _guarded_dict_method(name):
    method = getattr(dict, name)

    def guarded(self, *args, **kwargs):
        check_not_frozen()
        return method(self, *args, **kwargs)
    return guarded


class FreezableDict(dict):
    """dict that refuses changes once security declarations are frozen."""

    __setitem__ = _guarded_dict_method('__setitem__')
    __delitem__ = _guarded_dict_method('__delitem__')
    __ior__ = _guarded_dict_method('__ior__')
    clear = _guarded_dict_method('clear')
    pop = _guarded_dict_method('pop')
    popitem = _guarded_dict_method('popitem')
    setdefault = _guarded_dict_method('setdefault')
    update = _guarded_dict_method('update')
