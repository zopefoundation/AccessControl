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
""" TaintedString implementation.

TaintedStrings hold potentially dangerous untrusted data; anything that could
possibly hold HTML is considered dangerous. DTML code will use the quoted
value of this string, and raised exceptions in Zope will use the repr()
conversion.
"""

from functools import total_ordering
from html import escape


def should_be_tainted(value):
    if isinstance(value, int):
        # ord('<') is 60
        return 60 == value
    elif isinstance(value, bytes):
        return 60 in value
    else:
        return '<' in value


def taint_string(value):
    if isinstance(value, bytes):
        return TaintedBytes(value)
    else:
        return TaintedString(value)


@total_ordering
class TaintedString:

    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value

    def __repr__(self):
        return repr(self.quoted())

    def __eq__(self, o):
        return self._value == o

    def __lt__(self, o):
        return self._value < o

    def __hash__(self):
        return hash(self._value)

    def __len__(self):
        return len(self._value)

    def __getitem__(self, index):
        v = self._value[index]
        if should_be_tainted(v):
            v = self.__class__(v)
        return v

    def __getslice__(self, i, j):
        i = max(i, 0)
        j = max(j, 0)
        v = self._value[i:j]
        if should_be_tainted(v):
            v = self.__class__(v)
        return v

    def __add__(self, o):
        return self.__class__(self._value + o)

    def __radd__(self, o):
        return self.__class__(o + self._value)

    def __mul__(self, o):
        return self.__class__(self._value * o)

    def __rmul__(self, o):
        return self.__class__(o * self._value)

    def __mod__(self, o):
        return self.__class__(self._value % o)

    def __int__(self):
        return int(self._value)

    def __float__(self):
        return float(self._value)

    def __getstate__(self):
        # If an object tries to store a TaintedString, it obviously wasn't
        # aware that it was playing with untrusted data. Complain acordingly.
        raise SystemError(
            "A TaintedString cannot be pickled. Code that "
            "caused this TaintedString to be stored should be more careful "
            "with untrusted data from the REQUEST.")

    def __getattr__(self, a):
        # for string methods support other than those defined below
        return getattr(self._value, a)

    def encode(self, *args):
        return self.__class__(self._value.encode(*args))

    def expandtabs(self, *args):
        return self.__class__(self._value.expandtabs(*args))

    def replace(self, *args):
        v = self._value.replace(*args)
        if should_be_tainted(v):
            v = self.__class__(v)
        return v

    def split(self, *args):
        r = self._value.split(*args)
        return list(map(lambda v, c=self.__class__:
                        should_be_tainted(v) and c(v) or v, r))

    def splitlines(self, *args):
        r = self._value.splitlines(*args)
        return list(map(lambda v, c=self.__class__:
                        should_be_tainted(v) and c(v) or v, r))

    def translate(self, *args):
        v = self._value.translate(*args)
        if should_be_tainted(v):
            v = self.__class__(v)
        return v

    def quoted(self):
        return escape(self._value, 1)

    # As called by cDocumentTemplate
    __untaint__ = quoted


def createSimpleWrapper(func):
    return lambda s, f=func: s.__class__(getattr(s._value, f)())


def createOneArgWrapper(func):
    return lambda s, a, f=func: s.__class__(getattr(s._value, f)(a))


def createOneOptArgWrapper(func):
    return lambda s, a=None, f=func: s.__class__(getattr(s._value, f)(a))


simpleWrappedMethods = ["capitalize", "lower", "swapcase", "title", "upper"]
oneArgWrappedMethods = ["center", "join", "ljust", "rjust"]
oneOptArgWrappedMethods = ["lstrip", "rstrip", "strip"]

for f in simpleWrappedMethods:
    setattr(TaintedString, f, createSimpleWrapper(f))

for f in oneArgWrappedMethods:
    setattr(TaintedString, f, createOneArgWrapper(f))

for f in oneOptArgWrappedMethods:
    setattr(TaintedString, f, createOneOptArgWrapper(f))


class TaintedBytes(TaintedString):

    def __init__(self, value):
        if isinstance(value, bytes):
            self._value = value
        elif isinstance(value, int):
            value = bytes([value])
            self._value = value
        else:
            raise ValueError(
                "Can be constructed only from bytes "
                "(or a single int).")

    def quoted(self):
        result = escape(self._value.decode('utf8'), 1)
        return result.encode('utf8')

    def __str__(self):
        return self._value.decode('utf8')

    def decode(self, *args):
        return TaintedString(self._value.decode(*args))
