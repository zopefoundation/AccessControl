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
'''Collect rules for access to objects that don\'t have roles.

The rules are expressed as a mapping from type -> assertion

An assertion can be:

  - A dict

  - A callable

  - Something with a truth value

If the assertion is a callable, then it will be called with
a name being accessed and the name used.  Its return value is ignored,
but in may veto an access by raising an exception.

If the assertion is a dictionary, then the keys are attribute names.
The values may be callables or objects with boolean values. If a value
is callable, it will be called with the object we are accessing an
attribute of and the attribute name. It should return an attribute
value. Callables are often used to returned guarded versions of
methods.  Otherwise, accesses are allowed if values in this dictionary
are true and disallowed if the values are false or if an item for an
attribute name is not present.

If the assertion is not a dict and is not callable, then access to
unprotected attributes is allowed if the assertion is true, and
disallowed otherwise.

XXX This descrition doesn't actually match what's done in ZopeGuards
or in ZopeSecurityPolicy. :(
'''

from contextlib import contextmanager

from BTrees.IIBTree import IIBTree
from BTrees.IIBTree import IIBucket
from BTrees.IIBTree import IISet
from BTrees.IOBTree import IOBTree
from BTrees.IOBTree import IOBucket
from BTrees.IOBTree import IOSet
from BTrees.OIBTree import OIBTree
from BTrees.OIBTree import OIBucket
from BTrees.OIBTree import OISet
#
#   WAAAA!
#
from BTrees.OOBTree import OOBTree
from BTrees.OOBTree import OOBucket
from BTrees.OOBTree import OOSet


_noroles = []  # this is imported in various places
_marker = object()

# ContainerAssertions are used by cAccessControl to check access to
# attributes of container types, like dict, list, or string.
# ContainerAssertions maps types to a either a dict, a function, or a
# simple boolean value.  When guarded_getattr checks the type of its
# first argument against ContainerAssertions, and invokes checking
# logic depending on what value it finds.

# If the value for a type is:
#   - a boolean value:
#      - the value determines whether access is allowed
#   - a function (or callable):
#      - The function is called with the name of the attribute and
#        the actual attribute value, then the value is returned.
#        The function can raise an exception.
#   - a dict:
#      - The dict maps attribute names to boolean values or functions.
#        The boolean values behave as above, but the functions do not.
#        The value returned for attribute access is the result of
#        calling the function with the object and the attribute name.
ContainerAssertions = {
    type(()): 1,
    type(b''): 1,
    type(u''): 1,
    range: 1,
}

Containers = ContainerAssertions.get


def allow_type(Type, allowed=1):
    """Allow a type and all of its methods and attributes to be used from
    restricted code.  The argument Type must be a type."""
    if type(Type) is not type:
        raise ValueError("%r is not a type" % Type)
    if hasattr(Type, '__roles__'):
        raise ValueError("%r handles its own security" % Type)
    if not (isinstance(allowed, int) or isinstance(allowed, dict)):
        raise ValueError("The 'allowed' argument must be an int or dict.")
    ContainerAssertions[Type] = allowed


for tree_type, has_values in [
    (OOBTree, 1),
    (OOBucket, 1),
    (OOSet, 0),
    (OIBTree, 1),
    (OIBucket, 1),
    (OISet, 0),
    (IOBTree, 1),
    (IOBucket, 1),
    (IOSet, 0),
    (IIBTree, 1),
    (IIBucket, 1),
    (IISet, 0),
]:
    tree = tree_type()
    keys = tree.keys()

    if not isinstance(keys, list):  # lists have their own declarations
        allow_type(type(keys))

    if has_values:
        assert isinstance(keys, type(tree.values()))
        assert isinstance(keys, type(tree.items()))


@contextmanager
def override_containers(type_, assertions):
    """Temporarily override the container assertions."""
    orig_container = Containers(type_, _marker)
    ContainerAssertions[type_] = assertions
    try:
        yield
    finally:
        if orig_container is _marker:
            del ContainerAssertions[type_]
        else:
            ContainerAssertions[type_] = orig_container
