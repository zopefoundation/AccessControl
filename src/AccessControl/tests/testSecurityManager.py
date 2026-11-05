##############################################################################
#
# Copyright (c) 2005 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Tests for the SecurityManager implementations
"""

import gc
import sys
import unittest
import weakref
from contextlib import contextmanager

from ..Implementation import PURE_PYTHON


_THREAD_ID = 123


class DummyContext:

    def __init__(self):
        self.user = object()
        self.stack = []


class DummyPolicy:

    CHECK_PERMISSION_ARGS = None
    CHECK_PERMISSION_RESULT = object()

    VALIDATE_ARGS = None

    def checkPermission(self, *args):
        self.CHECK_PERMISSION_ARGS = args
        return self.CHECK_PERMISSION_RESULT

    def validate(self, *args):
        self.VALIDATE_ARGS = args
        return True


class ExecutableObject:
    def __init__(self, new_policy):
        self._new_policy = new_policy

    def _customSecurityPolicy(self):
        return self._new_policy


class Holder:
    """Plain object used to build reference cycles."""


@contextmanager
def _no_automatic_gc():
    """Keep automatic collections from interfering with the assertions."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _referents(obj, depth):
    """Objects reachable from ``obj`` via ``gc.get_referents`` in ``depth``
    steps.

    Depth 2 covers Python versions where the instance ``__dict__`` is a
    separate object instead of inline values.
    """
    seen = {}
    frontier = [obj]
    for _ in range(depth):
        next_frontier = []
        for candidate in frontier:
            for referent in gc.get_referents(candidate):
                if id(referent) not in seen:
                    seen[id(referent)] = referent
                    next_frontier.append(referent)
        frontier = next_frontier
    return list(seen.values())


# Py_TPFLAGS_HAVE_GC
_HAVE_GC = 1 << 14


class ISecurityManagerConformance:

    def test_conforms_to_ISecurityManager(self):
        from zope.interface.verify import verifyClass

        from AccessControl.interfaces import ISecurityManager
        verifyClass(ISecurityManager, self._getTargetClass())


class SecurityManagerTestBase:

    def _makeOne(self, thread_id, context):
        return self._getTargetClass()(thread_id, context)

    def test_getUser(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        self.assertIs(mgr.getUser(), context.user)

    def test_calledByExecutable_no_stack(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        self.assertFalse(mgr.calledByExecutable())

    def test_calledByExecutable_with_stack(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        executableObject = object()
        mgr.addContext(executableObject)
        self.assertTrue(mgr.calledByExecutable())

    def test_addContext_no_custom_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        original_policy = mgr._policy
        executableObject = object()
        mgr.addContext(executableObject)
        self.assertIs(mgr._policy, original_policy)

    def test_addContext_with_custom_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = DummyPolicy()
        executableObject = ExecutableObject(new_policy)
        mgr.addContext(executableObject)
        self.assertIs(mgr._policy, new_policy)

    def test_addContext_with_custom_policy_then_none(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        original_policy = mgr._policy
        new_policy = DummyPolicy()
        executableObject = ExecutableObject(new_policy)
        mgr.addContext(executableObject)
        mgr.addContext(object())
        self.assertIs(mgr._policy, original_policy)

    def test_removeContext_pops_items_above_EO(self):
        context = DummyContext()
        ALPHA, BETA, GAMMA, DELTA = object(), object(), object(), object()
        context.stack.append(ALPHA)
        context.stack.append(BETA)
        context.stack.append(GAMMA)
        context.stack.append(DELTA)
        mgr = self._makeOne(_THREAD_ID, context)

        mgr.removeContext(GAMMA)

        self.assertEqual(len(context.stack), 2)
        self.assertIs(context.stack[0], ALPHA)
        self.assertIs(context.stack[1], BETA)

    def test_removeContext_last_EO_restores_default_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        original_policy = mgr._policy
        top = object()
        context.stack.append(top)
        mgr.removeContext(top)
        self.assertIs(mgr._policy, original_policy)

    def test_removeContext_with_top_having_custom_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = DummyPolicy()
        context.stack.append(ExecutableObject(new_policy))
        top = object()
        context.stack.append(top)
        mgr.removeContext(top)
        self.assertIs(mgr._policy, new_policy)

    def test_removeContext_with_top_having_no_custom_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        original_policy = mgr._policy
        new_policy = DummyPolicy()
        executableObject = ExecutableObject(new_policy)
        context.stack.append(executableObject)
        top = object()
        context.stack.append(top)
        mgr.removeContext(executableObject)
        self.assertIs(mgr._policy, original_policy)

    def test_checkPermission_delegates_to_policy(self):
        context = DummyContext()
        PERMISSION = 'PERMISSION'
        TARGET = object()
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = mgr._policy = DummyPolicy()
        result = mgr.checkPermission(PERMISSION, TARGET)
        self.assertIs(result, DummyPolicy.CHECK_PERMISSION_RESULT)
        self.assertIs(new_policy.CHECK_PERMISSION_ARGS[0], PERMISSION)
        self.assertIs(new_policy.CHECK_PERMISSION_ARGS[1], TARGET)
        self.assertIs(new_policy.CHECK_PERMISSION_ARGS[2], context)

    def test_validate_without_roles_delegates_to_policy(self):
        context = DummyContext()
        ACCESSED = object()
        CONTAINER = object()
        NAME = 'NAME'
        VALUE = object()
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = mgr._policy = DummyPolicy()

        result = mgr.validate(ACCESSED,
                              CONTAINER,
                              NAME,
                              VALUE,
                              )

        self.assertTrue(result)
        self.assertEqual(len(new_policy.VALIDATE_ARGS), 5)
        self.assertIs(new_policy.VALIDATE_ARGS[0], ACCESSED)
        self.assertIs(new_policy.VALIDATE_ARGS[1], CONTAINER)
        self.assertEqual(new_policy.VALIDATE_ARGS[2], NAME)
        self.assertIs(new_policy.VALIDATE_ARGS[3], VALUE)
        self.assertIs(new_policy.VALIDATE_ARGS[4], context)

    def test_validate_with_roles_delegates_to_policy(self):
        context = DummyContext()
        ACCESSED = object()
        CONTAINER = object()
        NAME = 'NAME'
        VALUE = object()
        ROLES = ('Hamlet', 'Othello')
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = mgr._policy = DummyPolicy()

        result = mgr.validate(ACCESSED,
                              CONTAINER,
                              NAME,
                              VALUE,
                              ROLES,
                              )

        self.assertTrue(result)
        self.assertEqual(len(new_policy.VALIDATE_ARGS), 6)
        self.assertIs(new_policy.VALIDATE_ARGS[0], ACCESSED)
        self.assertIs(new_policy.VALIDATE_ARGS[1], CONTAINER)
        self.assertEqual(new_policy.VALIDATE_ARGS[2], NAME)
        self.assertIs(new_policy.VALIDATE_ARGS[3], VALUE)
        self.assertIs(new_policy.VALIDATE_ARGS[4], context)
        self.assertEqual(new_policy.VALIDATE_ARGS[5], ROLES)

    def test_DTMLValidate_delegates_to_policy_validate(self):
        context = DummyContext()
        ACCESSED = object()
        CONTAINER = object()
        NAME = 'NAME'
        VALUE = object()
        MD = {}
        mgr = self._makeOne(_THREAD_ID, context)
        new_policy = mgr._policy = DummyPolicy()

        result = mgr.DTMLValidate(ACCESSED,
                                  CONTAINER,
                                  NAME,
                                  VALUE,
                                  MD,
                                  )

        self.assertTrue(result)
        self.assertEqual(len(new_policy.VALIDATE_ARGS), 5)
        self.assertIs(new_policy.VALIDATE_ARGS[0], ACCESSED)
        self.assertIs(new_policy.VALIDATE_ARGS[1], CONTAINER)
        self.assertEqual(new_policy.VALIDATE_ARGS[2], NAME)
        self.assertIs(new_policy.VALIDATE_ARGS[3], VALUE)
        self.assertIs(new_policy.VALIDATE_ARGS[4], context)

    # Garbage collection.  A manager references its context, its policy and
    # (C implementation) cached bound policy methods.  Reference cycles
    # through those references must be collectable, see issue #177.

    def _assertCycleCollected(self, build):
        # ``build`` returns a weak reference to an object that is kept alive
        # only by a reference cycle through a security manager.
        with _no_automatic_gc():
            ref = build()
            self.assertIsNotNone(ref(), 'cycle must keep the object alive')
            gc.collect()
            self.assertIsNone(ref(), 'cycle through the manager not collected')

    def test_gc_collects_cycle_through_context(self):
        # Scenario from issue #177:
        # holder -> manager -> context.user -> holder
        def build():
            holder = Holder()
            context = DummyContext()
            context.user = Holder()
            context.user.back = holder
            holder.manager = self._makeOne(_THREAD_ID, context)
            return weakref.ref(holder)
        self._assertCycleCollected(build)

    def test_gc_collects_cycle_through_policy(self):
        # holder -> manager -> policy -> holder
        # The policy is installed through addContext, the real code path.
        def build():
            holder = Holder()
            policy = DummyPolicy()
            policy.back = holder
            mgr = self._makeOne(_THREAD_ID, DummyContext())
            mgr.addContext(ExecutableObject(policy))
            self.assertIs(mgr._policy, policy)
            holder.manager = mgr
            return weakref.ref(holder)
        self._assertCycleCollected(build)

    def test_gc_collects_cycle_through_cached_policy_methods(self):
        # policy -> manager -> cached bound policy methods -> policy
        # The C implementation caches policy.validate and
        # policy.checkPermission after their first use.  An untraversed
        # cache entry keeps the policy, and with it the cycle, alive.
        def build():
            policy = DummyPolicy()
            mgr = self._makeOne(_THREAD_ID, DummyContext())
            mgr._policy = policy
            mgr.validate(None, None, None, None)
            mgr.checkPermission('View', None)
            policy.manager = mgr
            return weakref.ref(policy)
        self._assertCycleCollected(build)

    def test_gc_sees_context_and_policy(self):
        context = DummyContext()
        mgr = self._makeOne(_THREAD_ID, context)
        referents = _referents(mgr, 2)
        self.assertTrue(any(r is context for r in referents))
        self.assertTrue(any(r is mgr._policy for r in referents))

    def test_manager_is_gc_tracked(self):
        mgr = self._makeOne(_THREAD_ID, DummyContext())
        self.assertTrue(gc.is_tracked(mgr))

    def test_manager_released_without_cycle(self):
        # Plain reference counting still frees a manager.
        with _no_automatic_gc():
            mgr = self._makeOne(_THREAD_ID, DummyContext())
            ref = weakref.ref(mgr)
            del mgr
            self.assertIsNone(ref())

    def test_setting_policy_releases_cached_policy_methods(self):
        with _no_automatic_gc():
            mgr = self._makeOne(_THREAD_ID, DummyContext())
            policy = DummyPolicy()
            mgr._policy = policy
            mgr.validate(None, None, None, None)
            mgr.checkPermission('View', None)
            ref = weakref.ref(policy)
            mgr._policy = DummyPolicy()
            del policy
            self.assertIsNone(ref())

    @unittest.skipIf(not getattr(sys, '_is_gil_enabled', lambda: True)(),
                     reason='Reference counts are not exact without the GIL.')
    def test_type_refcount_stable_across_instance_lifecycles(self):
        # Instance creation and deallocation must INCREF and DECREF the
        # type object symmetrically.
        klass = self._getTargetClass()
        context = DummyContext()
        with _no_automatic_gc():
            klass(_THREAD_ID, context)
            before = sys.getrefcount(klass)
            for _ in range(1000):
                klass(_THREAD_ID, context)
            self.assertEqual(sys.getrefcount(klass), before)


class PythonSecurityManagerTests(SecurityManagerTestBase,
                                 ISecurityManagerConformance,
                                 unittest.TestCase):

    def _getTargetClass(self):
        from AccessControl.ImplPython import SecurityManager
        return SecurityManager


@unittest.skipIf(PURE_PYTHON, reason="Test expects C impl.")
class C_SecurityManagerTests(SecurityManagerTestBase,
                             ISecurityManagerConformance,
                             unittest.TestCase):
    # The C version mixes in the Python version, which is why we
    # can test for conformance to ISecurityManager.

    def _getTargetClass(self):
        from AccessControl.ImplC import SecurityManager
        return SecurityManager

    def test_c_type_participates_in_gc(self):
        from AccessControl.cAccessControl import SecurityManager
        self.assertTrue(SecurityManager.__flags__ & _HAVE_GC)
        self.assertTrue(gc.is_tracked(SecurityManager()))

    def test_gc_collects_cycle_through_bare_c_instance(self):
        # The C base type must work on its own, without the Python
        # subclass that ImplC.SecurityManager adds on top.
        from AccessControl.cAccessControl import SecurityManager

        def build():
            holder = Holder()
            context = DummyContext()
            context.user = holder
            mgr = SecurityManager()
            mgr._context = context
            holder.manager = mgr
            return weakref.ref(holder)
        self._assertCycleCollected(build)
