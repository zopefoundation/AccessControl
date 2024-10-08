##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
"""Test Zope Guards
"""

import doctest
import gc
import operator
import os
import sys
import unittest

from AccessControl.ZopeGuards import guarded_all
from AccessControl.ZopeGuards import guarded_any
from AccessControl.ZopeGuards import guarded_getattr


try:
    __file__
except NameError:
    __file__ = os.path.abspath(sys.argv[1])
_FILEPATH = os.path.abspath(__file__)
_HERE = os.path.dirname(_FILEPATH)


class SecurityManager:

    def __init__(self, reject=0):
        self.calls = []
        self.reject = reject

    def validate(self, *args):
        from AccessControl import Unauthorized
        self.calls.append(('validate', args))
        if self.reject:
            raise Unauthorized
        return 1

    def validateValue(self, *args):
        from AccessControl import Unauthorized
        self.calls.append(('validateValue', args))
        if self.reject:
            raise Unauthorized
        return 1

    def checkPermission(self, *args):
        self.calls.append(('checkPermission', args))
        return not self.reject


class GuardTestCase(unittest.TestCase):

    def setSecurityManager(self, manager):
        from AccessControl.SecurityManagement import _managers
        from AccessControl.SecurityManagement import get_ident
        key = get_ident()
        old = _managers.get(key)
        if manager is None:
            del _managers[key]
        else:
            _managers[key] = manager
        return old


class Method:

    def __init__(self, *args):
        self.args = args


class TestGuardedGetattr(GuardTestCase):

    def setUp(self):
        self.__sm = SecurityManager()
        self.__old = self.setSecurityManager(self.__sm)
        gc.disable()

    def tearDown(self):
        self.setSecurityManager(self.__old)
        gc.enable()

    def test_miss(self):
        from AccessControl.ZopeGuards import guarded_getattr
        obj, name = object(), 'nonesuch'
        self.assertRaises(AttributeError, guarded_getattr, obj, name)
        self.assertEqual(len(self.__sm.calls), 0)

    def test_unhashable_key(self):
        from AccessControl.ZopeGuards import guarded_getattr
        obj, name = object(), []
        self.assertRaises(TypeError, guarded_getattr, obj, name)
        self.assertEqual(len(self.__sm.calls), 0)

    def test_unauthorized(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_getattr
        obj, name = Method(), 'args'
        value = getattr(obj, name)
        rc = sys.getrefcount(value)
        self.__sm.reject = True
        self.assertRaises(Unauthorized, guarded_getattr, obj, name)
        self.assertEqual(len(self.__sm.calls), 1)
        del self.__sm.calls[:]
        self.assertEqual(rc, sys.getrefcount(value))

    def test_calls_validate_for_unknown_type(self):
        from AccessControl.ZopeGuards import guarded_getattr
        guarded_getattr(self, 'test_calls_validate_for_unknown_type')
        self.assertEqual(len(self.__sm.calls), 1)

    def test_attr_handler_table(self):
        from AccessControl import Unauthorized
        from AccessControl.SimpleObjectPolicies import ContainerAssertions
        from AccessControl.ZopeGuards import guarded_getattr
        d = {}
        _dict = type(d)
        old = ContainerAssertions.get(_dict)

        mytable = {
            'keys': 1,
            'values': Method,
        }
        ContainerAssertions[_dict] = mytable
        try:
            guarded_getattr(d, 'keys')
            self.assertEqual(len(self.__sm.calls), 0)
            values = guarded_getattr(d, 'values')
            self.assertEqual(values.__class__, Method)
            self.assertEqual(values.args, (d, 'values'))
            self.assertRaises(Unauthorized, guarded_getattr, d, 'items')
        finally:
            ContainerAssertions[_dict] = old

    def test_simple_object_policies(self):
        '''
        Test that we are able to access attributes of simple types (here:
        unicode and bytes)
        '''
        from AccessControl.ZopeGuards import guarded_getattr
        orig_value = self.__sm.reject
        self.__sm.reject = True
        try:
            items = [b'a ', 'a ']
            for item in items:
                self.assertEqual(guarded_getattr(item, 'strip')(),
                                 item.strip())
        finally:
            self.__sm.reject = orig_value
        self.assertEqual(len(self.__sm.calls), 0)


class TestGuardedHasattr(GuardTestCase):

    def setUp(self):
        self.__sm = SecurityManager()
        self.__old = self.setSecurityManager(self.__sm)
        gc.disable()

    def tearDown(self):
        self.setSecurityManager(self.__old)
        gc.enable()

    def test_miss(self):
        from AccessControl.ZopeGuards import guarded_hasattr
        obj, name = object(), 'nonesuch'
        self.assertFalse(guarded_hasattr(obj, name))
        self.assertEqual(len(self.__sm.calls), 0)
        del self.__sm.calls[:]

    def test_unhashable_key(self):
        from AccessControl.ZopeGuards import guarded_hasattr
        obj, name = object(), []
        self.assertFalse(guarded_hasattr(obj, name))
        self.assertEqual(len(self.__sm.calls), 0)

    def test_unauthorized(self):
        from AccessControl.ZopeGuards import guarded_hasattr
        obj, name = Method(), 'args'
        value = getattr(obj, name)
        rc = sys.getrefcount(value)
        self.__sm.reject = True
        self.assertFalse(guarded_hasattr(obj, name))
        self.assertEqual(len(self.__sm.calls), 1)
        del self.__sm.calls[:]
        self.assertEqual(rc, sys.getrefcount(value))

    def test_hit(self):
        from AccessControl.ZopeGuards import guarded_hasattr
        obj = Method(2411)
        name = 'args'
        value = getattr(obj, name)
        rc = sys.getrefcount(value)
        self.assertTrue(guarded_hasattr(obj, name))
        self.assertEqual(len(self.__sm.calls), 1)
        del self.__sm.calls[:]
        self.assertEqual(rc, sys.getrefcount(value))


class TestDictGuards(GuardTestCase):

    def test_get_simple(self):
        from AccessControl.ZopeGuards import get_dict_get
        get = get_dict_get({'foo': 'bar'}, 'get')
        self.assertEqual(get('foo'), 'bar')

    def test_get_default(self):
        from AccessControl.ZopeGuards import get_dict_get
        get = get_dict_get({'foo': 'bar'}, 'get')
        self.assertIsNone(get('baz'))
        self.assertEqual(get('baz', 'splat'), 'splat')

    def test_get_validates(self):
        from AccessControl.ZopeGuards import get_dict_get
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        get = get_dict_get({'foo': GuardTestCase}, 'get')
        try:
            get('foo')
        finally:
            self.setSecurityManager(old)
        self.assertTrue(sm.calls)

    def test_pop_simple(self):
        from AccessControl.ZopeGuards import get_dict_pop
        pop = get_dict_pop({'foo': 'bar'}, 'pop')
        self.assertEqual(pop('foo'), 'bar')

    def test_pop_raises(self):
        from AccessControl.ZopeGuards import get_dict_pop
        pop = get_dict_pop({'foo': 'bar'}, 'pop')
        self.assertRaises(KeyError, pop, 'baz')

    def test_pop_default(self):
        from AccessControl.ZopeGuards import get_dict_pop
        pop = get_dict_pop({'foo': 'bar'}, 'pop')
        self.assertEqual(pop('baz', 'splat'), 'splat')

    def test_pop_validates(self):
        from AccessControl.ZopeGuards import get_dict_get
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        pop = get_dict_get({'foo': GuardTestCase}, 'pop')
        try:
            pop('foo')
        finally:
            self.setSecurityManager(old)
        self.assertTrue(sm.calls)

    def test_keys_empty(self):
        from AccessControl.ZopeGuards import get_mapping_view
        keys = get_mapping_view({}, 'keys')
        self.assertEqual(list(keys()), [])

    def test_kvi_len(self):
        from AccessControl.ZopeGuards import get_mapping_view
        for attr in ("keys", "values", "items"):
            with self.subTest(attr):
                view = get_mapping_view({'a': 1}, attr)
                self.assertEqual(len(view()), 1)

    def test_keys_validates(self):
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        keys = guarded_getattr({GuardTestCase: 1}, 'keys')
        try:
            next(iter(keys()))
        finally:
            self.setSecurityManager(old)
        self.assertTrue(sm.calls)

    def test_items_validates(self):
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        items = guarded_getattr({GuardTestCase: GuardTestCase}, 'items')
        try:
            next(iter(items()))
        finally:
            self.setSecurityManager(old)
        self.assertEqual(len(sm.calls), 2)

    def test_values_empty(self):
        from AccessControl.ZopeGuards import get_mapping_view
        values = get_mapping_view({}, 'values')
        self.assertEqual(list(values()), [])

    def test_values_validates(self):
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        values = guarded_getattr({GuardTestCase: 1}, 'values')
        try:
            next(iter(values()))
        finally:
            self.setSecurityManager(old)
        self.assertTrue(sm.calls)

    def test_kvi_iteration(self):
        d = dict(a=1, b=2)
        for attr in ("keys", "values", "items"):
            v = getattr(d, attr)()
            si = guarded_getattr(d, attr)()
            self.assertEqual(next(iter(si)), next(iter(v)))


class TestListGuards(GuardTestCase):

    def test_pop_simple(self):
        from AccessControl.ZopeGuards import get_list_pop
        pop = get_list_pop(['foo', 'bar', 'baz'], 'pop')
        self.assertEqual(pop(), 'baz')
        self.assertEqual(pop(0), 'foo')

    def test_pop_raises(self):
        from AccessControl.ZopeGuards import get_list_pop
        pop = get_list_pop([], 'pop')
        self.assertRaises(IndexError, pop)

    def test_pop_validates(self):
        from AccessControl.ZopeGuards import get_list_pop
        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        pop = get_list_pop([GuardTestCase], 'pop')
        try:
            pop()
        finally:
            self.setSecurityManager(old)
        self.assertTrue(sm.calls)


class TestBuiltinFunctionGuards(GuardTestCase):

    def test_zip_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_zip
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_zip, [1, 2, 3], [3, 2, 1])
        self.assertRaises(Unauthorized, guarded_zip, [1, 2, 3], [1])
        self.setSecurityManager(old)

    def test_map_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_map
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_map, str,
                          [1, 2, 3])
        self.assertRaises(Unauthorized, guarded_map, lambda x, y: x + y,
                          [1, 2, 3], [3, 2, 1])
        self.setSecurityManager(old)

    def test_all_fails(self):
        from AccessControl import Unauthorized
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_all, [True, True, False])
        self.setSecurityManager(old)

    def test_any_fails(self):
        from AccessControl import Unauthorized
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_any, [True, True, False])
        self.setSecurityManager(old)

    def test_min_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_min
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_min, [1, 2, 3])
        self.assertRaises(Unauthorized, guarded_min, 1, 2, 3)

        class MyDict(dict):  # guard() skips 'dict' values
            pass

        self.assertRaises(Unauthorized, guarded_min,
                          MyDict(x=1), MyDict(x=2),
                          key=operator.itemgetter('x'))
        self.setSecurityManager(old)

    def test_max_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_max
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_max, [1, 2, 3])
        self.assertRaises(Unauthorized, guarded_max, 1, 2, 3)

        class MyDict(dict):  # guard() skips 'dict' values
            pass

        self.assertRaises(Unauthorized, guarded_max,
                          MyDict(x=1), MyDict(x=2),
                          key=operator.itemgetter('x'))
        self.setSecurityManager(old)

    def test_enumerate_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_enumerate
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        enum = guarded_enumerate([1, 2, 3])
        self.assertRaises(Unauthorized, enum.next)
        self.setSecurityManager(old)

    def test_sum_fails(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_sum
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        self.assertRaises(Unauthorized, guarded_sum, [1, 2, 3])
        self.setSecurityManager(old)

    def test_zip_succeeds(self):
        from AccessControl.ZopeGuards import guarded_zip
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_zip([1, 2, 3],
                                     [3, 2, 1],
                                     ),
                         [(1, 3), (2, 2), (3, 1)])
        self.assertEqual(guarded_zip([1, 2, 3], [1]), [(1, 1)])
        self.setSecurityManager(old)

    def test_map_succeeds(self):
        from AccessControl.ZopeGuards import guarded_map
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_map(str, [1, 2, 3]), ['1', '2', '3'])
        self.assertEqual(guarded_map(lambda x, y: x + y, [1, 2, 3], [3, 2, 1]),
                         [4, 4, 4])
        self.setSecurityManager(old)

    def test_all_succeeds(self):
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_all([True, True, False]), False)
        self.setSecurityManager(old)

    def test_any_succeeds(self):
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_any([True, True, False]), True)
        self.setSecurityManager(old)

    def test_min_succeeds(self):
        from AccessControl.ZopeGuards import guarded_min
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_min([1, 2, 3]), 1)
        self.assertEqual(guarded_min(1, 2, 3), 1)

        class MyDict(dict):  # guard() skips 'dict' values
            pass

        self.assertEqual(guarded_min(MyDict(x=1), MyDict(x=2),
                                     key=operator.itemgetter('x')),
                         {'x': 1})
        self.setSecurityManager(old)

    def test_max_succeeds(self):
        from AccessControl.ZopeGuards import guarded_max
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_max([1, 2, 3]), 3)
        self.assertEqual(guarded_max(1, 2, 3), 3)

        class MyDict(dict):  # guard() skips 'dict' values
            pass
        self.assertEqual(guarded_max(MyDict(x=1), MyDict(x=2),
                                     key=operator.itemgetter('x')),
                         {'x': 2})
        self.setSecurityManager(old)

    def test_enumerate_succeeds(self):
        from AccessControl.ZopeGuards import guarded_enumerate
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        enum = guarded_enumerate([1, 2, 3])
        self.assertEqual(next(enum), (0, 1))
        self.assertEqual(next(enum), (1, 2))
        self.assertEqual(next(enum), (2, 3))
        self.assertRaises(StopIteration, enum.next)
        self.setSecurityManager(old)

    def test_sum_succeeds(self):
        from AccessControl.ZopeGuards import guarded_sum
        sm = SecurityManager()  # accepts
        old = self.setSecurityManager(sm)
        self.assertEqual(guarded_sum([1, 2, 3]), 6)
        self.assertEqual(guarded_sum([1, 2, 3], start=36), 42)
        self.setSecurityManager(old)

    def test_apply(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import safe_builtins
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        gapply = safe_builtins['apply']

        def f(a=1, b=2):
            return a + b

        # This one actually succeeds, because apply isn't given anything
        # to unpack.
        self.assertEqual(gapply(f), 3)
        # Likewise, because the things passed are empty.
        self.assertEqual(gapply(f, (), {}), 3)

        self.assertRaises(Unauthorized, gapply, f, [1])
        self.assertRaises(Unauthorized, gapply, f, (), {'a': 2})
        self.assertRaises(Unauthorized, gapply, f, [1], {'a': 2})

        sm = SecurityManager()  # accepts
        self.setSecurityManager(sm)
        self.assertEqual(gapply(f), 3)
        self.assertEqual(gapply(f, (), {}), 3)
        self.assertEqual(gapply(f, [0]), 2)
        self.assertEqual(gapply(f, [], {'b': 18}), 19)
        self.assertEqual(gapply(f, [10], {'b': 1}), 11)

        self.setSecurityManager(old)


class TestGuardedDictListTypes(unittest.TestCase):

    def testDictCreation(self):
        from AccessControl.ZopeGuards import safe_builtins
        d = safe_builtins['dict']
        self.assertEqual(d(), {})
        self.assertEqual(d({1: 2}), {1: 2})
        self.assertEqual(d(((1, 2),)), {1: 2})
        self.assertEqual(d(foo=1), {"foo": 1})
        self.assertEqual(d.fromkeys((1, 2, 3)), {1: None, 2: None, 3: None})
        self.assertEqual(d.fromkeys((1, 2, 3), 'f'), {1: 'f', 2: 'f', 3: 'f'})

    def testListCreation(self):
        from AccessControl.ZopeGuards import safe_builtins
        safe_l = safe_builtins['list']
        self.assertEqual(safe_l(), [])
        self.assertEqual(safe_l([1, 2, 3]), [1, 2, 3])
        x = [3, 2, 1]
        self.assertEqual(safe_l(x), [3, 2, 1])
        self.assertEqual(sorted(safe_l(x)), [1, 2, 3])


class TestRestrictedPythonApply(GuardTestCase):

    def test_apply(self):
        from AccessControl import Unauthorized
        from AccessControl.ZopeGuards import guarded_apply
        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        gapply = guarded_apply

        def f(a=1, b=2):
            return a + b

        # This one actually succeeds, because apply isn't given anything
        # to unpack.
        self.assertEqual(gapply(*(f,)), 3)
        # Likewise, because the things passed are empty.
        self.assertEqual(gapply(*(f,), **{}), 3)

        self.assertRaises(Unauthorized, gapply, *(f, 1))
        self.assertRaises(Unauthorized, gapply, *(f,), **{'a': 2})
        self.assertRaises(Unauthorized, gapply, *(f, 1), **{'a': 2})

        sm = SecurityManager()  # accepts
        self.setSecurityManager(sm)
        self.assertEqual(gapply(*(f,)), 3)
        self.assertEqual(gapply(*(f,), **{}), 3)
        self.assertEqual(gapply(*(f, 0)), 2)
        self.assertEqual(gapply(*(f,), **{'b': 18}), 19)
        self.assertEqual(gapply(*(f, 10), **{'b': 1}), 11)

        self.setSecurityManager(old)


# Map function name to the # of times it's been called.
wrapper_count = {}


class FuncWrapper:
    def __init__(self, funcname, func):
        self.funcname = funcname
        wrapper_count[funcname] = 0
        self.func = func

    def __call__(self, *args, **kws):
        wrapper_count[self.funcname] += 1
        return self.func(*args, **kws)

    def __repr__(self):
        return "<FuncWrapper around %r>" % self.func


# Given the high wall between AccessControl and RestrictedPython, I suppose
# the next one could be called an integration test.
# But we're simply trying to run RestrictedPython with the *intended*
# implementations of the special wrappers here, so no apologies.
_ProtectedBase = None


class TestActualPython(GuardTestCase):

    _old_mgr = _old_policy = _marker = []

    def setUp(self):
        self._wrapped_dicts = []

    def tearDown(self):
        self._restorePolicyAndManager()
        for munged, orig in self._wrapped_dicts:
            munged.update(orig)
        del self._wrapped_dicts

    def _initPolicyAndManager(self, manager=None):
        from AccessControl.SecurityManagement import _managers
        from AccessControl.SecurityManagement import get_ident
        from AccessControl.SecurityManagement import newSecurityManager
        from AccessControl.SecurityManager import setSecurityPolicy
        from AccessControl.ZopeSecurityPolicy import ZopeSecurityPolicy

        class UnderprivilegedUser:
            """ Anonymous USer for unit testing purposes.
            """

            def getId(self):
                return 'Underprivileged User'

            getUserName = getId

            def allowed(self, object, object_roles=None):
                return 0

            def getRoles(self):
                return ()

        self._policy = ZopeSecurityPolicy()
        self._old_policy = setSecurityPolicy(self._policy)

        if manager is None:
            thread_id = get_ident()
            self._old_mgr = manager = _managers.get(thread_id, self._marker)
            newSecurityManager(None, UnderprivilegedUser())
        else:
            self._old_mgr = self.setSecurityManager(manager)

    def _restorePolicyAndManager(self):
        from AccessControl.SecurityManagement import noSecurityManager
        from AccessControl.SecurityManager import setSecurityPolicy

        if self._old_mgr is not self._marker:
            self.setSecurityManager(self._old_mgr)
        else:
            noSecurityManager()

        if self._old_policy is not self._marker:
            setSecurityPolicy(self._old_policy)

    def _getProtectedBaseClass(self):
        from ExtensionClass import Base

        from AccessControl.class_init import InitializeClass
        from AccessControl.SecurityInfo import ClassSecurityInfo

        global _ProtectedBase
        if _ProtectedBase is None:

            class ProtectedBase(Base):
                security = ClassSecurityInfo()

                @security.private
                def private_method(self):
                    return 'private_method called'

            InitializeClass(ProtectedBase)
            _ProtectedBase = ProtectedBase

        return _ProtectedBase

    def testPython(self):
        code, its_globals = self._compile("actual_python.py")

        # Fiddle the global and safe-builtins dicts to count how many times
        # the special functions are called.
        self._wrap_replaced_dict_callables(its_globals)
        self._wrap_replaced_dict_callables(its_globals['__builtins__'])

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        try:
            exec(code, its_globals)
        finally:
            self.setSecurityManager(old)

        # Use wrapper_count to determine coverage.
        # print wrapper_count  # uncomment to see wrapper names & counts
        untouched = [k for k, v in wrapper_count.items() if v == 0]
        if untouched:
            untouched.sort()
            self.fail("Unexercised wrappers: %r" % untouched)

    def testPythonRealAC(self):
        code, its_globals = self._compile("actual_python.py")
        exec(code, its_globals)

    def test_derived_class_normal(self):
        from AccessControl import Unauthorized

        NORMAL_SCRIPT = """
class Normal(ProtectedBase):
    pass

normal = Normal()
result = normal.private_method()
"""
        code, its_globals = self._compile_str(NORMAL_SCRIPT, 'normal_script')
        its_globals['ProtectedBase'] = self._getProtectedBaseClass()

        self._initPolicyAndManager()

        with self.assertRaises(Unauthorized):
            exec(code, its_globals)
            self.fail("Didn't raise Unauthorized: \n%s" %
                      its_globals['result']())

    def test_derived_class_sneaky_en_suite(self):
        #  Disallow declaration of security-affecting names in classes
        #  defined in restricted code (compile-time check).

        SNEAKY_SCRIPT = """
class Sneaky(ProtectedBase):
    private_method__roles__ = None


sneaky = Sneaky()
result = sneaky.private_method()
"""
        with self.assertRaises(SyntaxError):
            self._compile_str(SNEAKY_SCRIPT, 'sneaky_script')
            self.fail("Didn't raise SyntaxError!")

    def test_derived_sneaky_post_facto(self):
        #  Assignment to a class outside its suite fails at
        #  compile time with a SyntaxError.

        SNEAKY_SCRIPT = """
class Sneaky(ProtectedBase):
    pass

Sneaky.private_method__roles__ = None

sneaky = Sneaky()
result = sneaky.private_method()
"""
        with self.assertRaises(SyntaxError):
            self._compile_str(SNEAKY_SCRIPT, 'sneaky_script')
            self.fail("Didn't raise SyntaxError!")

    def test_derived_sneaky_instance(self):
        #  Assignment of security-sensitive names to an instance
        #  fails at compile time with a SyntaxError.

        SNEAKY_SCRIPT = """
class Sneaky(ProtectedBase):
    pass

sneaky = Sneaky()
sneaky.private_method__roles__ = None
result = sneaky.private_method()
"""
        with self.assertRaises(SyntaxError):
            self._compile_str(SNEAKY_SCRIPT, 'sneaky_script')
            self.fail("Didn't raise SyntaxError!")

    def test_dict_access(self):
        SIMPLE_DICT_ACCESS_SCRIPT = """
def foo(text):
    return text

kw = {'text':'baz'}
print(foo(**kw))

kw = {'text':True}
print(foo(**kw))
printed  # Prevent a warning of RestrictedPython that itis not used.
"""
        code, its_globals = self._compile_str(SIMPLE_DICT_ACCESS_SCRIPT, 'x')

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        try:
            exec(code, its_globals)
        finally:
            self.setSecurityManager(old)

        self.assertEqual(its_globals['_print'](),
                         'baz\nTrue\n')

    def test_guarded_next__1(self):
        """There is a `safe_builtin` named `next`."""
        SCRIPT = "result = next(iterator)"

        code, its_globals = self._compile_str(SCRIPT, 'ignored')
        its_globals['iterator'] = iter([2411, 123])

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        try:
            exec(code, its_globals)
        finally:
            self.setSecurityManager(old)

        self.assertEqual(its_globals['result'], 2411)

    def test_guarded_next_default(self):
        """There is a `safe_builtin` named `next` with `default`."""
        SCRIPT = "result = next(iterator, 'default')"

        code, its_globals = self._compile_str(SCRIPT, 'ignored')
        its_globals['iterator'] = iter([])

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        try:
            exec(code, its_globals)
        finally:
            self.setSecurityManager(old)
        self.assertEqual(its_globals['result'], "default")

    def test_guarded_next_StopIteration(self):
        """There is a `safe_builtin` named `next`, raising StopIteration
        when iterator is exhausted."""
        SCRIPT = "result = next(iterator)"

        code, its_globals = self._compile_str(SCRIPT, 'ignored')
        its_globals['iterator'] = iter([])

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        with self.assertRaises(StopIteration):
            try:
                exec(code, its_globals)
            finally:
                self.setSecurityManager(old)

    def test_guarded_next__2(self):
        """It guards the access during iteration."""
        from AccessControl import Unauthorized

        SCRIPT = "next(iterator)"

        code, its_globals = self._compile_str(SCRIPT, 'ignored')
        its_globals['iterator'] = iter([2411, 123])

        sm = SecurityManager(reject=True)
        old = self.setSecurityManager(sm)
        with self.assertRaises(Unauthorized):
            try:
                exec(code, its_globals)
            finally:
                self.setSecurityManager(old)
        self.assertEqual([('validate', (2411, 2411, None, 2411))], sm.calls)

    def test_guarded_next__3(self):
        """It does not double check if using a `SafeIter`."""
        from AccessControl.ZopeGuards import SafeIter

        SCRIPT = "next(iter([2411, 123]))"

        code, its_globals = self._compile_str(SCRIPT, 'ignored')
        its_globals['iterator'] = SafeIter([2411, 123])

        sm = SecurityManager()
        old = self.setSecurityManager(sm)
        try:
            exec(code, its_globals)
        finally:
            self.setSecurityManager(old)
        self.assertEqual(
            [('validate', ([2411, 123], [2411, 123], None, 2411))], sm.calls)

    def _compile_str(self, text, name):
        from RestrictedPython import compile_restricted

        from AccessControl.ZopeGuards import get_safe_globals
        from AccessControl.ZopeGuards import guarded_getattr

        code = compile_restricted(text, name, 'exec')

        g = get_safe_globals()
        g['_getattr_'] = guarded_getattr
        g['__debug__'] = 1  # so assert statements are active
        g['__name__'] = __name__  # so classes can be defined in the script
        return code, g

    # Compile code in fname, as restricted Python. Return the
    # compiled code, and a safe globals dict for running it in.
    # fname is the string name of a Python file; it must be found
    # in the same directory as this file.
    def _compile(self, fname):
        fn = os.path.join(_HERE, fname)
        with open(fn) as f:
            text = f.read()
        return self._compile_str(text, fn)

    # d is a dict, the globals for execution or our safe builtins.
    # The callable values which aren't the same as the corresponding
    # entries in builtins are wrapped in a FuncWrapper, so we can
    # tell whether they're executed.
    def _wrap_replaced_dict_callables(self, d):
        from RestrictedPython.Guards import builtins
        orig = d.copy()
        self._wrapped_dicts.append((d, orig))
        for k, v in d.items():
            if callable(v) and v is not getattr(builtins, k, None):
                d[k] = FuncWrapper(k, v)


def test_inplacevar():
    """
Verify the correct behavior of protected_inplacevar.

    >>> from AccessControl.ZopeGuards import protected_inplacevar

Basic operations on objects without inplace slots work as expected:

    >>> protected_inplacevar('+=', 1, 2)
    3
    >>> protected_inplacevar('-=', 5, 2)
    3
    >>> protected_inplacevar('*=', 5, 2)
    10
    >>> protected_inplacevar('/=', 6, 2.0)
    3.0
    >>> protected_inplacevar('//=', 6, 2)
    3
    >>> protected_inplacevar('%=', 5, 2)
    1
    >>> protected_inplacevar('**=', 5, 2)
    25
    >>> protected_inplacevar('<<=', 5, 2)
    20
    >>> protected_inplacevar('>>=', 5, 2)
    1
    >>> protected_inplacevar('&=', 5, 2)
    0
    >>> protected_inplacevar('^=', 7, 2)
    5
    >>> protected_inplacevar('|=', 5, 2)
    7

Inplace operations are allowed on lists:

    >>> protected_inplacevar('+=', [1], [2])
    [1, 2]

    >>> protected_inplacevar('*=', [1], 2)
    [1, 1]

But not on custom objects:

    >>> class C:
    ...     def __iadd__(self, other):
    ...         return 42
    >>> protected_inplacevar('+=', C(), 2)    # doctest: +NORMALIZE_WHITESPACE
    Traceback (most recent call last):
    ...
    TypeError: Augmented assignment to C objects is not allowed in
    untrusted code
"""


def test_inplacevar_for_py24():
    """
protected_inplacevar allows in-place ops on sets:

    >>> from AccessControl.ZopeGuards import protected_inplacevar
    >>> s = set((1,2,3,4))
    >>> sorted(protected_inplacevar('-=', s, set((1, 3))))
    [2, 4]
    >>> sorted(s)
    [2, 4]

    >>> sorted(protected_inplacevar('|=', s, set((1, 3, 9))))
    [1, 2, 3, 4, 9]
    >>> sorted(s)
    [1, 2, 3, 4, 9]

    >>> sorted(protected_inplacevar('&=', s, set((1, 2, 3, 9))))
    [1, 2, 3, 9]
    >>> sorted(s)
    [1, 2, 3, 9]

    >>> sorted(protected_inplacevar('^=', s, set((1, 3, 7, 8))))
    [2, 7, 8, 9]
    >>> sorted(s)
    [2, 7, 8, 9]
"""


def test_suite():
    suite = unittest.TestSuite([
        doctest.DocTestSuite(),
    ])
    for cls in (TestGuardedGetattr,
                TestGuardedHasattr,
                TestDictGuards,
                TestBuiltinFunctionGuards,
                TestListGuards,
                TestGuardedDictListTypes,
                TestRestrictedPythonApply,
                TestActualPython,
                ):
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    return suite
