##############################################################################
#
# Copyright (c) 2026 Zope Foundation and Contributors.
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
"""Tests for refusing changes once security declarations are frozen.
"""

import unittest

from zExceptions import Forbidden

from AccessControl import frozen


class FrozenTestCase(unittest.TestCase):

    def setUp(self):
        self._orig_frozen = frozen._frozen
        frozen._frozen = False

    def tearDown(self):
        frozen._frozen = self._orig_frozen

    def test_not_frozen_by_default(self):
        self.assertFalse(frozen.is_frozen())
        # Does not raise.
        frozen.check_not_frozen()

    def test_freeze(self):
        frozen.freeze()
        self.assertTrue(frozen.is_frozen())
        with self.assertRaises(Forbidden) as cm:
            frozen.check_not_frozen()
        self.assertEqual(str(cm.exception),
                         'Security declarations are frozen.')

    def test_freeze_twice(self):
        frozen.freeze()
        frozen.freeze()
        self.assertTrue(frozen.is_frozen())


class FreezableDictTestCase(unittest.TestCase):

    def setUp(self):
        self._orig_frozen = frozen._frozen
        frozen._frozen = False

    def tearDown(self):
        frozen._frozen = self._orig_frozen

    def _makeOne(self):
        return frozen.FreezableDict({'a': 1, 'b': 2})

    def test_is_dict(self):
        self.assertIsInstance(self._makeOne(), dict)

    def test_changes_before_freeze(self):
        d = self._makeOne()
        d['c'] = 3
        del d['a']
        d.update({'d': 4})
        d.update(e=5)
        d |= {'f': 6}
        self.assertEqual(d.setdefault('g', 7), 7)
        self.assertEqual(d.pop('b'), 2)
        self.assertEqual(d, {'c': 3, 'd': 4, 'e': 5, 'f': 6, 'g': 7})
        self.assertEqual(d.popitem(), ('g', 7))
        d.clear()
        self.assertEqual(d, {})

    def test_changes_after_freeze(self):
        d = self._makeOne()
        frozen.freeze()
        with self.assertRaises(Forbidden):
            d['c'] = 3
        with self.assertRaises(Forbidden):
            d['a'] = 3
        with self.assertRaises(Forbidden):
            del d['a']
        with self.assertRaises(Forbidden):
            d |= {'c': 3}
        self.assertRaises(Forbidden, d.update, {'c': 3})
        self.assertRaises(Forbidden, d.update, c=3)
        self.assertRaises(Forbidden, d.setdefault, 'c', 3)
        # Even when the key exists, so nothing would change.
        self.assertRaises(Forbidden, d.setdefault, 'a', 1)
        self.assertRaises(Forbidden, d.pop, 'a')
        self.assertRaises(Forbidden, d.pop, 'nonesuch', None)
        self.assertRaises(Forbidden, d.popitem)
        self.assertRaises(Forbidden, d.clear)
        self.assertEqual(d, {'a': 1, 'b': 2})

    def test_reading_after_freeze(self):
        d = self._makeOne()
        frozen.freeze()
        self.assertEqual(d['a'], 1)
        self.assertEqual(d.get('b'), 2)
        self.assertIsNone(d.get('nonesuch'))
        self.assertIn('a', d)
        self.assertEqual(len(d), 2)
        self.assertEqual(sorted(d), ['a', 'b'])
        self.assertEqual(sorted(d.items()), [('a', 1), ('b', 2)])

    def test_copies_after_freeze(self):
        # Copies are plain dicts, so they can be changed.
        d = self._makeOne()
        frozen.freeze()
        copy = d.copy()
        self.assertIs(type(copy), dict)
        copy['c'] = 3
        merged = d | {'c': 3}
        self.assertIs(type(merged), dict)
        self.assertEqual(merged, {'a': 1, 'b': 2, 'c': 3})
        self.assertEqual(d, {'a': 1, 'b': 2})
