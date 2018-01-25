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
""" TaintedString tests.
"""

import unittest

import six


class TestTaintedString(unittest.TestCase):

    def setUp(self):
        self.unquoted = '<test attr="&">'
        self.quoted = '&lt;test attr=&quot;&amp;&quot;&gt;'
        self.tainted = self._getClass()(self.unquoted)

    def _getClass(self):
        from AccessControl.tainted import TaintedString
        return TaintedString

    def testStr(self):
        self.assertEqual(str(self.tainted), self.unquoted)

    def testRepr(self):
        self.assertEqual(repr(self.tainted), repr(self.quoted))

    def testCmp(self):
        self.assertTrue(self.tainted == self.unquoted)
        self.assertTrue(self.tainted < 'a')
        self.assertTrue(self.tainted > '.')

    def testHash(self):
        hash = {}
        hash[self.tainted] = self.quoted
        hash[self.unquoted] = self.unquoted
        self.assertEqual(hash[self.tainted], self.unquoted)

    def testLen(self):
        self.assertEqual(len(self.tainted), len(self.unquoted))

    def testGetItem(self):
        self.assertTrue(isinstance(self.tainted[0], self._getClass()))
        self.assertEqual(self.tainted[0], '<')
        self.assertFalse(isinstance(self.tainted[-1], self._getClass()))
        self.assertEqual(self.tainted[-1], '>')

    def testGetSlice(self):
        self.assertTrue(isinstance(self.tainted[0:1], self._getClass()))
        self.assertEqual(self.tainted[0:1], '<')
        self.assertFalse(isinstance(self.tainted[1:], self._getClass()))
        self.assertEqual(self.tainted[1:], self.unquoted[1:])

    def testConcat(self):
        self.assertTrue(isinstance(self.tainted + 'test', self._getClass()))
        self.assertEqual(self.tainted + 'test', self.unquoted + 'test')
        self.assertTrue(isinstance('test' + self.tainted, self._getClass()))
        self.assertEqual('test' + self.tainted, 'test' + self.unquoted)

    def testMultiply(self):
        self.assertTrue(isinstance(2 * self.tainted, self._getClass()))
        self.assertEqual(2 * self.tainted, 2 * self.unquoted)
        self.assertTrue(isinstance(self.tainted * 2, self._getClass()))
        self.assertEqual(self.tainted * 2, self.unquoted * 2)

    def testInterpolate(self):
        tainted = self._getClass()('<%s>')
        self.assertTrue(isinstance(tainted % 'foo', self._getClass()))
        self.assertEqual(tainted % 'foo', '<foo>')
        tainted = self._getClass()('<%s attr="%s">')
        self.assertTrue(isinstance(tainted % ('foo', 'bar'), self._getClass()))
        self.assertEqual(tainted % ('foo', 'bar'), '<foo attr="bar">')

    def testStringMethods(self):
        simple = "capitalize isalpha isdigit islower isspace istitle isupper" \
            " lower lstrip rstrip strip swapcase upper".split()
        returnsTainted = "capitalize lower lstrip rstrip strip swapcase upper"
        returnsTainted = returnsTainted.split()
        unquoted = '\tThis is a test  '
        tainted = self._getClass()(unquoted)
        for f in simple:
            v = getattr(tainted, f)()
            self.assertEqual(v, getattr(unquoted, f)())
            if f in returnsTainted:
                self.assertTrue(isinstance(v, self._getClass()))
            else:
                self.assertFalse(isinstance(v, self._getClass()))

        optArg = "lstrip rstrip strip".split()
        for f in optArg:
            v = getattr(tainted, f)(" ")
            self.assertEqual(v, getattr(unquoted, f)(" "))
            self.assertTrue(isinstance(v, self._getClass()))

        justify = "center ljust rjust".split()
        for f in justify:
            v = getattr(tainted, f)(30)
            self.assertEqual(v, getattr(unquoted, f)(30))
            self.assertTrue(isinstance(v, self._getClass()))

        searches = "find index rfind rindex endswith startswith".split()
        searchraises = "index rindex".split()
        for f in searches:
            v = getattr(tainted, f)('test')
            self.assertEqual(v, getattr(unquoted, f)('test'))
            if f in searchraises:
                self.assertRaises(ValueError, getattr(tainted, f), 'nada')

        self.assertEqual(tainted.count('test', 1, -1),
                          unquoted.count('test', 1, -1))

        self.assertEqual(tainted.encode(), unquoted.encode())
        self.assertTrue(isinstance(tainted.encode(), self._getClass()))

        self.assertEqual(tainted.expandtabs(10), unquoted.expandtabs(10))
        self.assertTrue(isinstance(tainted.expandtabs(), self._getClass()))

        self.assertEqual(tainted.replace('test', 'spam'),
                          unquoted.replace('test', 'spam'))
        self.assertTrue(isinstance(tainted.replace('test', '<'),
                                self._getClass()))
        self.assertFalse(isinstance(tainted.replace('test', 'spam'),
                               self._getClass()))

        self.assertEqual(tainted.split(), unquoted.split())
        for part in self._getClass()('< < <').split():
            self.assertTrue(isinstance(part, self._getClass()))
        for part in tainted.split():
            self.assertFalse(isinstance(part, self._getClass()))

        multiline = 'test\n<tainted>'
        lines = self._getClass()(multiline).split()
        self.assertEqual(lines, multiline.split())
        self.assertTrue(isinstance(lines[1], self._getClass()))
        self.assertFalse(isinstance(lines[0], self._getClass()))

        transtable = ''.join(map(chr, range(256)))
        self.assertEqual(tainted.translate(transtable),
                          unquoted.translate(transtable))
        self.assertTrue(isinstance(self._getClass()('<').translate(transtable),
                                self._getClass()))
        if six.PY2:
            # Translate no longer supports a second argument
            self.assertFalse(isinstance(self._getClass()('<').translate(transtable,
                                                                   '<'),
                                   self._getClass()))

    def testQuoted(self):
        self.assertEqual(self.tainted.quoted(), self.quoted)
