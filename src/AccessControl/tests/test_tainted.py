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


class TestFunctions(unittest.TestCase):

    def test_taint_string(self):
        from AccessControl.tainted import TaintedBytes
        from AccessControl.tainted import TaintedString
        from AccessControl.tainted import taint_string
        self.assertIsInstance(taint_string('string'), TaintedString)
        self.assertIsInstance(taint_string(b'bytes'), TaintedBytes)

    def test_should_be_tainted(self):
        from AccessControl.tainted import should_be_tainted
        self.assertFalse(should_be_tainted('string'))
        self.assertTrue(should_be_tainted('<string'))
        self.assertFalse(should_be_tainted(b'string'))
        self.assertTrue(should_be_tainted(b'<string'))
        self.assertFalse(should_be_tainted(b'string'[0]))
        self.assertTrue(should_be_tainted(b'<string'[0]))


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

    def testEqual(self):
        self.assertEqual(self.tainted, self.unquoted)

    def testCmp(self):
        self.assertEqual(self.tainted, self.unquoted)
        self.assertLess(self.tainted, 'a')
        self.assertGreater(self.tainted, '.')

    def testHash(self):
        hash = {}
        hash[self.tainted] = self.quoted
        hash[self.unquoted] = self.unquoted
        self.assertEqual(hash[self.tainted], self.unquoted)

    def testLen(self):
        self.assertEqual(len(self.tainted), len(self.unquoted))

    def testGetItem(self):
        self.assertIsInstance(self.tainted[0], self._getClass())
        self.assertEqual(self.tainted[0], '<')
        self.assertNotIsInstance(self.tainted[-1], self._getClass())
        self.assertEqual(self.tainted[-1], '>')

    def testGetSlice(self):
        self.assertIsInstance(self.tainted[0:1], self._getClass())
        self.assertEqual(self.tainted[0:1], '<')
        self.assertNotIsInstance(self.tainted[1:], self._getClass())
        self.assertEqual(self.tainted[1:], self.unquoted[1:])

    CONCAT = 'test'

    def testConcat(self):
        self.assertIsInstance(
            self.tainted + self.CONCAT,
            self._getClass()
        )
        self.assertEqual(self.tainted + self.CONCAT,
                         self.unquoted + self.CONCAT)
        self.assertIsInstance(
            self.CONCAT + self.tainted,
            self._getClass()
        )
        self.assertEqual(self.CONCAT + self.tainted,
                         self.CONCAT + self.unquoted)

    def testMultiply(self):
        self.assertIsInstance(2 * self.tainted, self._getClass())
        self.assertEqual(2 * self.tainted, 2 * self.unquoted)
        self.assertIsInstance(self.tainted * 2, self._getClass())
        self.assertEqual(self.tainted * 2, self.unquoted * 2)

    def testInterpolate(self):
        tainted = self._getClass()('<%s>')
        self.assertIsInstance(tainted % 'foo', self._getClass())
        self.assertEqual(tainted % 'foo', '<foo>')
        tainted = self._getClass()('<%s attr="%s">')
        self.assertIsInstance(tainted % ('foo', 'bar'), self._getClass())
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
                self.assertIsInstance(v, self._getClass())
            else:
                self.assertNotIsInstance(v, self._getClass())

        optArg = "lstrip rstrip strip".split()
        for f in optArg:
            v = getattr(tainted, f)(" ")
            self.assertEqual(v, getattr(unquoted, f)(" "))
            self.assertIsInstance(v, self._getClass())

        justify = "center ljust rjust".split()
        for f in justify:
            v = getattr(tainted, f)(30)
            self.assertEqual(v, getattr(unquoted, f)(30))
            self.assertIsInstance(v, self._getClass())

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
        self.assertIsInstance(tainted.encode(), self._getClass())

        self.assertEqual(tainted.expandtabs(10), unquoted.expandtabs(10))
        self.assertIsInstance(tainted.expandtabs(), self._getClass())

        self.assertEqual(tainted.replace('test', 'spam'),
                         unquoted.replace('test', 'spam'))
        self.assertIsInstance(
            tainted.replace('test', '<'),
            self._getClass()
        )
        self.assertNotIsInstance(
            tainted.replace('test', 'spam'),
            self._getClass()
        )

        self.assertEqual(tainted.split(), unquoted.split())
        for part in self._getClass()('< < <').split():
            self.assertIsInstance(part, self._getClass())
        for part in tainted.split():
            self.assertNotIsInstance(part, self._getClass())

        multiline = 'test\n<tainted>'
        lines = self._getClass()(multiline).split()
        self.assertEqual(lines, multiline.split())
        self.assertIsInstance(lines[1], self._getClass())
        self.assertNotIsInstance(lines[0], self._getClass())

        transtable = ''.join(map(chr, range(256)))
        self.assertEqual(tainted.translate(transtable),
                         unquoted.translate(transtable))
        self.assertIsInstance(
            self._getClass()('<').translate(transtable),
            self._getClass()
        )

    def testQuoted(self):
        self.assertEqual(self.tainted.quoted(), self.quoted)


class TestTaintedBytes(TestTaintedString):

    def setUp(self):
        self.unquoted = b'<test attr="&">'
        self.quoted = b'&lt;test attr=&quot;&amp;&quot;&gt;'
        self.tainted = self._getClass()(self.unquoted)

    def _getClass(self):
        from AccessControl.tainted import TaintedBytes
        return TaintedBytes

    def testCmp(self):
        self.assertEqual(self.tainted, self.unquoted)
        self.assertEqual(self.tainted, self.unquoted)
        self.assertLess(self.tainted, b'a')
        self.assertGreater(self.tainted, b'.')

    CONCAT = b'test'

    def testGetItem(self):
        self.assertIsInstance(self.tainted[0], self._getClass())
        self.assertEqual(self.tainted[0], self._getClass()(b'<'))
        self.assertNotIsInstance(self.tainted[-1], self._getClass())
        self.assertEqual(self.tainted[-1], 62)

    def testStr(self):
        self.assertEqual(str(self.tainted), self.unquoted.decode('utf8'))

    def testGetSlice(self):
        self.assertIsInstance(self.tainted[0:1], self._getClass())
        self.assertEqual(self.tainted[0:1], b'<')
        self.assertNotIsInstance(self.tainted[1:], self._getClass())
        self.assertEqual(self.tainted[1:], self.unquoted[1:])

    def testInterpolate(self):
        tainted = self._getClass()(b'<%s>')
        self.assertIsInstance(tainted % b'foo', self._getClass())
        self.assertEqual(tainted % b'foo', b'<foo>')
        tainted = self._getClass()(b'<%s attr="%s">')
        self.assertIsInstance(
            tainted % (b'foo', b'bar'),
            self._getClass()
        )
        self.assertEqual(tainted % (b'foo', b'bar'), b'<foo attr="bar">')

    def testStringMethods(self):
        simple = "capitalize isalpha isdigit islower isspace istitle isupper" \
            " lower lstrip rstrip strip swapcase upper".split()
        returnsTainted = "capitalize lower lstrip rstrip strip swapcase upper"
        returnsTainted = returnsTainted.split()
        unquoted = b'\tThis is a test  '
        tainted = self._getClass()(unquoted)
        for f in simple:
            v = getattr(tainted, f)()
            self.assertEqual(v, getattr(unquoted, f)())
            if f in returnsTainted:
                self.assertIsInstance(v, self._getClass())
            else:
                self.assertNotIsInstance(v, self._getClass())

        optArg = "lstrip rstrip strip".split()
        for f in optArg:
            v = getattr(tainted, f)(b" ")
            self.assertEqual(v, getattr(unquoted, f)(b" "))
            self.assertIsInstance(v, self._getClass())

        justify = "center ljust rjust".split()
        for f in justify:
            v = getattr(tainted, f)(30)
            self.assertEqual(v, getattr(unquoted, f)(30))
            self.assertIsInstance(v, self._getClass())

        searches = "find index rfind rindex endswith startswith".split()
        searchraises = "index rindex".split()
        for f in searches:
            v = getattr(tainted, f)(b'test')
            self.assertEqual(v, getattr(unquoted, f)(b'test'))
            if f in searchraises:
                self.assertRaises(ValueError, getattr(tainted, f), b'nada')

        self.assertEqual(tainted.count(b'test', 1, -1),
                         unquoted.count(b'test', 1, -1))

        self.assertEqual(tainted.decode(), unquoted.decode())
        from AccessControl.tainted import TaintedString
        self.assertIsInstance(tainted.decode(), TaintedString)

        self.assertEqual(tainted.expandtabs(10), unquoted.expandtabs(10))
        self.assertIsInstance(tainted.expandtabs(), self._getClass())

        self.assertEqual(tainted.replace(b'test', b'spam'),
                         unquoted.replace(b'test', b'spam'))
        self.assertIsInstance(
            tainted.replace(b'test', b'<'),
            self._getClass()
        )
        self.assertNotIsInstance(
            tainted.replace(b'test', b'spam'),
            self._getClass()
        )

        self.assertEqual(tainted.split(), unquoted.split())
        for part in self._getClass()(b'< < <').split():
            self.assertIsInstance(part, self._getClass())
        for part in tainted.split():
            self.assertNotIsInstance(part, self._getClass())

        multiline = b'test\n<tainted>'
        lines = self._getClass()(multiline).split()
        self.assertEqual(lines, multiline.split())
        self.assertIsInstance(lines[1], self._getClass())
        self.assertNotIsInstance(lines[0], self._getClass())

        transtable = bytes(range(256))
        self.assertEqual(tainted.translate(transtable),
                         unquoted.translate(transtable))
        kls = self._getClass()(b'<')
        self.assertIsInstance(
            kls.translate(transtable),
            self._getClass()
        )

    def testConstructor(self):
        from AccessControl.tainted import TaintedBytes
        self.assertEqual(TaintedBytes(60), b'<')
        self.assertEqual(TaintedBytes(32), b' ')
        self.assertEqual(TaintedBytes(b'abc'), b'abc')
        self.assertRaises(ValueError, TaintedBytes, "abc")
