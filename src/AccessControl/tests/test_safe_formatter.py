from zExceptions import Unauthorized
import unittest


class FormatterTest(unittest.TestCase):
    """Test SafeFormatter and SafeStr.

    There are some integration tests in Zope2 itself.
    """

    def test_positional_argument_regression(self):
        """Testing fix of http://bugs.python.org/issue13598 issue."""
        from AccessControl.safe_formatter import SafeFormatter
        self.assertEqual(
            SafeFormatter('{} {}').safe_format('foo', 'bar'),
            'foo bar'
        )

        self.assertEqual(
            SafeFormatter('{0} {1}').safe_format('foo', 'bar'),
            'foo bar'
        )
        self.assertEqual(
            SafeFormatter('{1} {0}').safe_format('foo', 'bar'),
            'bar foo'
        )

    def test_prevents_bad_string_formatting(self):
        from AccessControl.safe_formatter import safe_format
        with self.assertRaises(Unauthorized) as err:
            safe_format('{0.__class__}', None)(1)
        self.assertEqual(
            "You are not allowed to access '__class__' in this context",
            str(err.exception))

    def test_prevents_bad_unicode_formatting(self):
        from AccessControl.safe_formatter import safe_format
        with self.assertRaises(Unauthorized) as err:
            safe_format(u'{0.__class__}', None)(1)
        self.assertEqual(
            "You are not allowed to access '__class__' in this context",
            str(err.exception))
