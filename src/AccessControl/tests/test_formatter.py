from zExceptions import Unauthorized
import unittest


class FormatterTest(unittest.TestCase):
    """Test our safe formatter.

    This started out with more tests, but they all need
    Products.PageTemplates, which means Zope2, which means we would need
    to pull in far too many dependencies, and need many extra version
    pins to get a sane environment.  So look for some tests in Zope2
    itself.
    """

    def test_positional_argument_regression(self):
        """
        to test http://bugs.python.org/issue13598 issue
        """
        from AccessControl.safe_formatter import SafeFormatter
        try:
            self.assertEqual(
                SafeFormatter('{} {}').safe_format('foo', 'bar'),
                'foo bar'
            )
        except ValueError:
            # On Python 2.6 you get:
            # ValueError: zero length field name in format
            pass

        self.assertEqual(
            SafeFormatter('{0} {1}').safe_format('foo', 'bar'),
            'foo bar'
        )
        self.assertEqual(
            SafeFormatter('{1} {0}').safe_format('foo', 'bar'),
            'bar foo'
        )

    def test_prevents_bad_string_formatting(self):
        from AccessControl.safe_formatter import SafeFormatter
        self.assertRaises(Unauthorized,
                          SafeFormatter('{0.__class__}').safe_format,
                          'foo')

    def test_prevents_bad_unicode_formatting(self):
        from AccessControl.safe_formatter import SafeFormatter
        self.assertRaises(Unauthorized,
                          SafeFormatter(u'{0.__class__}').safe_format,
                          u'foo')
