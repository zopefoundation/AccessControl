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
            self.assertEquals(
                SafeFormatter('{} {}').safe_format('foo', 'bar'),
                'foo bar'
            )
        except ValueError:
            # On Python 2.6 you get:
            # ValueError: zero length field name in format
            pass

        self.assertEquals(
            SafeFormatter('{0} {1}').safe_format('foo', 'bar'),
            'foo bar'
        )
        self.assertEquals(
            SafeFormatter('{1} {0}').safe_format('foo', 'bar'),
            'bar foo'
        )
