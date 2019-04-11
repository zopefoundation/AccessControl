#############################################################################
#
# Copyright (c) 2007 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################

import unittest

import zExceptions
from zope.interface import implementer
from zope.publisher.interfaces.browser import IBrowserRequest

from AccessControl.requestmethod import buildfacade
from AccessControl.requestmethod import getfullargspec
from AccessControl.requestmethod import requestmethod


@implementer(IBrowserRequest)
class DummyRequest:

    def __init__(self, method):
        self.method = method


GET = DummyRequest('GET')
POST = DummyRequest('POST')


class RequestMethodDecoratorsTests(unittest.TestCase):
    """Using request method decorators, you can limit functions or methods to
    only be callable when the HTTP request was made using a particular method.
    """

    def test_requires_the_defined_HTTP_mehtod(self):
        # To limit access to a function or method to POST requests, use the
        # requestmethod decorator factory:
        @requestmethod('POST')
        def foo(bar, REQUEST):
            return bar

        # When this method is accessed through a request that does not use
        # POST, the Forbidden exception will be raised:
        with self.assertRaises(zExceptions.Forbidden) as err:
            foo('spam', GET)
        self.assertEqual('Request must be POST', str(err.exception))

        # Only when the request was made using POST, will the call succeed:
        self.assertEqual('spam', foo('spam', POST))

    def test_it_does_not_matter_if_REQUEST_is_positional_or_keyword_arg(self):
        # It doesn't matter if REQUEST is a positional or a keyword parameter:

        @requestmethod('POST')
        def foo(bar, REQUEST=None):
            return bar

        with self.assertRaises(zExceptions.Forbidden) as err:
            foo('spam', GET)
        self.assertEqual('Request must be POST', str(err.exception))

        # *Not* passing an optional REQUEST always succeeds::
        self.assertEqual('spam', foo('spam', POST))

    def test_REQUEST_parameter_is_a_requirement(self):
        # Note that the REQUEST parameter is a requirement for the decorator to
        # operate, not including it in the callable signature results in an
        # error:
        try:
            @requestmethod('POST')
            def foo(bar):
                return bar
        except ValueError as e:
            self.assertEqual(
                'No REQUEST parameter in callable signature', str(e))
        else:
            self.fail('Did not raise')

    def test_preserves_keyword_parameter_defaults(self):
        # Because the Zope Publisher uses introspection to match REQUEST
        # variables against callable signatures, the result of the decorator
        # must match the original closely, and keyword parameter defaults must
        # be preserved:
        mutabledefault = dict()

        @requestmethod('POST')
        def foo(bar, baz=mutabledefault, egg=mutabledefault, REQUEST=None,
                *args):
            return bar, baz is mutabledefault, egg is None, REQUEST
        self.assertEqual((['bar', 'baz', 'egg', 'REQUEST'], 'args', None),
                         getfullargspec(foo)[:3])
        self.assertEqual(('spam', True, True, None), foo('spam', egg=None))
        with self.assertRaises(TypeError) as err:
            foo(monty='python')
        self.assertEqual("foo() got an unexpected keyword argument 'monty'",
                         str(err.exception))

    def test_can_be_used_for_any_request_method(self):
        # The `requestmethod` decorator factory can be used for any request
        # method, simply pass in the desired request method:
        @requestmethod('PUT')
        def foo(bar, REQUEST=None):
            return bar

        with self.assertRaises(zExceptions.Forbidden) as err:
            foo('spam', GET)
        self.assertEqual('Request must be PUT', str(err.exception))

    def test_allows_multiple_request_methods(self):
        # You can pass in multiple request methods allow access by any of them:
        @requestmethod('GET', 'HEAD', 'PROPFIND')
        def foo(bar, REQUEST=None):
            return bar

        self.assertEqual('spam', foo('spam', GET))
        with self.assertRaises(zExceptions.Forbidden) as err:
            foo('spam', POST)
        self.assertEqual('Request must be GET, HEAD or PROPFIND',
                         str(err.exception))

    def test_facade_render_correct_args_kwargs(self):
        """ s. https://github.com/zopefoundation/AccessControl/issues/69
        """
        def foo(bar, baz, *args, **kwargs):
            """foo doc"""
            return baz
        got = buildfacade('foo', foo, foo.__doc__)
        expected = '\n'.join([
            'def foo(bar, baz, *args, **kwargs):',
            '    """foo doc"""',
            '    return _curried(bar, baz, *args, **kwargs)'])
        self.assertEqual(expected, got)
