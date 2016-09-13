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

from zope.interface import implementer
from zope.publisher.interfaces.browser import IBrowserRequest


@implementer(IBrowserRequest)
class DummyRequest:

    def __init__(self, method):
        self.method = method


def test_suite():
    from doctest import DocFileSuite
    return DocFileSuite('../requestmethod.txt',
                        globs=dict(GET=DummyRequest('GET'),
                                   POST=DummyRequest('POST')))
