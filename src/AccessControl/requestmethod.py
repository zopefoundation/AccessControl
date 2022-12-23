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

from inspect import getfullargspec
from inspect import signature

from zExceptions import Forbidden
from zope.publisher.interfaces.browser import IBrowserRequest


_default = []


def buildfacade(name, method, docstring):
    """Build a facade function, matching the decorated method in signature.

    Note that defaults are replaced by _default, and _curried will reconstruct
    these to preserve mutable defaults.

    """
    sig = signature(method)
    args = []
    callargs = []
    for v in sig.parameters.values():
        parts = str(v).split('=')
        args.append(
            parts[0] if len(parts) == 1 else
            f'{parts[0]}=_default')  # NOQA: 43
        callargs.append(parts[0])
    return 'def {}({}):\n    """{}"""\n    return _curried({})'.format(
        name, ', '.join(args), docstring, ', '.join(callargs))


def requestmethod(*methods):
    """Create a request method specific decorator"""
    methods = list(map(lambda m: m.upper(), methods))
    if len(methods) > 1:
        methodsstr = ', '.join(methods[:-1])
        methodsstr += ' or ' + methods[-1]
    else:
        methodsstr = methods[0]

    def _methodtest(callable):
        """Only allow callable when request method is %s.""" % methodsstr
        spec = getfullargspec(callable)
        args, defaults = spec[0], spec[3]
        try:
            r_index = args.index('REQUEST')
        except ValueError:
            raise ValueError('No REQUEST parameter in callable signature')

        arglen = len(args)
        if defaults is not None:
            defaults = list(zip(args[arglen - len(defaults):], defaults))
            arglen -= len(defaults)

        def _curried(*args, **kw):
            request = args[r_index]
            if IBrowserRequest.providedBy(request):
                if request.method not in methods:
                    raise Forbidden('Request must be %s' % methodsstr)

            # Reconstruct keyword arguments
            if defaults is not None:
                args, kwparams = args[:arglen], args[arglen:]
                for positional, (key, default) in zip(kwparams, defaults):
                    if positional is _default:
                        kw[key] = default
                    else:
                        kw[key] = positional

            return callable(*args, **kw)

        # Build a facade, with a reference to our locally-scoped _curried
        name = callable.__name__
        facade_globs = dict(_curried=_curried, _default=_default)
        exec(buildfacade(name, callable, callable.__doc__), facade_globs)
        return facade_globs[name]

    return _methodtest


# For Zope versions 2.8 - 2.10
postonly = requestmethod('POST')

__all__ = ('requestmethod', 'postonly')
