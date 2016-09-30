Request method decorators
=========================

Using request method decorators, you can limit functions or methods to only
be callable when the HTTP request was made using a particular method.

To limit access to a function or method to POST requests, use the
`requestmethod` decorator factory::

  >>> from AccessControl.requestmethod import requestmethod
  >>> @requestmethod('POST')
  ... def foo(bar, REQUEST):
  ...     return bar

When this method is accessed through a request that does not use POST, the
Forbidden exception will be raised::

  >>> foo('spam', GET)
  Traceback (most recent call last):
  ...
  Forbidden: Request must be POST

Only when the request was made using POST, will the call succeed::

  >>> foo('spam', POST)
  'spam'

The `REQUEST` can be is a positional or a keyword parameter.
*Not* passing an optional `REQUEST` always succeeds.

Note that the `REQUEST` parameter is a requirement for the decorator to
operate, not including it in the callable signature results in an error.

You can pass in multiple request methods allow access by any of them.
