import string
from collections.abc import Mapping

import _string

from AccessControl.ZopeGuards import guarded_getattr
from AccessControl.ZopeGuards import guarded_getitem


def formatter_field_name_split(field_name):
    return _string.formatter_field_name_split(field_name)


class _MagicFormatMapping(Mapping):
    """Pulled from Jinja2.

    This class implements a dummy wrapper to fix a bug in the Python
    standard library for string formatting.

    See http://bugs.python.org/issue13598 for information about why
    this is necessary.
    """

    def __init__(self, args, kwargs):
        self._args = args
        self._kwargs = kwargs
        self._last_index = 0

    def __getitem__(self, key):
        if key == '':
            idx = self._last_index
            self._last_index += 1
            try:
                return self._args[idx]
            except LookupError:
                pass
            key = str(idx)
        return self._kwargs[key]

    def __iter__(self):
        return iter(self._kwargs)

    def __len__(self):
        return len(self._kwargs)


class SafeFormatter(string.Formatter):
    """Formatter using guarded access."""

    def __init__(self, value):
        self.value = value
        super().__init__()

    def get_field(self, field_name, args, kwargs):
        """Get the field value using guarded methods."""
        first, rest = formatter_field_name_split(field_name)

        obj = self.get_value(first, args, kwargs)

        # loop through the rest of the field_name, doing
        #  getattr or getitem as needed
        for is_attr, i in rest:
            if is_attr:
                obj = guarded_getattr(obj, i)
            else:
                obj = guarded_getitem(obj, i)

        return obj, first

    def safe_format(self, *args, **kwargs):
        """Safe variant of `format` method."""
        kwargs = _MagicFormatMapping(args, kwargs)
        return self.vformat(self.value, args, kwargs)

    def safe_format_map(self, kw):
        kwargs = _MagicFormatMapping((), kw)
        return self.vformat(self.value, (), kwargs)


def safe_format(inst, method):
    """Use our SafeFormatter that uses guarded_getattr for attribute access."""
    return SafeFormatter(inst).safe_format


def safe_format_map(inst, method):
    return SafeFormatter(inst).safe_format_map
