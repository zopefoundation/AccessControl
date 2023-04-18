/*****************************************************************************

  Copyright (c) 2012 Zope Foundation and Contributors.
  All Rights Reserved.

  This software is subject to the provisions of the Zope Public License,
  Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
  WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
  FOR A PARTICULAR PURPOSE

 ****************************************************************************/

#ifndef PERSISTENT__COMPAT_H
#define PERSISTENT__COMPAT_H

#include "Python.h"

#define INTERN PyUnicode_InternFromString
#define INTERN_INPLACE PyUnicode_InternInPlace
#define NATIVE_CHECK PyUnicode_Check
#define NATIVE_CHECK_EXACT PyUnicode_CheckExact
#define NATIVE_FROM_STRING PyUnicode_FromString
#define NATIVE_FROM_STRING_AND_SIZE PyUnicode_FromStringAndSize

#define INT_FROM_LONG(x) PyLong_FromLong(x)
#define INT_CHECK(x) PyLong_Check(x)
#define INT_AS_LONG(x) PyLong_AS_LONG(x)

#define HAS_TP_DESCR_GET(ob) 1

#endif

/* Python compatibility shims */

// Compatibility with Visual Studio 2013 and older which don't support
// the inline keyword in C (only in C++): use __inline instead.
#if (defined(_MSC_VER) && _MSC_VER < 1900 \
     && !defined(__cplusplus) && !defined(inline))
#  define inline __inline
#  define PYTHONCAPI_COMPAT_MSC_INLINE
   // These two macros are undefined at the end of this file
#endif

#ifndef _PyObject_CAST
#  define _PyObject_CAST(op) ((PyObject*)(op))
#endif

#if PY_VERSION_HEX < 0x030900A4 && !defined(Py_SET_TYPE)
static inline void
_Py_SET_TYPE(PyObject *ob, PyTypeObject *type)
{
    ob->ob_type = type;
}
#define Py_SET_TYPE(ob, type) _Py_SET_TYPE(_PyObject_CAST(ob), type)
#endif

#ifdef PYTHONCAPI_COMPAT_MSC_INLINE
#  undef inline
#  undef PYTHONCAPI_COMPAT_MSC_INLINE
#endif
