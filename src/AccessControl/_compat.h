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

#include "Python.h"

#if PY_MAJOR_VERSION >= 3
#define PY3K
#endif

#ifdef PY3K
#define NATIVE_FORMAT PyUnicode_Format
#define NATIVE_GET_SIZE PyUnicode_GET_SIZE
#else
#define NATIVE_FORMAT PyString_Format
#define NATIVE_GET_SIZE PyString_GET_SIZE
#endif
