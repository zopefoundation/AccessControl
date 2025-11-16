##############################################################################
#
# Copyright (c) 2010 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################

from os.path import join

from setuptools import Extension
from setuptools import setup


ext_modules = [
    Extension(
        name='AccessControl.cAccessControl',
        include_dirs=['include', 'src'],
        sources=[join('src', 'AccessControl', 'cAccessControl.c')],
        depends=[join('include', 'ExtensionClass', 'ExtensionClass.h'),
                 join('include', 'ExtensionClass', '_compat.h'),
                 join('include', 'Acquisition', 'Acquisition.h')]),
]


setup(ext_modules=ext_modules)
