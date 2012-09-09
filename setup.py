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
from setuptools import setup, find_packages, Extension

setup(name='AccessControl',
      version='3.0.5dev',
      url='http://pypi.python.org/pypi/AccessControl',
      license='ZPL 2.1',
      description="Security framework for Zope2.",
      author='Zope Foundation and Contributors',
      author_email='zope-dev@zope.org',
      long_description=open('README.txt').read() + '\n' +
                       open('CHANGES.txt').read(),
      packages=find_packages('src'),
      package_dir={'': 'src'},
      ext_modules=[Extension(
            name='AccessControl.cAccessControl',
            include_dirs=['include', 'src'],
            sources=[join('src', 'AccessControl', 'cAccessControl.c')],
            depends=[join('include', 'ExtensionClass', 'ExtensionClass.h'),
                     join('include', 'Acquisition', 'Acquisition.h')]),
      ],
      install_requires=[
        'Acquisition',
        'DateTime',  # optional dependency of RestrictedPython
        'ExtensionClass',
        'Persistence',
        'Record',
        'RestrictedPython',
        'transaction',
        'zExceptions',
        'ZODB3',
        'zope.component',
        'zope.configuration',
        'zope.deferredimport',
        'zope.interface',
        'zope.publisher',
        'zope.schema',
        'zope.security',
        'zope.testing',
      ],
      include_package_data=True,
      zip_safe=False,
      )
