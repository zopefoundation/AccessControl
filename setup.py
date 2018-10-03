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

README = open('README.rst').read()
CHANGES = open('CHANGES.rst').read()

ext_modules = [
    Extension(
        name='AccessControl.cAccessControl',
        include_dirs=['include', 'src'],
        sources=[join('src', 'AccessControl', 'cAccessControl.c')],
        depends=[join('include', 'ExtensionClass', 'ExtensionClass.h'),
                 join('include', 'ExtensionClass', '_compat.h'),
                 join('include', 'Acquisition', 'Acquisition.h')]),
]

version = '4.0b5.dev0'


setup(name='AccessControl',
      version=version,
      url='http://pypi.python.org/pypi/AccessControl',
      license='ZPL 2.1',
      description="Security framework for Zope2.",
      author='Zope Foundation and Contributors',
      author_email='zope-dev@zope.org',
      long_description=README + '\n\n' + CHANGES,
      packages=find_packages('src'),
      package_dir={'': 'src'},
      classifiers=[
          "Development Status :: 6 - Mature",
          "Environment :: Web Environment",
          "Framework :: Zope2",
          "License :: OSI Approved :: Zope Public License",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Programming Language :: Python :: Implementation :: CPython",
      ],
      ext_modules=ext_modules,
      install_requires=[
          'Acquisition',
          'AuthEncoding',
          'BTrees',
          'DateTime',  # optional dependency of RestrictedPython
          'ExtensionClass>=4.2.1',
          'Persistence>=3.0a3',
          'RestrictedPython >= 4.0a1',
          'six',
          'transaction',
          'zExceptions',
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
