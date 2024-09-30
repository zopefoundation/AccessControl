Changelog
=========

For changes before version 3.0, see ``HISTORY.rst``.

7.1 (unreleased)
----------------

- Respect ``PURE_PYTHON`` environment variable set to ``0`` when running tests.


7.0 (2024-05-30)
----------------

- Add preliminary support for Python 3.13 as of 3.13b1.

- Remove support for Python 3.7.

- Build Windows wheels on GHA.

- Make dict views (`.keys()`, `.items()` and `.values()`) behave like their
  unrestricted versions.
  (`#147 <https://github.com/zopefoundation/AccessControl/pull/147>`_)

- Make `.items()` validate each keys and values, like `.keys()` and
  `.values()` do.

- Fix build errors on recent macOS versions.


6.3 (2023-11-20)
----------------

- Add support for Python 3.12.


6.2 (2023-09-04)
----------------

- Fix information disclosure through ``str.format_map``.
  (CVE-2023-41050)


6.1 (2023-05-22)
----------------
- Update C header files for ``ExtensionClass`` and ``Acquisition``
  from the original packages where needed.
  (`#140 <https://github.com/zopefoundation/AccessControl/issues/140>`_)

- Add preliminary support for Python 3.12a5.


6.0 (2023-01-12)
----------------

- Build Linux binary wheels for Python 3.11

- Drop support for Python 2.7, 3.5, 3.6.


5.7 (2022-11-17)
----------------

- Add support for building arm64 wheels on macOS.


5.6 (2022-11-03)
----------------

- Add support for final Python 3.11 release.


5.5 (2022-10-10)
----------------

- Switch from ``-Ofast`` to ``-O3`` when compiling code for Linux wheels.
  (`#133 <https://github.com/zopefoundation/AccessControl/pull/133>`_)

- Add support for Python 3.11 (as of 3.11.0rc2).


5.4 (2022-08-26)
----------------

- Add support for Python 3.11 (as of 3.11.0b5).

- Support ``default`` argument in ``next`` built-in function.
  (`#131 <https://github.com/zopefoundation/AccessControl/pull/131>`_)


5.3.1 (2022-03-29)
------------------

- Prevent race condition in guarded_import
  (`#123 <https://github.com/zopefoundation/AccessControl/issues/123>`_)


5.3 (2022-02-25)
----------------

- Provide ``AccessControl.get_safe_globals`` to facilitate safe use.

- Honor ``PURE_PYTHON`` environment variable to enable python implementation
  during runtime.

- Add support for Python 3.10.


5.2 (2021-07-30)
----------------

- Fix Appveyor configuration so tests can run and wheels build.


5.1 (2021-07-30)
----------------
NOTE: This release has been yanked from PyPI due to wheel build issues.

- Fix a remote code execution issue by preventing access to
  ``string.Formatter`` from restricted code.


5.0 (2020-10-07)
----------------

- Add support for Python 3.9.

- Remove deprecated classes and functions in
  (see `#32 <https://github.com/zopefoundation/AccessControl/issues/32>`_):

  + ``AccessControl/DTML.py``
  + ``AccessControl/Owned.py``
  + ``AccessControl/Role.py``
  + ``AccessControl/Permissions.py``

- Add deprecation warnings for BBB imports in:

  + ``AccessControl/AuthEncoding.py``
  + ``AccessControl/Owned.py``
  + ``AccessControl/Role.py``
  + ``AccessControl/User.py``

- Although this version might run on Zope 4, it is no longer supported because
  of the dropped deprecation warnings.


4.2 (2020-04-20)
----------------

- Add missing permission ``Manage WebDAV Locks``

- Fix regression for BBB import of ```users.UnrestrictedUser``
  (`#94 <https://github.com/zopefoundation/AccessControl/issues/94>`_)

- Add a check if database is present in ``.owner.ownerInfo``.
  (`#91 <https://github.com/zopefoundation/AccessControl/issues/91>`_).


4.1 (2019-09-02)
----------------

- Python 3: Allow iteration over the result of ``dict.{keys,values,items}``
  (`#89 <https://github.com/zopefoundation/AccessControl/issues/89>`_).


4.0 (2019-05-08)
----------------

Changes since 3.0.12:

- Add support for Python 3.5, 3.6, 3.7 and 3.8.

- Restore simple access to bytes methods in Python 3
  (`#83 <https://github.com/zopefoundation/AccessControl/issues/83>`_)

- Clarify deprecation warnings for several BBB shims.
  (`#32 <https://github.com/zopefoundation/AccessControl/issues/32>`_)

- Add a test to prove that a user folder flag cannot be acquired elsewhere.
  (`#7 <https://github.com/zopefoundation/AccessControl/issues/7>`_)

- Tighten basic auth string handling in ``BasicUserFolder.identify``
  (`#56 <https://github.com/zopefoundation/AccessControl/issues/56>`_)

- Prevent the Zope 4 ZMI from showing an add dialog for the user folder.
  (`#82 <https://github.com/zopefoundation/AccessControl/issues/82>`_)

- Fix order of roles returned by
  ``AccessControl.rolemanager.RoleManager.userdefined_roles``.

- Add configuration for `zodbupdate`.

- Add ``TaintedBytes`` besides ``TaintedString`` in ``AccessControl.tainted``.
  (`#57 <https://github.com/zopefoundation/AccessControl/issues/57>`_)

- Security fix: In ``str.format``, check the security for attributes that are
  accessed. (Ported from 2.13).

- Port ``override_container`` context manager here from 2.13.

- Add AppVeyor configuration to automate building Windows eggs.

- Fix for compilers that only support C89 syntax (e.g. on Windows).

- Sanitize and test `RoleManager` role handling.

- Depend on RestrictedPython >= 4.0.

- #16: Fixed permission handling by avoiding column and row numbers as
  identifiers for permissions and roles.

- Extract ``.AuthEncoding`` to its own package for reuse.

- Declare missing dependency on BTrees.

- Drop `Record` dependency, which now does its own security declaration.

- Remove leftovers from history support dropped in Zope.

- Remove duplicate guard against * imports.
  (`#60 <https://github.com/zopefoundation/AccessControl/issues/60>`_)


3.0.12 (2015-12-21)
-------------------

- Avoid acquiring ``access`` from module wrapped by
  ``SecurityInfo._ModuleSecurityInfo``.  See:
  https://github.com/zopefoundation/AccessControl/issues/12

3.0.11 (2014-11-02)
-------------------

- Harden test fix for machines that do not define `localhost`.

3.0.10 (2014-11-02)
-------------------

- Test fix for machines that do not define `localhost`.

3.0.9 (2014-08-08)
------------------

- GitHub #6: Do not pass SecurityInfo instance itself to declarePublic/declarePrivate
  when using the public/private decorator. This fixes ``Conflicting security declarations``
  warnings on Zope startup.

- LP #1248529: Leave existing security manager in place inside
  ``RoleManager.manage_getUserRolesAndPermissions``.

3.0.8 (2013-07-16)
------------------

- LP #1169923:  ensure initialization of shared ``ImplPython`` state
  (used by ``ImplC``) when using the "C" security policy.  Thanks to
  Arnaud Fontaine for the patch.

3.0.7 (2013-05-14)
------------------

- Remove long-deprecated 'Shared' roles support (pre-dates Zope, never
  used by Zope itself)

- Prevent infinite loop when looking up local roles in an acquisition chain
  with cycles.

3.0.6 (2012-10-31)
------------------

- LP #1071067: Use a stronger random number generator and a constant time
  comparison function.

3.0.5 (2012-10-21)
------------------

- LP #966101: Recognize special `zope2.Private` permission in ZCML
  role directive.

3.0.4 (2012-09-09)
------------------

- LP #1047318: Tighten import restrictions for restricted code.

3.0.3 (2012-08-23)
------------------

- Fix a bug in ZopeSecurityPolicy.py. Global variable `rolesForPermissionOn`
  could be overridden if `__role__` had custom rolesForPermissionOn.

3.0.2 (2012-06-22)
------------------

- Add Anonymous as a default role for Public permission.

3.0.1 (2012-05-24)
------------------

- Fix tests under Python 2.6.

3.0 (2012-05-12)
----------------

- Added decorators for public, private and protected security declarations.

- Update tests to take advantage of automatic test suite discovery.
