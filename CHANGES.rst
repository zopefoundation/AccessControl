Changelog
=========

For changes before version 3.0, see ``HISTORY.rst``.

4.0 (unreleased)
----------------

- Extract ``.AuthEncoding`` to its own package for reuse.


4.0a2 (2016-08-01)
------------------

- Declare missing dependency on BTrees.

4.0a1 (2016-07-21)
------------------

- Modernised C code in preparation of porting to Python 3.

- #16: Fixed permission handling by avoiding column and row numbers as
  identifiers for permissions and roles.

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
