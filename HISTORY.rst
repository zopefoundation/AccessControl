Pre 3.0 Changelog
=================

2.13.12 (2012-10-31)
--------------------

- LP #1071067: Use a stronger random number generator and a constant time
  comparison function.

2.13.11 (2012-10-21)
--------------------

- LP #966101: Recognize special `zope2.Private` permission in ZCML
  role directive.

2.13.10 (2012-09-09)
--------------------

- LP #1047318: Tighten import restrictions for restricted code.

2.13.9 (2012-08-23)
-------------------

- Fix a bug in ZopeSecurityPolicy.py. Global variable `rolesForPermissionOn`
  could be overridden if `__role__` had custom rolesForPermissionOn.

2.13.8 (2012-06-22)
-------------------

- Add Anonymous as a default role for Public permission.

2.13.7 (2011-12-12)
-------------------

- Exclude compiled `.so` and `.dll` files from source distributions.

2.13.6 (2011-12-12)
-------------------

- Added `manifest.in` to ensure the inclusion of the `include` directory into
  the release.

2.13.5 (2011-12-12)
-------------------

- Apply changes made available in `Products.Zope_Hotfix_20111024` and make them
  more robust.

2.13.4 (2011-01-11)
-------------------

- Return the created user in _doAddUser.

- Added IUser interface.

- LP #659968: Added support for level argument to the ``__import__`` function
  as introduced in Python 2.5. Currently only level=-1 is supported.

2.13.3 (2010-08-28)
-------------------

- Added a ``role`` subdirective for the ``permission`` ZCML directive. If any
  roles are specified, they will override the default set of default roles
  (Manager).

2.13.2 (2010-07-16)
-------------------

- Added ``override_existing_protection`` parameter to the protectName helper.

2.13.1 (2010-06-19)
-------------------

- Restore security declarations for deprecated ``sets`` module.

2.13.0 (2010-06-19)
-------------------

- Released as separate package.
