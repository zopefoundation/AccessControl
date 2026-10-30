##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""SecurityInfo objects and access control constants.

   SecurityInfo objects are used in class definitions to allow
   a declarative style of associating access control information
   with class attributes.

   More information on using SecurityInfo and guide to Zope security
   for developers can be found in the dev.zope.org "Declarative Security"
   project:

   http://dev.zope.org/Wikis/DevSite/Projects/DeclarativeSecurity

   While SecurityInfo objects largely remove the need for Python
   programmers to care about the underlying implementation, there
   are several constants defined that should be used by code that
   must set __roles__ attributes directly. (the constants are also
   accessible from the AccessControl namespace). The defined access
   control constants and their meanings are:

   ACCESS_PUBLIC:  accessible from restricted code and possibly
                   through the web (if object has a docstring)

   ACCESS_PRIVATE: accessible only from python code

   ACCESS_NONE:    no access

"""

import sys
from logging import getLogger

from Acquisition import Implicit
from Persistence import Persistent

from AccessControl import frozen
from AccessControl.class_init import InitializeClass
from AccessControl.ImplPython import _what_not_even_god_should_do


# always patch Persistent before ClassSecurityInfo is used
Persistent.__class_init__ = InitializeClass

LOG = getLogger('SecurityInfo')

# Security constants - these are imported into the AccessControl
# namespace and can be referenced as AccessControl.PUBLIC etc.

ACCESS_NONE = _what_not_even_god_should_do
ACCESS_PRIVATE = ()
ACCESS_PUBLIC = None

_marker = []


class SecurityInfo(Implicit):
    """Encapsulate security information."""

    __security_info__ = 1

    __roles__ = ACCESS_PRIVATE

    def __init__(self):
        self.names = {}
        self.roles = {}
        self._unused_protected_decorators = set()

    def _setaccess(self, names, access):
        for name in names:
            if self.names.get(name, access) != access:
                LOG.warning(
                    f'Conflicting security declarations for {name!r}')
                self._warnings = 1
            self.names[name] = access

    declarePublic__roles__ = ACCESS_PRIVATE

    def declarePublic(self, name, *names):
        """Declare names to be publicly accessible."""
        self._setaccess((name,) + names, ACCESS_PUBLIC)

    declarePrivate__roles__ = ACCESS_PRIVATE

    def declarePrivate(self, name, *names):
        """Declare names to be inaccessible to restricted code."""
        self._setaccess((name,) + names, ACCESS_PRIVATE)

    declareProtected__roles__ = ACCESS_PRIVATE

    def declareProtected(self, permission_name, name, *names):
        """Declare names to be associated with a permission."""
        self._setaccess((name,) + names, permission_name)

    declareObjectPublic__roles__ = ACCESS_PRIVATE

    def declareObjectPublic(self):
        """Declare the object to be publicly accessible."""
        self._setaccess(('',), ACCESS_PUBLIC)

    declareObjectPrivate__roles__ = ACCESS_PRIVATE

    def declareObjectPrivate(self):
        """Declare the object to be inaccessible to restricted code."""
        self._setaccess(('',), ACCESS_PRIVATE)

    declareObjectProtected__roles__ = ACCESS_PRIVATE

    def declareObjectProtected(self, permission_name):
        """Declare the object to be associated with a permission."""
        self._setaccess(('',), permission_name)

    public__roles__ = ACCESS_PRIVATE

    def public(self, func):
        """Decorate a function to be publicly accessible."""
        self.declarePublic(func.__name__)  # NOQA: D001
        return func

    private__roles__ = ACCESS_PRIVATE

    def private(self, func):
        """Decorate a function to be inaccessible to restricted code."""
        self.declarePrivate(func.__name__)  # NOQA: D001
        return func

    protected__roles__ = ACCESS_PRIVATE

    def protected(self, permission_name):
        """Return a decorator to associate a function with a permission."""
        # the decorator returned is remembered in a set and will
        # remove itself upon call. self.apply will check for an empty
        # set and raise an AssertionError otherwise.
        key = f"'{permission_name}':{id(lambda x: x)}"

        def decor(func):
            self.declareProtected(permission_name, func.__name__)  # NOQA: D001
            self._unused_protected_decorators.remove(key)
            return func
        # make sure our key algo creates unique-enough keys
        if key in self._unused_protected_decorators:
            raise KeyError(f"Duplicate key: {key}")
        self._unused_protected_decorators.add(key)
        return decor

    setPermissionDefault__roles__ = ACCESS_PRIVATE

    def setPermissionDefault(self, permission_name, roles):
        """Declare default roles for a permission"""
        rdict = {}
        for role in roles:
            rdict[role] = 1
        if self.roles.get(permission_name, rdict) != rdict:
            LOG.warning('Conflicting default role'
                        ' declarations for permission "%s"' % permission_name)
            self._warnings = 1
        self.roles[permission_name] = rdict

    setDefaultAccess__roles__ = ACCESS_PRIVATE

    def setDefaultAccess(self, access):
        """Declare default attribute access policy.

        This should be a boolean value, a map of attribute names to
        booleans, or a callable (name, value) -> boolean.
        """
        if isinstance(access, str):
            access = access.lower()
            if access == 'allow':
                access = 1
            elif access == 'deny':
                access = 0
            else:
                raise ValueError("'allow' or 'deny' expected")
        self.access = access


class ClassSecurityInfo(SecurityInfo):
    """Encapsulate security information for class objects."""

    __roles__ = ACCESS_PRIVATE

    apply__roles__ = ACCESS_PRIVATE

    def apply(self, classobj):
        """Apply security information to the given class object."""

        # make sure all decorators handed out by security.protected were used
        if self._unused_protected_decorators:
            msg = "Class '%r' has %d non-decorator security.protected calls!"
            raise AssertionError(msg % (classobj,
                                 len(self._unused_protected_decorators)))

        cdict = classobj.__dict__

        # Check the class for an existing __ac_permissions__ and
        # incorporate that if present to support older classes or
        # classes that haven't fully switched to using SecurityInfo.
        if '__ac_permissions__' in cdict:
            for item in cdict['__ac_permissions__']:
                permission_name = item[0]
                self._setaccess(item[1], permission_name)
                if len(item) > 2:
                    self.setPermissionDefault(permission_name, item[2])

        # Set __roles__ for attributes declared public or private.
        # Collect protected attribute names in ac_permissions.
        ac_permissions = {}
        for name, access in self.names.items():
            if access in (ACCESS_PRIVATE, ACCESS_PUBLIC, ACCESS_NONE):
                setattr(classobj, '%s__roles__' % name, access)
            else:
                if access not in ac_permissions:
                    ac_permissions[access] = []
                ac_permissions[access].append(name)

        # Now transform our nested dict structure into the nested tuple
        # structure expected of __ac_permissions__ attributes and set
        # it on the class object.
        getRoles = self.roles.get
        __ac_permissions__ = []
        permissions = sorted(ac_permissions.items())
        for permission_name, names in permissions:
            roles = getRoles(permission_name, ())
            if len(roles):
                entry = (permission_name, tuple(names), tuple(roles.keys()))
            else:
                entry = (permission_name, tuple(names))
            __ac_permissions__.append(entry)
        for permission_name, roles in self.roles.items():
            if permission_name not in ac_permissions:
                entry = (permission_name, (), tuple(roles.keys()))
                __ac_permissions__.append(entry)
        setattr(classobj, '__ac_permissions__', tuple(__ac_permissions__))

        # Take care of default attribute access policy
        access = getattr(self, 'access', _marker)
        if access is not _marker:
            setattr(classobj, '__allow_access_to_unprotected_subobjects__',
                    access)

        if getattr(self, '_warnings', None):
            LOG.warning('Class "%s" had conflicting'
                        ' security declarations' % classobj.__name__)


class ClassSecurityInformation(ClassSecurityInfo):
    # Default policy is disallow
    access = 0


_moduleSecurity = frozen.FreezableDict()
_appliedModuleSecurity = frozen.FreezableDict()


def secureModule(mname, *imp):
    modsec = _moduleSecurity.get(mname, None)
    if modsec is None:
        if mname in _appliedModuleSecurity:
            return sys.modules[mname]
        return  # no MSI, no module

    if imp:
        __import__(mname, *imp)
    module = sys.modules[mname]
    modsec.apply(module.__dict__)
    _appliedModuleSecurity[mname] = modsec
    try:
        del _moduleSecurity[mname]
    except KeyError:
        # In case of access from multiple threads, the del might fail, but that
        # is OK.
        pass
    return module


def ModuleSecurityInfo(module_name=None):
    if module_name is not None:
        modsec = _moduleSecurity.get(module_name, None)
        if modsec is not None:
            return modsec
        modsec = _appliedModuleSecurity.get(module_name, None)
        if modsec is not None:
            # Move security info back to to-apply dict (needed for product
            # refresh). Also invoke this check for parent packages already
            # applied
            del _appliedModuleSecurity[module_name]
            _moduleSecurity[module_name] = modsec
            dot = module_name.rfind('.')
            if dot > 0:
                ModuleSecurityInfo(module_name[:dot])
            return modsec
        dot = module_name.rfind('.')
        if dot > 0:
            # If the module is in a package, recursively make sure
            # there are security declarations for the package steps
            # leading to the module
            modname = module_name[dot + 1:]
            pmodsec = ModuleSecurityInfo(module_name[:dot])
            if modname not in pmodsec.names:
                pmodsec.declarePublic(modname)  # NOQA: D001
    return _ModuleSecurityInfo(module_name)


class _ModuleSecurityInfo(SecurityInfo):
    """Encapsulate security information for modules."""

    __roles__ = ACCESS_PRIVATE
    access = False  # deny by default, prevent acquiring 'access' from module

    def __init__(self, module_name=None):
        self.names = {}
        if module_name is not None:
            global _moduleSecurity  # noqa: F824
            _moduleSecurity[module_name] = self

    __call____roles__ = ACCESS_PRIVATE

    def __call__(self, name, value):
        """Callback for __allow_access_to_unprotected_subobjects__ hook."""
        access = self.names.get(name, _marker)
        if access is not _marker:
            return access == ACCESS_PUBLIC

        return getattr(self, 'access', 0)

    def _setaccess(self, names, access):
        frozen.check_not_frozen()
        super()._setaccess(names, access)

    setDefaultAccess__roles__ = ACCESS_PRIVATE

    def setDefaultAccess(self, access):
        """Declare default attribute access policy."""
        frozen.check_not_frozen()
        super().setDefaultAccess(access)

    apply__roles__ = ACCESS_PRIVATE

    def apply(self, dict):
        """Apply security information to the given module dict."""

        # Start with default attribute access policy
        access = getattr(self, 'access', _marker)
        if access is not _marker or len(self.names):
            dict['__allow_access_to_unprotected_subobjects__'] = self

        if getattr(self, '_warnings', None):
            LOG.warning('Module "%s" had conflicting'
                        ' security declarations' % dict['__name__'])

    declareProtected__roles__ = ACCESS_PRIVATE

    def declareProtected(self, permission_name, *names):
        """Cannot declare module names protected."""
        pass

    declareObjectProtected__roles__ = ACCESS_PRIVATE

    def declareObjectProtected(self, permission_name):
        """Cannot declare module protected."""
        pass

    setDefaultRoles__roles__ = ACCESS_PRIVATE

    def setDefaultRoles(self, permission_name, roles):
        """Cannot set default roles for permissions in a module."""
        pass

# Handy little utility functions


def allow_module(module_name):
    """Allow a module and all its contents to be used from a
    restricted Script. The argument module_name may be a simple
    or dotted module or package name. Note that if a package
    path is given, all modules in the path will be available."""
    ModuleSecurityInfo(module_name).setDefaultAccess(1)
    dot = module_name.find('.')
    while dot > 0:
        ModuleSecurityInfo(module_name[:dot]).setDefaultAccess(1)
        dot = module_name.find('.', dot + 1)


allow_module.__roles__ = ACCESS_PRIVATE

# Modules that should never be fully accessible from restricted code.
# A declaration for one of these, or a submodule, is logged by
# check_dangerous_modules, which freeze_security_declarations calls.
# PLEASE NOTE: This listing cannot ever be complete and it cannot guard
# against malicious or sloppy code exposing other unsafe modules! Its
# purpose is just informational, it is not a safe catch-all.
DANGEROUS_MODULES = frozenset((
    # processes and code execution
    '_posixsubprocess', '_thread', 'asyncio', 'atexit', 'bdb', 'builtins',
    'code', 'codeop', 'concurrent', 'copyreg', 'cProfile', 'ctypes',
    '_ctypes', 'doctest', 'faulthandler', 'gc', 'importlib', 'inspect',
    'logging', 'marshal', 'multiprocessing', 'nt', 'operator', 'os', 'pdb',
    'pickle', '_pickle', 'pkgutil', 'posix', 'profile', 'pty', 'pydoc',
    'runpy', 'shelve', 'signal', 'site', 'subprocess', 'sys', 'threading',
    'timeit', 'trace', 'traceback', 'types', 'unittest', 'webbrowser',
    'zipimport',
    # filesystem
    'bz2', 'codecs', 'compileall', 'configparser', 'dbm', 'ensurepip',
    'fcntl', 'filecmp', 'fileinput', 'genericpath', 'glob', 'gzip', 'io',
    '_io', 'linecache', 'lzma', 'mailbox', 'mmap', 'netrc', 'ntpath',
    'pathlib', 'posixpath', 'py_compile', 'shutil', 'sqlite3', 'sysconfig',
    'tarfile', 'tempfile', 'venv', 'zipapp', 'zipfile',
    # network
    'ftplib', 'http', 'imaplib', 'poplib', 'select', 'selectors', 'smtplib',
    'socket', 'socketserver', 'ssl', 'urllib', 'wsgiref', 'xmlrpc',
    # information about the system, or process wide state
    'getpass', 'grp', 'locale', 'platform', 'pwd', 'resource',
    # Zope: security declarations and policy, switching users or sites,
    # transactions, the database
    'AccessControl', 'App', 'transaction', 'ZODB', 'Zope2',
    'zope.component.hooks', 'zope.interface',
    # third-party network libraries: requests from the server itself can
    # reach internal services, and httpx can use local Unix sockets
    'aiohttp', 'httpx', 'pycurl', 'requests', 'urllib3',
))


def freeze_security_declarations(dangerous_modules=DANGEROUS_MODULES):
    """Refuse changes to security declarations from now on.

    Call this once all code has been loaded, for example when Zope has
    started.  Afterwards, ModuleSecurityInfo, allow_module, allow_class and
    allow_type raise Forbidden for any change, so new modules, classes and
    types cannot be opened up to restricted code.

    Normal class security declarations with ClassSecurityInfo still work,
    because classes may be imported later, for example when loading objects
    from the database.

    Pending declarations are applied first, because importing a module from
    restricted code would otherwise still need to change them.  Dangerous
    modules that are fully accessible are logged as a warning, see
    check_dangerous_modules.

    Calling this when security declarations are already frozen does nothing.
    """
    if frozen.is_frozen():
        return
    # Most of these modules have likely already been imported, because the
    # declarations are usually made in the module itself or its package.
    # So this is fast.
    for name in sorted(_moduleSecurity):
        try:
            secureModule(name, {}, {})
        except ImportError:
            LOG.info(f'Could not import {name!r} to apply its'
                     ' module security declarations.')

    check_dangerous_modules(dangerous_modules)
    frozen.freeze()


def check_dangerous_modules(dangerous_modules=DANGEROUS_MODULES):
    """Log a warning for dangerous modules accessible from restricted code.

    Only modules that are fully accessible are logged, for example with
    allow_module, not modules where only specific names are public.
    A submodule of a dangerous module is dangerous as well.  Pass
    dangerous_modules to check other modules, for example ``{'my.package'}``.
    """
    for name in sorted(set(_moduleSecurity) | set(_appliedModuleSecurity)):
        modsec = _appliedModuleSecurity.get(name) or _moduleSecurity[name]
        access = getattr(modsec, 'access', 0)
        if not access or isinstance(access, dict):
            # Only specific names are accessible.
            continue
        parts = name.split('.')
        for index in range(1, len(parts) + 1):
            if '.'.join(parts[:index]) in dangerous_modules:
                LOG.warning(
                    f'Module {name!r} is accessible from restricted code.')
                break


def allow_class(Class):
    """Allow a class and all of its methods to be used from a
    restricted Script.  The argument Class must be a class."""
    frozen.check_not_frozen()
    Class._security = sec = ClassSecurityInfo()
    sec.declareObjectPublic()
    sec.setDefaultAccess(1)
    sec.apply(Class)
    InitializeClass(Class)


allow_class.__roles__ = ACCESS_PRIVATE
