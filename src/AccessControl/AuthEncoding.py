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


import AuthEncoding.AuthEncoding
from zope.deferredimport import deprecated


deprecated(
    "The functionality of AccessControl.AuthEncoding has moved to"
    " AuthEncoding.AuthEncoding. Please import from there."
    " This backward compatibility shim will be removed in AccessControl"
    " version 6.",
    MySQLDigestScheme='AuthEncoding.AuthEncoding:MySQLDigestScheme',
    PasswordEncryptionScheme='AuthEncoding.AuthEncoding:PasswordEncryptionScheme',  # noqa
    SHADigestScheme='AuthEncoding.AuthEncoding:SHADigestScheme',
    SSHADigestScheme='AuthEncoding.AuthEncoding:SSHADigestScheme',
    constant_time_compare='AuthEncoding.AuthEncoding:constant_time_compare',
    is_encrypted='AuthEncoding.AuthEncoding:is_encrypted',
    listSchemes='AuthEncoding.AuthEncoding:listSchemes',
    pw_encode='AuthEncoding.AuthEncoding:pw_encode',
    pw_encrypt='AuthEncoding.AuthEncoding:pw_encrypt',
    pw_validate='AuthEncoding.AuthEncoding:pw_validate',
    registerScheme='AuthEncoding.AuthEncoding:registerScheme',
)

# Bogosity on various platforms due to ITAR restrictions.
# We need to import the module anyway to check for the presence of
# restrictions, but do want to silence the ImportError.

if hasattr(AuthEncoding.AuthEncoding, 'CryptDigestScheme'):
    deprecated(
        "The functionality of AccessControl.AuthEncoding has moved to"
        " AuthEncoding.AuthEncoding. Please import from there."
        " This backward compatibility shim will be removed in AccessControl"
        " version 6.",
        CryptDigestScheme='AuthEncoding.AuthEncoding:CryptDigestScheme',
    )
