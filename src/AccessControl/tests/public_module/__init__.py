# test module, public

from Acquisition import aq_base  # Foil the old ZopeSecurityPolicy # NOQA: F401

from AccessControl.SecurityInfo import allow_class  # NOQA: F401
from AccessControl.SecurityInfo import allow_module  # NOQA: F401
from AccessControl.SimpleObjectPolicies import allow_type  # NOQA: F401


def pub():
    pass
