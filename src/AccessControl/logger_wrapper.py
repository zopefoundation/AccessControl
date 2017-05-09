# A wrapper to replace the usage of the zLOG module in cAccessControl without
# having the need to change the C code significantly.

# Standard Library Imports
from logging import getLogger


LOG = getLogger('AccessControl')
warn = LOG.warn
