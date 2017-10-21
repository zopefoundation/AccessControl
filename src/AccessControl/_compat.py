"""Python 3 compat module"""
import sys


PY3 = sys.version_info[0] == 3
if PY3:
	import _thread as thread
else:
	import thread

get_ident = thread.get_ident
