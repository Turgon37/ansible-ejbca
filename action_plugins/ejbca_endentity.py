from __future__ import absolute_import, division, print_function

# Standard library imports
import os.path
import sys

# The module_utils path must be added to sys.path in order to import
# juniper_junos_common. The module_utils path is relative to the path of this
# file.
module_utils_path = os.path.normpath(os.path.join(
                                       os.path.dirname(os.path.realpath(__file__)),
                                       '../module_utils'))
if module_utils_path is not None:
    sys.path.insert(0, module_utils_path)
    import ejbca_common
    del sys.path[0]


# Use the custom behavior of JuniperJunosActionModule as our ActionModule.
# The Ansible core engine will call ActionModule.run()
from ejbca_common import EJBCAActionModule as ActionModule
