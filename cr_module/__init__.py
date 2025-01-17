# -*- coding: utf-8 -*-
#  Copyright (c) 2020 - 2025 Ricardo Bartels. All rights reserved.
#
#  check_redfish.py
#
#  This work is licensed under the terms of the MIT license.
#  For a copy, see file LICENSE.txt included in this
#  repository or visit: <https://opensource.org/licenses/MIT>.

from cr_module.common import grab
from cr_module.classes.plugin import PluginData

system_power_state = None


# function has been placed here to avoid circular dependencies
def get_system_power_state():

    global system_power_state

    if system_power_state is not None:
        return system_power_state

    plugin_object = PluginData()

    for system in plugin_object.rf.get_system_properties("systems") or list():
        system_state = grab(plugin_object.rf.get(system), "PowerState")
        if system_state is not None:
            system_power_state = system_state
            break

    if system_power_state is None:
        system_power_state = "On"

    return system_power_state

# EOF
